/**
**********************************************************************
*
* Copyright (c) 2012 Baidu.com, Inc. All Rights Reserved
* @file			$HeadURL$
* @brief			list接口定义
* @author		jorenwu(wujiaoren@baidu.com)
* @date			2012/04/21
* @version		$Id$
***********************************************************************
*/

#include "common_includes.h"

#include "parser.h"
#include "util.h"
#include "logger.h"

/* ketword definition */
struct keyword {
	const char *string;
	int (*handler) (vector);
	vector sub;
};

/* global vars */
vector keywords;
FILE *current_stream;
char *current_conf_file;

/* local vars */
static int sublevel = 0;
static int process_stream(vector keywords_vec);

static int
keyword_alloc(vector keywords_vec,const char *string, int (*handler) (vector))
{
	struct keyword *keyword;

	if (vector_alloc_slot(keywords_vec) < 0)
		return -1;

	keyword = (struct keyword *) MALLOC(sizeof (struct keyword));
	if (!keyword)
		return -1;
	keyword->string = string;
	keyword->handler = handler;

	vector_set_slot(keywords_vec, keyword);
	return 0;
}

static int
keyword_alloc_sub(vector keywords_vec, const char *string,int (*handler) (vector))
{
	int i = 0;
	struct keyword *keyword;

	/* fetch last keyword */
	keyword = VECTOR_SLOT(keywords_vec, VECTOR_SIZE(keywords_vec) - 1);

	/* position to last sub level */
	for (i = 0; i < sublevel; i++)
		keyword =
		    VECTOR_SLOT(keyword->sub, VECTOR_SIZE(keyword->sub) - 1);

	/* First sub level allocation */
	if (!keyword->sub) {
		keyword->sub = vector_alloc();
		if (!keyword->sub)
			return -1;
	}

	/* add new sub keyword */
	if (keyword_alloc(keyword->sub, string, handler) < 0)
		return -1;
	return 0;
}

/* Exported helpers */
void
install_sublevel(void)
{
	sublevel++;
}

void
install_sublevel_end(void)
{
	sublevel--;
}

int
install_keyword_root(const char *string, int (*handler) (vector))
{
	if (keyword_alloc(keywords, string, handler) < 0)
		return -1;
	return 0;
}

int
install_keyword(const char *string, int (*handler) (vector))
{
	if (keyword_alloc_sub(keywords, string, handler) < 0)
		return -1;
	return 0;
}

void
dump_keywords(vector keydump, unsigned int level)
{
	unsigned int i, j;
	struct keyword *keyword_vec;

	for (i = 0; i < VECTOR_SIZE(keydump); i++) {
		keyword_vec = VECTOR_SLOT(keydump, i);
		for (j = 0; j < level; j++)
			log_print("  ");
		log_print("Keyword : %s\n", keyword_vec->string);
		if (keyword_vec->sub)
			dump_keywords(keyword_vec->sub, level + 1);
	}
}

void
free_keywords(vector keywords_vec)
{
	struct keyword *keyword_vec = NULL;
	unsigned int i;

	for (i = 0; i < VECTOR_SIZE(keywords_vec); i++) {
		keyword_vec = VECTOR_SLOT(keywords_vec, i);
		if (keyword_vec->sub)
			free_keywords(keyword_vec->sub);
		FREE(keyword_vec);
	}
	vector_free(keywords_vec);
}

/* return 0:ok, -1:fail */
int
alloc_strvec(char *string, vector *ret_vec)
{
	char *cp, *start, *token;
	int str_len;
	vector strvec;

	*ret_vec = NULL;

	if (!string)
		return 0;

	cp = string;

	/* Skip white spaces */
	while (isspace((int) *cp) && *cp != '\0')
		cp++;

	/* Return if there is only white spaces */
	if (*cp == '\0')
		return 0;

	/* Return if string begin with a comment */
	if (*cp == '!' || *cp == '#')
		return 0;

	/* Create a vector and alloc each command piece */
	strvec = vector_alloc();
	if (!strvec)
		return -1;

	while (1) {
		start = cp;
		while (!isspace((int) *cp) && *cp != '\0')
			cp++;
		str_len = cp - start;
		token = MALLOC(str_len + 1);
		if (!token)
			return -1;
		memcpy(token, start, str_len);
		*(token + str_len) = '\0';

		/* Alloc & set the slot */
		if (vector_alloc_slot(strvec) < 0) {
			FREE(token);
			return -1;
		}
		vector_set_slot(strvec, token);

		while (isspace((int) *cp) && *cp != '\0')
			cp++;
		if (*cp == '\0' || *cp == '!' || *cp == '#') {
			*ret_vec = strvec;
			return 0;
		}
	}
}

static int
read_conf_file(char *conf_file)
{
	int ret = 0;
	unsigned int i;
	FILE *stream;
	glob_t globbuf;

	globbuf.gl_offs = 0;
	if (glob(conf_file, 0, NULL, &globbuf) != 0) {
		log_print("open cfg file \"%s\" failed: %s\n",
			conf_file, strerror(errno));
		ret = -1;
		goto out;
	}

	for(i = 0; i < globbuf.gl_pathc; i++){
		stream = fopen(globbuf.gl_pathv[i], "r");
		if (!stream) {
			log_print("open cfg file \"%s\" failed: %s\n",
				globbuf.gl_pathv[i], strerror(errno));
			ret = -1;
			goto out;
		}
		current_stream = stream;
		current_conf_file = globbuf.gl_pathv[i];

		char prev_path[MAXBUF];
		getcwd(prev_path, MAXBUF);

		char *confpath = strdup(globbuf.gl_pathv[i]);
		dirname(confpath);
		chdir(confpath);
		ret = process_stream(keywords);
		fclose(stream);

		/* add by yangyi for possible memleak */
		if (confpath)
			free(confpath);

		chdir(prev_path);

		if (ret < 0)
			goto out;
	}


out:
	globfree(&globbuf);

	return ret;
}

static int kw_level = 0;
static int
check_include(char *buf)
{
	int ret = 0;
	char *str;
	vector strvec;

	/* 限定include关键字只能在配置文件中最外一层处理 */
	if (kw_level > 0)
		return 0;

	if (alloc_strvec(buf, &strvec) < 0)
		return -1;

	if (!strvec){
		return 0;
	}
	str = VECTOR_SLOT(strvec, 0);

	if (!strcmp(str, EOB)) {
		free_strvec(strvec);
		return 0;
	}

	if(!strcmp("include", str) && VECTOR_SIZE(strvec) == 2){
		char *conf_file = VECTOR_SLOT(strvec, 1);

		FILE *prev_stream = current_stream;
		char *prev_conf_file = current_conf_file;
		char prev_path[MAXBUF];
		getcwd(prev_path, MAXBUF);
		ret = read_conf_file(conf_file);
		current_stream = prev_stream;
		current_conf_file = prev_conf_file;
		chdir(prev_path);
		free_strvec(strvec);
		return ((ret < 0) ? ret : 1);
	}
	free_strvec(strvec);
	return 0;
}

static int
read_line(char *buf, int size)
{
	int ch;
	int ret = 1;

	while(ret == 1) {
		int count = 0;
		memset(buf, 0, MAXBUF);
		while ((ch = fgetc(current_stream)) != EOF && (int) ch != '\n'
			   && (int) ch != '\r') {
			if (count < size)
				buf[count] = (int) ch;
			else
				break;
			count++;
		}
		ret = check_include(buf);
	}

	buf[MAXBUF-1] = 0;
	if (ret < 0)
		return ret;
	return (ch == EOF) ? 0 : 1;
}

int
read_line_no_include(char *buf, int size)
{
	int ch;
	int count = 0;
	memset(buf, 0, MAXBUF);
	while ((ch = fgetc(current_stream)) != EOF && (int) ch != '\n'
		   && (int) ch != '\r') {
		if (count < size)
			buf[count] = (int) ch;
		else
			break;
		count++;
	}

	buf[MAXBUF-1] = 0;
	return (ch == EOF) ? 0 : 1;
}

/* recursive configuration stream handler */
static int
process_stream(vector keywords_vec)
{
	unsigned int i;//, match = 0;
	int ret = 0;
	struct keyword *keyword_vec;
	char *str;
	char *buf;
	vector strvec;

	buf = zalloc(MAXBUF);
	if (!buf)
		return -1;

	while (1) {
		//match = 0;
		memset(buf,0, MAXBUF);
		/* read_line, 0: end of file, 1: new line, -1: err */
		ret = read_line(buf, MAXBUF);
		if (ret <= 0)
			goto out;

		if (alloc_strvec(buf, &strvec) < 0) {
			ret = -1;
			goto out;
		}

		if (!strvec)
			continue;

		str = VECTOR_SLOT(strvec, 0);
		if (!strcmp(str, EOB) && kw_level > 0) {
			ret = 0;
			free_strvec(strvec);
			goto out;
		}

		for (i = 0; i < VECTOR_SIZE(keywords_vec); i++) {
			keyword_vec = VECTOR_SLOT(keywords_vec, i);

			if (!strcasecmp(keyword_vec->string, str)) {
				//match = 1;
				if (keyword_vec->handler) {
					ret = (*keyword_vec->handler) (strvec);
					/* check return status */
					if (ret < 0) {
						free_strvec(strvec);
						goto out;
					}
				}

				if (keyword_vec->sub) {
					kw_level++;
					ret = process_stream(keyword_vec->sub);
					kw_level--;
					/* check return status */
					if (ret < 0) {
						free_strvec(strvec);
						goto out;
					}
				}
				break;
			}
		}

		/* strings not in keyword_vec, NEED THIS? */
#if 0
		if (match == 0) {
			ret = -1;
			free_strvec(strvec);
			goto out;
		}
#endif

		free_strvec(strvec);
	}

out:
	xfree(buf);

	return ret;
}

/* Data initialization */
int
init_data(char *conf_file, int (*init_keywords) (void))
{
	int	ret = 0;
	if (conf_file == NULL || init_keywords == NULL) {
		return -1;
	}
	/* Init Keywords structure */
	keywords = vector_alloc();
	if (keywords == NULL) {
		log_print("cannot vector_alloc keywords\n");
		return -1;
	}

	ret = (*init_keywords) ();
	if (ret < 0) {
		log_print("init_keywords failed\n");
		free_keywords(keywords);
		return ret;
	}

	/* Stream handling */
	ret = read_conf_file(conf_file);
	if(ret >=0)
		log_print("read_conf_file successfully.\n");
	else
		log_print("read_conf_file failed.\n");

	free_keywords(keywords);

	return ret;
}


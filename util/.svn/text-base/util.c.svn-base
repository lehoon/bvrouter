/**
**********************************************************************
*
* Copyright (c) 2012 Baidu.com, Inc. All Rights Reserved
* @file			$HeadURL: https://svn.baidu.com/sys/ip/trunk/uinp/util/util.c $
* @brief			utilʵ��
* @author		jorenwu(wujiaoren@baidu.com)
* @date			2012/04/21
* @version		$Id: util.c 8911 2013-03-13 06:43:33Z zhangyu09 $
***********************************************************************
*/

#include "common_includes.h"

#include "util.h"

void *
xalloc(unsigned long size)
{
	void *mem = NULL;
	mem = malloc(size);

	return mem;
}


void *
zalloc(unsigned long size)
{
	void *mem = NULL;
	if ((mem = malloc(size)))
	{
		memset(mem, 0, size);
	}

	return mem;
}

void
xfree(void *p)
{
	if(NULL == p)
		return;

	free(p);
	p = NULL;
}

int bvrouter_atoi(char * str)
{
	int ret=0;
	char *p=str;
	char c;

	if(!p || '\0'==*p)
		return -1;

	while((c=*(p++))!='\0')
	{
		if(c>='0' && c<='9')
			ret = ret * 10 + (c-'0');
		else
			return -1;
	}

	return ret;
}


uint8_t ifmask_to_depth(uint32_t if_net)
{
	uint8_t depth = 32;
	uint32_t if_mask = ntohl(if_net); //if_net�������ֽ���
	while((if_mask & 0x01) == 0)
	{
		depth--;
		if_mask = if_mask >> 1;
	}
	return depth;
}

/**
*@brief		ת��ip��ַ����Ϊһ���ַ�����
*@param		ip ��Ҫ��ӡ��ip��ַ
*@return		�ַ���ָ��
*/
inline char *trans_ip(uint32_t ip)
{
	static uint8_t i = 0;
	static char g_print_ip_buf[5][20];		/**<���ڵ���ʱ����ӡip��ַ*/

	i = (i+1)%5;
	memset(g_print_ip_buf[i],0,20);
	sprintf(g_print_ip_buf[i],"%d.%d.%d.%d",
	((unsigned char *)&ip)[0],\
	((unsigned char *)&ip)[1],\
	((unsigned char *)&ip)[2],\
	((unsigned char *)&ip)[3]);
	return g_print_ip_buf[i];
}


int mac_str_to_bin( char *str, uint8_t *mac)
{
    int i;
    char *s, *e;

    if ((mac == NULL) || (str == NULL))
    {
        return -1;
    }

    s = (char *) str;
    for (i = 0; i < 6; ++i)
    {
        mac[i] = s ? strtoul (s, &e, 16) : 0;
        if (s)
           s = (*e) ? e + 1 : e;
    }
    return 0;
}

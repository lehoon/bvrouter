#include <string.h>
#include "conf.h"

void pal_conf_init(struct pal_config *conf)
{
	int i;

	memset(conf, 0, sizeof(*conf));

	conf->magic = PAL_CONF_MAGIC;

	for(i = 0; i < PAL_MAX_THREAD; i++) {
		conf->thread[i].cpu = -1;
	}
}


#include "thread.h"
#include "conf.h"

/* global config struct. All configurations are stored here */
struct pal_global_config g_pal_config;

/* id of each thread. ranges from 0 to PAL_MAX_THREAD-1 */
PAL_DEFINE_PER_THREAD(int, _thread_id);

/* thread conf structure of each thread. accessed frequently */
PAL_DEFINE_PER_THREAD(struct thread_conf *, _thconf);



VPATH += $(RTE_SRCDIR)/control

SRCS-y += bvrouter_config.c control_thread.c

#some macros in libev break strict-aliasing rules, so we have to disable the check
CFLAGS += -O2 -lev -fno-strict-aliasing

CFLAGS += -I $(RTE_SRCDIR)/pal/include
CFLAGS += -I $(RTE_SRCDIR)/includes -I $(RTE_SRCDIR)/includes/control
CFLAGS +=  -I $(RTE_SRCDIR)/includes/util  -I $(RTE_SRCDIR)/includes/monitor
CFLAGS +=  -I $(RTE_SRCDIR)/includes/worker  -I $(RTE_SRCDIR)/includes/slowpath
LDFLAGS += -lpopt

VPATH += $(RTE_SRCDIR)/namespace/alg

SRCS-y += bvr_alg.c bvr_ftp.c

#some macros in libev break strict-aliasing rules, so we have to disable the check
CFLAGS += -O2 -lev -fno-strict-aliasing
CFLAGS += $(WERROR_FLAGS)

CFLAGS += -I $(RTE_SRCDIR)/pal/include
CFLAGS += -I $(RTE_SRCDIR)/includes -I $(RTE_SRCDIR)/includes/control
CFLAGS +=  -I $(RTE_SRCDIR)/includes/util  -I $(RTE_SRCDIR)/includes/monitor
CFLAGS +=  -I $(RTE_SRCDIR)/includes/worker  -I $(RTE_SRCDIR)/includes/slowpath
CFLAGS +=  -I $(RTE_SRCDIR)/namespace

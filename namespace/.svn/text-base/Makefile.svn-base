
VPATH += $(RTE_SRCDIR)/namespace

SRCS-y += bvr_namespace.c bvr_ctl.c bvr_netfilter.c bvr_cjson.c bvr_arp.c bvr_route.c bvr_ipv4.c bvr_dev.c

#some macros in libev break strict-aliasing rules, so we have to disable the check

SUBDIRS := alg
SUBDIR_MAKEFILES := $(foreach f, $(SUBDIRS), $(RTE_SRCDIR)/namespace/$(f)/Makefile)
include $(SUBDIR_MAKEFILES)

CFLAGS += -O2 -lev -fno-strict-aliasing

CFLAGS += -I $(RTE_SRCDIR)/pal/include
CFLAGS += -I $(RTE_SRCDIR)/includes -I $(RTE_SRCDIR)/includes/control
CFLAGS +=  -I $(RTE_SRCDIR)/includes/util  -I $(RTE_SRCDIR)/includes/monitor
CFLAGS +=  -I $(RTE_SRCDIR)/includes/worker  -I $(RTE_SRCDIR)/includes/slowpath
CFLAGS +=  -I $(RTE_SRCDIR)/namespace

LDFLAGS += -lpopt

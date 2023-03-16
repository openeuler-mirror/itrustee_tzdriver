# when compile ko, you need to rename this file as Makefile, cos scripts of linux only recognize Makefile
obj-m := tzdriver.o

tzdriver-objs := core/smc_smp.o core/tc_client_driver.o core/session_manager.o core/mailbox_mempool.o core/teek_app_load.o
tzdriver-objs += core/agent.o core/gp_ops.o core/mem.o core/cmdmonitor.o core/tz_spi_notify.o core/tz_pm.o core/tee_compat_check.o
tzdriver-objs += auth/auth_base_impl.o auth/client_hash_auth.o tlogger/tlogger.o tlogger/log_pages_cfg.o ko_adapt.o
tzdriver-objs += core/reserved_mempool.o tzdriver_internal/tee_trace_event/tee_trace_event.o tzdriver_internal/tee_trace_event/tee_trace_interrupt.o
tzdriver-objs += core/shared_mem.o

RESULT := $(shell cat /proc/kallsyms | grep vsnprintf_s)

STATUS := $(findstring vsnprintf_s, $(RESULT))

ifneq ($(STATUS), vsnprintf_s)
tzdriver-objs += libboundscheck/src/memcpy_s.o libboundscheck/src/memset_s.o libboundscheck/src/strcpy_s.o libboundscheck/src/strncpy_s.o \
libboundscheck/src/memmove_s.o libboundscheck/src/strcat_s.o libboundscheck/src/strncat_s.o libboundscheck/src/strtok_s.o \
libboundscheck/src/securecutil.o libboundscheck/src/secureprintoutput_a.o libboundscheck/src/snprintf_s.o libboundscheck/src/vsnprintf_s.o
endif

# you should config right path according to your run-time environment
KPATH := /usr/src/kernels
KDIR  := $(KPATH)/$(shell ls $(KPATH))

EXTRA_CFLAGS += -isystem /usr/lib/gcc/aarch64-linux-gnu/10.3.1/include
EXTRA_CFLAGS += -fstack-protector-strong -DCONFIG_TEELOG -DCONFIG_TZDRIVER_MODULE -DCONFIG_TEECD_AUTH -DCONFIG_PAGES_MEM=y -DCONFIG_CLOUDSERVER_TEECD_AUTH
EXTRA_CFLAGS += -I$(PWD)/libboundscheck/include/ -I$(PWD) -I$(PWD)/auth -I$(PWD)/core -I$(PWD)/tzdriver_internal/tee_trace_event
EXTRA_CFLAGS += -I$(PWD)/tlogger -I$(PWD)/tzdriver_internal/kthread_affinity -I$(PWD)/tzdriver_internal/include
EXTRA_CFLAGS += -DCONFIG_CPU_AFF_NR=0 -DCONFIG_BIG_SESSION=1000 -DCONFIG_NOTIFY_PAGE_ORDER=4 -DCONFIG_512K_LOG_PAGES_MEM -DCONFIG_TEE_TRACE
EXTRA_CFLAGS += -DCONFIG_TEE_LOG_ACHIVE_PATH=\"/var/log/tee/last_teemsg\"
EXTRA_CFLAGS += -DNOT_TRIGGER_AP_RESET -DLAST_TEE_MSG_ROOT_GID -DCONFIG_NOCOPY_SHAREDMEM
EXTRA_CFLAGS += -DTEECD_PATH_UID_AUTH_CTX=\"/usr/bin/teecd:0\"
EXTRA_CFLAGS += -DCONFIG_AUTH_SUPPORT_UNAME -DCONFIG_AUTH_HASH -std=gnu99
all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	-rm -vrf *.o *.ko auth/*.o core/*.o tlogger/*.o
	-rm -vrf *.order *.symvers *.mod.c .tmp_versions .*o.cmd auth/.*o.cmd core/.*o.cmd tlogger/.*o.cmd
	-rm -vrf auth/.*.o.d core/.*.o.d tlogger/.*.o.d
	-rm -vrf tzdriver_internal/tee_trace_event/.*.o.d

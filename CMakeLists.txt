cmake_minimum_required (VERSION 2.8)
project (itrustee_tzdriver)
cmake_policy(SET CMP0037 OLD)

# Set target name
set(TARGET_NAME tzdriver)

# Add source files
set(depend-objs "core/smc_smp.o core/tc_client_driver.o core/session_manager.o core/mailbox_mempool.o core/teek_app_load.o")
set(depend-objs "${depend-objs} core/agent.o core/gp_ops.o core/mem.o core/cmdmonitor.o core/tzdebug.o core/tz_spi_notify.o core/tz_pm.o core/tee_compat_check.o")
set(depend-objs "${depend-objs} auth/auth_base_impl.o auth/client_hash_auth.o tlogger/tlogger.o tlogger/log_pages_cfg.o ko_adapt.o")
set(depend-objs "${depend-objs} core/reserved_mempool.o tzdriver_internal/tee_trace_event/tee_trace_event.o tzdriver_internal/tee_trace_event/tee_trace_interrupt.o")
set(depend-objs "${depend-objs} core/shared_mem.o core/smc_abi.o core/tee_info.o tzdriver_internal/tee_reboot/reboot.o")
set(depend-objs "${depend-objs} core/tee_portal.o core/tc_cvm_driver.o")

# Check libboundscheck.so
execute_process(COMMAND cat /proc/kallsyms COMMAND grep vsnprintf_s OUTPUT_VARIABLE RESULT)
if (NOT (${RESULT} MATCHES "vsnprintf_s"))
    set(boundscheck-objs "libboundscheck/src/memcpy_s.o libboundscheck/src/memset_s.o libboundscheck/src/strcpy_s.o libboundscheck/src/strncpy_s.o \
libboundscheck/src/memmove_s.o libboundscheck/src/strcat_s.o libboundscheck/src/strncat_s.o libboundscheck/src/strtok_s.o \
libboundscheck/src/securecutil.o libboundscheck/src/secureprintoutput_a.o libboundscheck/src/snprintf_s.o libboundscheck/src/vsnprintf_s.o")
    set(depend-objs "${depend-objs} ${boundscheck-objs}")
endif()

# you should config right path according to your run-time environment
set(KPATH /usr/src/kernels)
execute_process(COMMAND ls ${KPATH} OUTPUT_VARIABLE KDIR)
# Remove the last char \n
string(STRIP ${KDIR} KDIR)
set(KERNEL_DIR ${KPATH}/${KDIR})

# Set extra options
set(CMAKE_EXTRA_FLAGS "-fstack-protector-strong -DCONFIG_TEELOG -DCONFIG_TZDRIVER_MODULE -DCONFIG_TEECD_AUTH -DCONFIG_PAGES_MEM=y -DCONFIG_CLOUDSERVER_TEECD_AUTH")
set(CMAKE_EXTRA_FLAGS "${CMAKE_EXTRA_FLAGS} -DCONFIG_CPU_AFF_NR=0 -DCONFIG_BIG_SESSION=100 -DCONFIG_NOTIFY_PAGE_ORDER=4 -DCONFIG_512K_LOG_PAGES_MEM -DCONFIG_TEE_TRACE")
set(CMAKE_EXTRA_FLAGS "${CMAKE_EXTRA_FLAGS} -DCONFIG_TEE_LOG_ACHIVE_PATH=\\\\\\\"/var/log/tee/last_teemsg\\\\\\\"")
set(CMAKE_EXTRA_FLAGS "${CMAKE_EXTRA_FLAGS} -DNOT_TRIGGER_AP_RESET -DLAST_TEE_MSG_ROOT_GID -DCONFIG_NOCOPY_SHAREDMEM")
set(CMAKE_EXTRA_FLAGS "${CMAKE_EXTRA_FLAGS} -DTEECD_PATH_UID_AUTH_CTX=\\\\\\\"/usr/bin/teecd:0\\\\\\\"")
set(CMAKE_EXTRA_FLAGS "${CMAKE_EXTRA_FLAGS} -DCONFIG_AUTH_SUPPORT_UNAME -DCONFIG_AUTH_HASH -std=gnu99")
set(CMAKE_EXTRA_FLAGS "${CMAKE_EXTRA_FLAGS} -I${PROJECT_SOURCE_DIR}/libboundscheck/include/ -I${PROJECT_SOURCE_DIR} -I${PROJECT_SOURCE_DIR}/auth -I${PROJECT_SOURCE_DIR}/core")
set(CMAKE_EXTRA_FLAGS "${CMAKE_EXTRA_FLAGS} -I${PROJECT_SOURCE_DIR}/tlogger -I${PROJECT_SOURCE_DIR}/tzdriver_internal/kthread_affinity -I${PROJECT_SOURCE_DIR}/tzdriver_internal/include")
set(CMAKE_EXTRA_FLAGS "${CMAKE_EXTRA_FLAGS} -I${PROJECT_SOURCE_DIR}/tzdriver_internal/tee_trace_event")
set(CMAKE_EXTRA_FLAGS "${CMAKE_EXTRA_FLAGS} -isystem /usr/lib/gcc/aarch64-linux-gnu/10.3.1/include")
set(CMAKE_EXTRA_FLAGS "${CMAKE_EXTRA_FLAGS} -DCONFIG_TEE_TELEPORT_SUPPORT -DCONFIG_TEE_TELEPORT_AUTH -DTEE_TELEPORT_PATH_UID_AUTH_CTX=\\\\\\\"/usr/bin/tee_teleport:0\\\\\\\"")
set(CMAKE_EXTRA_FLAGS "${CMAKE_EXTRA_FLAGS} -DCONFIG_CONFIDENTIAL_CONTAINER -DCONFIG_TEE_AGENTD_AUTH -DTEE_AGENTD_PATH_UID_AUTH_CTX=\\\\\\\"/usr/bin/agentd:0\\\\\\\"")
set(CMAKE_EXTRA_FLAGS "${CMAKE_EXTRA_FLAGS} -DCONFIG_TA_AFFINITY=y -DCONFIG_TA_AFFINITY_CPU_NUMS=128 -DCONFIG_TEE_UPGRADE -DCONFIG_TEE_REBOOT -DCONFIG_CONFIDENTIAL_TEE")
set(CMAKE_EXTRA_FLAGS "${CMAKE_EXTRA_FLAGS} -I${PROJECT_SOURCE_DIR}/tzdriver_internal/tee_reboot -DMAILBOX_POOL_COUNT=8")

# Compile .ko file
add_custom_target(${TARGET_NAME} ALL COMMAND @echo "Compiling module ${TARGET_NAME}.ko...")
add_custom_command(TARGET ${TARGET_NAME}
    POST_BUILD
    COMMAND @echo "obj-m := ${TARGET_NAME}.o" > ${PROJECT_SOURCE_DIR}/Makefile
    COMMAND @echo "${TARGET_NAME}-objs := ${depend-objs}" >> ${PROJECT_SOURCE_DIR}/Makefile
    COMMAND @echo "EXTRA_CFLAGS += ${CMAKE_EXTRA_FLAGS}" >> ${PROJECT_SOURCE_DIR}/Makefile
    COMMAND @echo "all:" >> ${PROJECT_SOURCE_DIR}/Makefile
    COMMAND @echo -e "\\\t@make -C ${KERNEL_DIR} M=${PROJECT_SOURCE_DIR} modules" >> ${PROJECT_SOURCE_DIR}/Makefile
    COMMAND @cd ${PROJECT_SOURCE_DIR} && make
    COMMAND @rm -f ${PROJECT_SOURCE_DIR}/Makefile
)

# Clean output
add_custom_target(clean
    COMMAND cd ${PROJECT_SOURCE_DIR} && rm -vrf *.o *.ko auth/*.o core/*.o tlogger/*.o
    COMMAND cd ${PROJECT_SOURCE_DIR} && rm -vrf *.order *.symvers *.mod.c .tmp_versions .*o.cmd auth/.*o.cmd core/.*o.cmd tlogger/.*o.cmd
    COMMAND cd ${PROJECT_SOURCE_DIR} && rm -vrf auth/.*.o.d core/.*.o.d tlogger/.*.o.d
    COMMAND cd ${PROJECT_SOURCE_DIR} && rm -vrf tzdriver_internal/tee_trace_event/.*.o.d
)

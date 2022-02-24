cmake_minimum_required (VERSION 2.8)
project (itrustee_tzdriver)
cmake_policy(SET CMP0037 OLD)

# Set target name
set(TARGET_NAME tzdriver)

# Add source files
set(depend-objs "core/smc_smp.o core/tc_client_driver.o core/session_manager.o core/mailbox_mempool.o core/teek_app_load.o")
set(depend-objs "${depend-objs} core/agent.o core/gp_ops.o core/mem.o core/cmdmonitor.o core/tz_spi_notify.o core/tz_pm.o core/tee_compat_check.o")
set(depend-objs "${depend-objs} auth/auth_base_impl.o core/teec_daemon_auth.o tlogger/tlogger.o tlogger/log_pages_cfg.o ko_adapt.o auth/security_auth_enhance.o")

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
set(CMAKE_EXTRA_FLAGS "-fstack-protector-strong -DCONFIG_TEELOG -DCONFIG_TZDRIVER_MODULE -DCONFIG_TEECD_AUTH -DCONFIG_PAGES_MEM=y -DCONFIG_AUTH_ENHANCE -DCONFIG_CLOUDSERVER_TEECD_AUTH")
set(CMAKE_EXTRA_FLAGS "${CMAKE_EXTRA_FLAGS} -DCONFIG_CPU_AFF_NR=0 -DCONFIG_BIG_SESSION=1000 -DCONFIG_NOTIFY_PAGE_ORDER=4 -DCONFIG_512K_LOG_PAGES_MEM")
set(CMAKE_EXTRA_FLAGS "${CMAKE_EXTRA_FLAGS} -DCONFIG_TEE_LOG_ACHIVE_PATH=\\\\\\\"/var/log/tee/last_teemsg\\\\\\\"")
set(CMAKE_EXTRA_FLAGS "${CMAKE_EXTRA_FLAGS} -DNOT_TRIGGER_AP_RESET -DLAST_TEE_MSG_ROOT_GID")
set(CMAKE_EXTRA_FLAGS "${CMAKE_EXTRA_FLAGS} -I${PROJECT_SOURCE_DIR}/libboundscheck/include/ -I${PROJECT_SOURCE_DIR} -I${PROJECT_SOURCE_DIR}/auth -I${PROJECT_SOURCE_DIR}/core")
set(CMAKE_EXTRA_FLAGS "${CMAKE_EXTRA_FLAGS} -I${PROJECT_SOURCE_DIR}/tlogger -I${PROJECT_SOURCE_DIR}/kthread_affinity")

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
)

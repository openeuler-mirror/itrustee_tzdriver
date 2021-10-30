1.Project Info
Tzdriver (Trustzone driver) is a Linux kernel dirver module for ARM Trustzone.

2.Environment Prepare
1) you need an ARM Linux server (like kunpeng920)
2) download kernel source code to /usr/src/kernels
3) you should download libboundscheck from https://gitee.com/openeuler/libboundscheck

3.Compile
1) unzip libboundscheck and move libboundscheck to tzdriver/
like this:
tzdriver
    |--Makefile
    |--core
    |--......
    |--libboundscheck
        |--src
        |--include
        |--Makefile

2) cd tzdriver
3) make -C libboundscheck
4) make
then you will see tzdriver.ko under the folder "tzdriver"

4.Run
1) make sure that TEEOS is running
2) # insmod tzdriver.ko
3) # /usr/bin/teecd &
4) run any CA

5.License
please see License/Tzdriver_License for more details



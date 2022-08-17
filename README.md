# iTrustee OS tzdriver #
### 介绍 ###
iTrustee OS 非安全侧driver，支持与iTrustee OS通信

### 环境准备 ###
  1.准备一台ARM服务器，比如鲲鹏920
  2.下载kernel代码
  3.下载libboundscheck库，下载地址https://gitee.com/openeuler/libboundscheck
### 编译教程 ###
  1.解压libboundscheck，放到源码目录，结构如下：
```
    |--Makefile
    |--core
    |--......
    |--libboundscheck
        |--src
        |--include
        |--Makefile
```
   2.cd xxx(driver 源码路径)
   3.make -C libboundscheck
   4.make
   编译出tzdriver.ko文件
### 使用说明 ###
   1.确保ARM 服务器已经运行iTrustee OS
   2.使用root用户，执行insmod tzdriver.ko
   3.使用root用户，执行/usr/bin/teecd&
   4.运行测试CA 和TA

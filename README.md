# iTrustee tzdriver

#### 介绍
iTrustee OS 非安全侧driver，支持与iTrustee OS通信。

#### 操作系统
支持ARM服务器，比如鲲鹏920。

#### 编译教程
1）下载tzdriver代码。

2）下载libboundscheck库，下载地址<https://atomgit.com/openeuler/libboundscheck> 

3）解压libboundscheck，放到源码目录：

```
itrustee_tzdriver
|--Makefile
|--core
|--......
|--libboundscheck
    |--src
    |--include
    |--Makefile
```

4）cd xxx(tzdriver 源码路径)。

5）make -C libboundscheck。

6）make 编译出tzdriver.ko文件。
   鲲鹏920新型号使用命令：`make CPU_GROUP_BINDING=y`

#### 使用说明

1）确保ARM 服务器已经运行iTrustee OS。

2）使用root用户，执行insmod tzdriver.ko

3）使用root用户，执行nohup /usr/bin/teecd &

4）运行测试CA 和TA。

#### 参与贡献
    如果您想为本仓库贡献代码，请向本仓库任意maintainer发送邮件
    如果您找到产品中的任何Bug，欢迎您提出ISSUE

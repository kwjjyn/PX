# PX

---

## 1. 项目简介

本系统通过P4指定数据平面的解析流程，以及数据包的匹配规则，使用P4后端编译器P4C-XDP将其生成符合xdp的C语言表示，该表示被传递给clang和llvm以产生字节码。使用传统的eBPF内核hook，程序可以加载到设备驱动程序中的eBPF虚拟机中。内核验证程序保证生成的代码的安全性。从而向此设备驱动程序接收/发送的任何数据包都会触发已加载的P4程序的执行。完成对数据包的accept，drop，forward等操作。

### 动机

目前，工业界在云计算场景中主要使用OpenFlow作为南向协议进行南北向的通信。然而，OpenFlow并不支持弹性地增加匹配域，每增加一个匹配域就需要重新编写控制器和交换机两端的协议栈以及交换机的数据包处理逻辑，这无疑增加了交换机设计的难度，也严重影响OpenFlow协议的版本稳定性，影响OpenFlow的推广。为了解决OpenFlow协议编程能力不足的问题以及其设计本身所带来的可拓展性差的难题，可以使用数据平面编程语言P4来完成数据包处理的灵活性。

因此，PX（P4 and Xdp）系统设计将以下两方面作为目标：

- 协议处理灵活性 （通过P4实现）
- 数据包处理性能 （通过XDP实现）

将P4数据平面可编程的灵活性以及XDP处理包的高性能相结合，从而完成对OpenFlow协议的替代，同时使用XDP进行收发数据包，来保证实际业务的性能要求。

## 2. 环境搭建

### 2.1 系统要求

工具 | 版本
:-: | :-:
linux内核 | >= 4.14
clang/llvm| >= 3.8.1
iproute2| >= 180129

### 2.2 工具要求

* [ ] p4编译器
<https://github.com/p4lang/p4c>
* [ ] p4c-xdp编译器
<https://github.com/vmware/p4c-xdp>

## 3. 系统拓扑

创建三个namespace：

namespace|网卡ip|子网号|网关
:-:|:-:|:-:|:-:
 xdp_sender | 10.0.0.2|subnet2|10.0.0.4(ens4)
 xdp_test   | 192.168.0.2|subnet1|195.168.0.4(ens4)
 xdp_receiver|172.0.0.2|subnet3|172.0.0.4(ens5)

PX server运行在虚拟机中，包含三个网卡：

网卡 |ip|作用
:-:|:-:|:-:
ens3|10.10.1.2|管理网口
ens4|10.0.0.4/192.168.0.4|XDP_TX
ens5|172.0.0.4|TC转发

```bash
+------------------------------------------------------------+
|       +-------------------------------------------+        |
|       |                 PX server                 |        |
|       +-------------------+   +-------------------+        |
|       |   TC -> ingress   |   |   TC -> ingress   |        |
|       +-------------------+   +-------------------+        |
|       |        XDP        |   |        XDP        |        |
|       +-------------------+   +-------------------+        |
|       |        ens4       |   |        ens5       |        |
|------------------------------------------------------------|
|                 ↓                        |                 |
|           +-----------+            +-----------+           |
|           |Switch(br0)|            |Switch(br1)|           |
|           +-----------+            +-----------+           |
|              ↑    ↑                      |                 |
|          +---+    +---+                  |                 |
|          |            |                  |                 |
|          ↓            ↓                  ↓                 |
|     +--------+    +--------+         +--------+            |
|     |192.168.|    | 10.0.  |         | 172.0. |            |
|     +--------+    +--------+         +--------+            |
|     |Subnet1 |    |Subnet2 |         |Subnet3 |            |
|     +--------+    +--------+         +--------+            |
|     NameSpace1    NameSpace2         NameSpace3            |
|                                                            |
+------------------------------------------------------------+
```

**说明**：
xdp_sender与xdp_test在同一局域网下，网关都是PX server的ens4网卡。二层转发直接使用网桥，三层转发则数据包发往网关，经过XDP程序处理修改mac地址，ttl等信息使用XDP_TX转发到另一网段。
xdp_sender,xdp_test与xdp_receiver在不同局域网下，其中xdp_receiver的网关是PX server的ens5网卡。不同局域网要通信，首先都是经过网关的XDP程序处理，根据目的IP，修改目的mac及源mac，ttl等信息，通过XDP_PASS上传到TC层，TC将数据包转发到对应网卡egress路径转发出去。对于ARP请求，均是通过XDP,TC上传到PX server的网络协议栈进行处理并返回。

## 4. 运行

### 4.1 数据平面

`/p4/data-plane`目录中包含两个P4程序，分别运行在PXserver的ens4及ens5网卡上。

#### 编译

使用P4C-XDP编译器得到eBPF程序：

```bash
cd ~/PX/p4/data-plane
p4c-xdp --Werror -I ./p4include/ -I ../runtime/ --target xdp -o xdp_ens4.c xdp_ens4.p4
p4c-xdp --Werror -I ./p4include/ -I ../runtime/ --target xdp -o xdp_ens5.c xdp_ens5.p4
```

使用clang+llvm将eBPF程序编译成字节码:

```bash
clang -I ./p4include/ -I ../runtime/ -D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign  -Wno-compare-distinct-pointer-types  -Wno-gnu-variable-sized-type-not-at-end  -Wno-tautological-compare -O2 -emit-llvm -g -c xdp_ens4.c -o -| llc -march=bpf -filetype=obj -o xdp_ens4.o
clang -I ./p4include/ -I ../runtime/ -D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign  -Wno-compare-distinct-pointer-types  -Wno-gnu-variable-sized-type-not-at-end  -Wno-tautological-compare -O2 -emit-llvm -g -c xdp_ens5.c -o -| llc -march=bpf -filetype=obj -o xdp_ens5.o
```

#### 运行

分别加载到ens4及ens5网卡：

```bash
ip link set dev ens4 xdp obj xdp_ens4.o verb
ip link set dev ens5 xdp obj xdp_ens5.o verb
```

卸载XDP程序：

```bash
ip link set dev ens4 xdp off
ip link set dev ens5 xdp off
```

### 4.2 控制平面

`/p4/control-plane`目录中包含两个控制平面程序，分别针对ens4及ens5的数据平面程序下发流表项。

#### 编译

使用gcc完成对控制平面的编译：

```bash
cd ~/PX/p4/control-plane
gcc -I ../runtime/ -I ./libbpf/ ./libbpf/libbpf.o -I ../data-plane/ user_xdp_ens4.c -o user_xdp_ens4
gcc -I ../runtime/ -I ./libbpf/ ./libbpf/libbpf.o -I ../data-plane/ user_xdp_ens5.c -o user_xdp_ens5
```

#### 运行

```bash
./user_xdp_ens4
./user_xdp_ens5
```

### 4.3 Linux TC

针对不同局域网通信，需要使用linux TC来做转发数据包到不同网卡的操作。即通过编写eBPF程序，使用bpf_clone_redirect辅助函数通过hook附加在TC子系统中，来实现数据包的转发功能。在`/tc`目录中包含需要加载的eBPF程序。

#### 编译

使用clang+llvm将eBPF程序编译成字节码：

```bash
cd ~/PX/tc
clang -I ./bpf/ -I ./include/ -D__KERNEL__ -D__BPF_TRACING__  -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign  -Wno-compare-distinct-pointer-types -Wno-unknown-warning-option -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -Wno-tautological-compare -O2 -emit-llvm -g -c tc_redirect_kern.c -o -| llc -march=bpf -filetype=obj -o tc_redirect_kern.o
```

#### 运行

使用eBPF程序中的**clone_redirect_xmit_ens4toens5** 分节将其加载在ens4的ingress路径中：

```bash
tc qdisc add dev ens4 ingress
tc filter add dev ens4 root pref 10 u32 match u32 0 0 flowid 1:2 action bpf run object-file tc_redirect_kern.o section clone_redirect_xmit_ens4toens5 drop
```

使用eBPF程序中的**clone_redirect_xmit_ens5toens4** 分节将其加载在ens5的ingress路径中：

```bash
tc qdisc add dev ens5 ingress
tc filter add dev ens5 root pref 10 u32 match u32 0 0 flowid 1:2 action bpf run object-file tc_redirect_kern.o section clone_redirect_xmit_ens5toens4 drop
```

卸载已加载的eBPF程序：

```bash
tc qdisc del dev ens4 ingress
tc qdisc del dev ens5 ingress
```

### 4.4 一键化脚本

**script.py**程序包含功能如下：

- 编译P4数据平面，控制平面，tc eBPF程序
- 卸载已经加载在XDP,TC中的bpf程序
- 删除eBPF使用的maps

可以将其作为全局命令，假设仓库所在目录为~/PX：

```bash
$ chmod 777 ~/PX/script.py
$ ln -s ~/PX/script.py /usr/local/bin/px
$ px -h
PX command
version: 20190612
usage: px [ options ] < filename | interface >
where: options := { -h             display the usage of px command
                    -d filename    compile the data-plane P4 program
                    -c filename    compile the control-plane program
                    -t filename    compile the linux tc eBPF program
                    -o interface   off the eBPF of XDP and TC }
```

在PX目录下:

```bash
# 编译数据平面：
px -d xdp_ens4.p4
# 编译控制平面：
px -c user_xdp_ens4.c
# 编译tc eBPF程序：
px -t tc_redirect_kern.c
# 卸载ens4网卡上的所有加载程序并删除maps
px -o ens4
```

## 5. 项目树简介

```bash
PX
├── p4
│   ├── control-plane
│   │   ├── libbpf  .................控制平面所需头文件
│   │   ├── user_xdp_ens4.c  ........加载在ens4的控制平面程序
│   │   └── user_xdp_ens5.c  ........加载在ens5的控制平面程序
│   ├── data-plane
│   │   ├── p4include  ..............数据平面P4程序所需头文件
│   │   ├── xdp_ens4.p4  ............加载在ens4的数据平面程序
│   │   └── xdp_ens5.p4  ............加载在ens5的数据平面程序
│   └── runtime  ....................data/control plane共同需要的头文件
│── tc
│   ├── bpf  ........................TC所需bpf辅助函数
│   ├── include  ....................TC eBPF 所需头文件
│   └── tc_redirect_kern.c  .........加载在TC的eBPF程序
|── doc  ............................相关资料文档
|── readme.md
└── script.py   .....................PX系统一键编译命令
```

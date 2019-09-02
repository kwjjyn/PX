#!/usr/bin/python
# -*- coding: UTF-8 -*-
# *************************************************************************
# @brief ：此脚本程序主要用来编译p4数据平面，控制平面，tc eBPF程序，以及卸载已加载
#          的xdp，tc程序，并删除maps。
#          目前仅支持在PX目录下运行该程序，使用 -h 查看帮助信息。
# @author：寇健园
# @date  ：2019/6/13
# @note  : 用户编译得到目标文件后，需要使用加载命令加载到对应子系统中。
# *************************************************************************

import os
import sys
import getopt

cmd_p4 ="p4c-xdp --Werror -I ./p4include/ -I ../runtime/ --target xdp -o "

cmd_xdp1 ="clang -I ./p4include/ -I ../runtime/ -D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign  -Wno-compare-distinct-pointer-types  -Wno-gnu-variable-sized-type-not-at-end  -Wno-tautological-compare -O2 -emit-llvm -g -c "
cmd_xdp2 = " -o -| llc -march=bpf -filetype=obj -o "
cmd_control = "gcc -I ../runtime/ -I ./libbpf/ ./libbpf/libbpf.o -I ../data-plane/ "
cmd_tc1 ="clang -I ./bpf/ -I ./include/ -D__KERNEL__ -D__BPF_TRACING__  -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign  -Wno-compare-distinct-pointer-types -Wno-unknown-warning-option -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -Wno-tautological-compare -O2 -emit-llvm -g -c "
cmd_tc2 =" -o -| llc -march=bpf -filetype=obj -o "
cmd_xdpoff1 = "ip link set dev "
cmd_xdpoff2 = " xdp off "
cmd_tcoff1 = "tc qdisc del dev "
cmd_tcoff2 = " ingress "

def usage():
    print "PX command"
    print "version: 20190612"
    print "usage: px [ options ] < filename | interface >"
    print "where: options := { -h             display the usage of px command"
    print "                    -d filename    compile the data-plane P4 program"                                    
    print "                    -c filename    compile the control-plane program"
    print "                    -t filename    compile the linux tc eBPF program"
    print "                    -o interface   off the eBPF of XDP and TC }" 

def main():
    global cmd_p4
    global cmd_xdp1
    global cmd_xdp2
    global cmd_control
    global cmd_tc1
    global cmd_tc2
    global cmd_xdpoff1
    global cmd_xdpoff2
    global cmd_tcoff1
    global cmd_tcoff2
    opts,args = getopt.getopt(sys.argv[1:],"hd:c:t:l:o:")
    for op,value in opts:
        if op == "-h":
            usage()
            sys.exit()
        elif op == "-d":
            verify = value[-3:]
            if verify != ".p4":
                print "please input the valid p4 program"
                sys.exit()
            prefix = value[:-3]
            c = prefix + ".c"
            o = prefix + ".o"
            cmd_xdp = cmd_xdp1 + c + ' ' + cmd_xdp2 + o
            cmd_p4 = cmd_p4 + c + ' ' +  value
            cmd = "cd ./p4/data-plane " + "&& "+ cmd_p4 + " && " + cmd_xdp 
            os.system(cmd)
            print "Success:data plane program compiled"
        elif op == "-c":
            verify = value[-2:]
            if verify != ".c":
                print "please input the valid c program"
                sys.exit()
            prefix = value[:-2]
            cmd_control = cmd_control + value + " -o " + prefix
            cmd = "cd ./p4/control-plane " + "&& " + cmd_control
            os.system(cmd)
            print "Success:control plane program compiled"
        elif op == "-t":
            verify = value[-2:]
            if verify != ".c":
                print "please input the valid c program"
                sys.exit()
            prefix = value[:-2]
            o = prefix + ".o"
            cmd_tc = cmd_tc1 + value + cmd_tc2 + o
            cmd = "cd ./tc " + "&& " + cmd_tc
            os.system(cmd)
            print "Success:TC eBPF program compiled"
        elif op == "-o":
            cmd_xdpoff = cmd_xdpoff1 + value + cmd_xdpoff2
            cmd_tcoff = cmd_tcoff1 + value + cmd_tcoff2
            rm = "rm /sys/fs/bpf/xdp/globals/*"
            cmd = cmd_xdpoff + "&& " + cmd_tcoff + "&& " + rm
            os.system(cmd)
            print "all the attached eBPF programs and maps of XDP and TC have been deattached and deleted. "
        else:
            usage()
            sys.exit()


if __name__ == "__main__":
    main()

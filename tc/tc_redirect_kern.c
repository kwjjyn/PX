/*
 * @file    tc_redirect_kern.c
 * @brief   用户提供此eBPF程序，用来进行对TC成收到的数据包进行转发到其他网卡。
 *          使用clang+llvm完成编译。
 * @version 1.1
 * @author  寇健园
 * @date    2019/6/11
 * 
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
#include "bpf_helpers.h"

/* @brief   使用系统调用bpf_redirect函数进行数据包转发。将数据包重定向到索引ifindex的另一个网络设备。
 *          bpf_clone_redirect()类似，但是包不是克隆的，这提高了性能。
 *          转发数据包到egress路径。
 * @param   ifindex : 网卡索引
 *          flags	: 1代表ingress，0代表egress	  
 * 
 * @return  成功返回TC_ACT_REDIRECT,失败返回TC_ACT_SHOT
 * @note    此方式不会复制数据包，所以转发到另一个网卡后协议栈不会收到该数据包。
 *          因此XDP层需要对所有数据包进行处理，包括写完整的ARP处理逻辑。
 */
SEC("redirect_xmit")
int _redirect_xmit(struct __sk_buff *skb)
{
	return bpf_redirect(skb->ifindex + 1, 0);
}

/* 转发数据包到ingress路径 */
SEC("redirect_recv")
int _redirect_recv(struct __sk_buff *skb)
{
	return bpf_redirect(skb->ifindex + 1, 1);
}

/* @brief   克隆并将与skb关联的包重定向到索引ifindex的另一个网络设备。
 *          相比bpf_redirect多了一次复制，性能有所下降。
 *          转发数据包到egress路径。
 * @param   skb     : 表示当前数据包分配的SKB
 *          ifindex : 网卡索引
 *          flags	: 1代表ingress，0代表egress	
 * @return  TC_ACT_OK TC处理完后继续上报协议栈。
 * @note    1. 此方式复制数据包，所以转发到另一个网卡后协议栈仍会收到该数据包。
 *          因此XDP层只需对转发数据包进行处理，ARP处理交给协议栈协同处理即可。
 *          2. 数据包从ens4转发到ens5。
 */
SEC("clone_redirect_xmit_ens4toens5")
int _clone_redirect_xmit_ens4toens5(struct __sk_buff *skb)
{
	bpf_clone_redirect(skb, skb->ifindex + 1, 0);
	return TC_ACT_OK;
}

/* 数据包从ens5转发到ens4 */
SEC("clone_redirect_xmit_ens5toens4")
int _clone_redirect_xmit_ens5toens4(struct __sk_buff *skb)
{
	bpf_clone_redirect(skb, skb->ifindex - 1, 0);
	return TC_ACT_OK;
}

/* 转发数据包到ingress路径 */	
SEC("clone_redirect_recv")
int _clone_redirect_recv(struct __sk_buff *skb)
{
	bpf_clone_redirect(skb, skb->ifindex + 1, 1);
	return TC_ACT_SHOT;
}
char _license[] SEC("license") = "GPL";

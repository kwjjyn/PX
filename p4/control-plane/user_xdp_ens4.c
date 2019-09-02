﻿/*
 * @file    user_xdp_ens4.c
 * @brief   用户提供此控制平面程序，调用P4程序产生的控制平面API，来对流表进行增删改查。
 *          编译命令：
 *          gcc -I ../runtime/ -I ./libbpf/ ./libbpf/libbpf.o -I ../data-plane/ user_xdp_ens4.c -o user_xdp_ens4
 * @version 1.1
 * @author  寇健园
 * @date    2019/6/11
 * 
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include "libbpf.h"

#define CONTROL_PLANE 1
#include "xdp_ens4.h"

#define TABLE "/Ingress_dstmactable"

int main(void)
{
    int ret;	
    int fd;
    struct Ingress_dstmactable_key key;
	struct Ingress_dstmactable_value value;

    /* 初始化默认action */
	init_tables();

    /* @brief   下发匹配目标ip为192.168.0.2的流表。
     *          <key,value>：<192.168.0.2 , Forward_action + mac地址 >
     *          通过XDP_TX返回码从同网卡转发出去。
     *
     * @note    此处的mac地址应按网络字节序大端来写。
     */
    struct action_md_t tmp = {0,0x9a56852ada62} ;  /* 192.168.0.2的mac地址 */    
    
    value.action = Ingress_Forward_action;
    value.u.Ingress_Forward_action.md = tmp;	
    key.field0 =  0xc0a80002; /* ip dstAddr:192.168.0.2 */
 
    printf("=== Open BPF map: %s ===\n", MAP_PATH TABLE);
    fd = bpf_obj_get(MAP_PATH TABLE);
    if (fd < 0) {
        printf("BPF map %s not loaded\n", MAP_PATH TABLE);
        exit(1);
    }

    /* 下发流表 */
    printf("=== Write to eBPF map ===\n");
    printf("key = %x value = %x\n", key.field0, value.action);
    ret = bpf_update_elem(fd, &key, &value, BPF_ANY);
    if (ret) {
        perror("error updating map element\n");
        exit(1);
    }

    /* @brief   下发匹配目标ip为10.0.0.2的流表。
     *          <key,value>：<10.0.0.2 , Forward_action + mac地址 >
     *          通过XDP_TX返回码从同网卡转发出去。
     * @note    此处的mac地址应按网络字节序大端来写。
     */
    tmp.dst_mac =  0x1c1a602cd3c6 ; /* 10.0.0.2 mac */ 

    value.u.Ingress_Forward_action.md = tmp;
    key.field0 = 0x0a000002;    /* ip dstAddr: 10.0.0.2 */ 

    printf("key = %x value = %x\n", key.field0, value.action);
    ret = bpf_update_elem(fd, &key, &value, BPF_ANY);
    if (ret) {
        perror("error updating map element\n");
        exit(1);
    }

    /* @brief   下发匹配目标ip为172.0.0.2的流表。
     *          <key,value>：<172.0.0.2 , Redirect_action + mac地址 >
     *          通过XDP_PASS返回码改包后送给上层TC，TC转发包到目标网卡发送出去。
     * @note    此处的mac地址应按网络字节序大端来写。
     */
    tmp.src_mac = 0xe1e902005452; /* 目标网卡 mac */
    tmp.dst_mac = 0x33d355cadcd2; /* 172.0.0.2 mac */

    value.action = Ingress_Redirect_action;
    value.u.Ingress_Redirect_action.md = tmp;
    key.field0 = 0xac000002; /* ip dstAddr:172.0.0.2*/

    printf("key = %x value = %x\n", key.field0, value.action);
    ret = bpf_update_elem(fd, &key, &value, BPF_ANY);
    if (ret) {
        perror("error updating map element\n");
        exit(1);
    }

    close(fd);
    return 0;
}


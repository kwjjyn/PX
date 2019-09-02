/*
 * @file    xdp_ens4.p4
 * @brief   用户提供此数据平面程序，对数据包解析流程，匹配表等进行定义。
 *          通过使用p4c-xdp编译器完成向eBPF程序的编译。运行在ens4网卡。
 * @version 1.1
 * @author  寇健园
 * @date    2019/6/11
 * 
 */

#include "xdp_model.p4"

/* -------------------------------------------
 *               定义需要解析的header
 * -------------------------------------------
 */
header Ethernet {
    bit<48> destination;
    bit<48> source;
    bit<16> protocol;
}

header IPv4 {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

/* 定义action传递参数的metadate */
struct action_md_t {
    bit<48> src_mac;
    bit<48> dst_mac;
}

struct Headers {
    Ethernet ethernet;
    IPv4     ipv4;
}

/* -------------------------------------------
 *             定义解析器Parser流程
 * -------------------------------------------
 */
parser Parser(packet_in packet, out Headers hd) {

    /* 解析以太网协议类型 */
    state start {
        packet.extract(hd.ethernet);
        transition select(hd.ethernet.protocol) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }

    /* 解析ipv4 */
    state parse_ipv4 {
        packet.extract(hd.ipv4);
        transition select(hd.ipv4.protocol) {
	    default: accept;
        }
    }
}

/* -------------------------------------------
 *             定义Ingress处理逻辑
 * -------------------------------------------
 */
control Ingress(inout Headers hd, in xdp_input xin, out xdp_output xout) {

    xdp_action xact = xdp_action.XDP_PASS;

    /* @brief     同一局域网下的不同subnet执行此action。
     *            根据控制平面下发的流表项修改源和目的mac，同时ttl减1，并且做ip校验和。
     * @param md  控制平面下发的源和目的mac地址
     * @return    XDP_TX
     */
    action Forward_action(action_md_t md )
    {
        hd.ethernet.source = hd.ethernet.destination;
        hd.ethernet.destination = md.dst_mac;
        
	    //修改ttl
        hd.ipv4.ttl = hd.ipv4.ttl - 1;
        hd.ipv4.hdrChecksum = ebpf_ipv4_checksum(
                            hd.ipv4.version, hd.ipv4.ihl, hd.ipv4.diffserv,
                            hd.ipv4.totalLen, hd.ipv4.identification, hd.ipv4.flags,
                            hd.ipv4.fragOffset, hd.ipv4.ttl, hd.ipv4.protocol,
                            hd.ipv4.srcAddr, hd.ipv4.dstAddr);


	    xact = xdp_action.XDP_TX;
    }

    /* @brief     不同局域网下的不同subnet执行此action。上传到TC进行转发。
     *            根据控制平面下发的流表项修改源和目的mac，同时ttl减1，并且做ip校验和。
     * @param md  控制平面下发的源和目的mac地址
     * @return    XDP_PASS
     */
    action Redirect_action(action_md_t md )
    {
        hd.ethernet.source = md.src_mac;
        hd.ethernet.destination = md.dst_mac;
        
	    //修改ttl
        hd.ipv4.ttl = hd.ipv4.ttl - 1;
        hd.ipv4.hdrChecksum = ebpf_ipv4_checksum(
                            hd.ipv4.version, hd.ipv4.ihl, hd.ipv4.diffserv,
                            hd.ipv4.totalLen, hd.ipv4.identification, hd.ipv4.flags,
                            hd.ipv4.fragOffset, hd.ipv4.ttl, hd.ipv4.protocol,
                            hd.ipv4.srcAddr, hd.ipv4.dstAddr);


	    xact = xdp_action.XDP_PASS;
    }

    /* @brief     流表未匹配执行此默认action。
     *            将数据包原封不动上传到协议栈进行处理。比如ARP包，从而实现XDP和协议栈协同工作。
     * @return    XDP_PASS
     */
    action Drop_action()
    {
        xact = xdp_action.XDP_PASS;
    }
    
    /* @brief     定义流表。
                  key表示精确匹配ip数据包的目的ip。actions代表匹配后可以执行的动作集。
                  流表项总共64个。
     */
    table dstmactable {
        key = { hd.ipv4.dstAddr : exact; }
        actions = {
            Forward_action;
	        Redirect_action;
            Drop_action;
        }
        default_action = Drop_action;
        implementation = hash_table(64);
    }

    apply {
        /* 如果数据包为ip包，执行查表匹配操作 */
		if (hd.ipv4.isValid())
		{
            dstmactable.apply();
		}
        xout.output_port = 0;
        xout.output_action = xact;
    }
}

/* -------------------------------------------
 *         定义修改后的数据包组装逻辑
 * -------------------------------------------
 */
control Deparser(in Headers hdrs, packet_out packet) {
    apply {
        packet.emit(hdrs.ethernet);
        packet.emit(hdrs.ipv4);
    }
}

xdp(Parser(), Ingress(), Deparser()) main;


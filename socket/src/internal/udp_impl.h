/**
 * @file udp_impl.h
 * @brief UDP协议实现
 *
 * 实现UDP协议的核心功能，包括数据包的创建、发送和接收。
 * 基于DPDK实现高性能网络通信。
 *
 * @author 冯昊阳
 * @date 2025年2月18日
 */
#ifndef MYLIB_INTERNAL_UDP_IMPL_H
#define MYLIB_INTERNAL_UDP_IMPL_H

#include <rte_udp.h>
#include "common.h"
#include "arp_impl.h" /*作为填充UDP包头时，获取相应的MAC*/

/* UDP控制块结构 */
struct udp_control_block {
    struct mylib_socket *sock;     /* 关联的socket */
    
    /* 地址信息 */
    uint32_t remote_ip;           /* 远程IP */
    uint16_t remote_port;         /* 远程端口 */
    
    /* 统计信息 */
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    
    /* 链表指针 */
    struct udp_control_block *prev;
    struct udp_control_block *next;
};

/* UDP数据包结构 */
struct udp_packet {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t *data;
    uint16_t length;
};

/* 函数声明 */
mylib_error_t udp_init(void);
void udp_cleanup(void);
mylib_error_t udp_process_packet(struct rte_mbuf *mbuf);
struct rte_mbuf *udp_create_packet(struct udp_control_block *ucb,
                                 struct udp_packet *pkt);
mylib_error_t udp_output(struct udp_control_block *ucb);
void udp_input(struct udp_control_block *ucb, struct udp_packet *pkt);
struct udp_control_block *udp_create_ucb(struct mylib_socket *sock);
void udp_destroy_ucb(struct udp_control_block *ucb);

/* 查找函数 */
struct udp_control_block *udp_find_ucb(uint32_t local_ip, uint16_t local_port);

#endif /* MYLIB_INTERNAL_UDP_IMPL_H */ 
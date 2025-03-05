/**
 * @file icmp_impl.h
 * @brief ICMP协议实现
 *
 * 实现ICMP协议的核心功能，包括校验和计算、ARP表更新、Echo Request处理等。
 * 基于DPDK实现高性能网络通信。
 *
 * @author 冯昊阳
 * @date 2025年2月18日
 */
#ifndef _ICMP_IMPL_H_
#define _ICMP_IMPL_H_

#include <rte_mbuf.h>
#include <rte_icmp.h>
#include "common.h"
#include "arp_impl.h" /*作为填充ICMP包头时，获取相应的MAC*/

/* ICMP处理函数声明 */
mylib_error_t icmp_init(void);
void icmp_cleanup(void);
mylib_error_t icmp_process_packet(struct rte_mbuf *mbuf);

/* ICMP校验和计算函数 */
uint16_t icmp_checksum(const void *buf, size_t len);

#endif /* _ICMP_IMPL_H_ */ 
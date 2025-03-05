/**
 * @file dpdk_init.h
 * @brief DPDK初始化
 *
 * 实现DPDK的初始化功能，包括EAL初始化、内存池创建、端口配置等。
 * 基于DPDK实现高性能网络通信。
 *
 * @author 冯昊阳
 * @date 2025年2月18日
 */
#ifndef MYLIB_DPDK_INIT_H
#define MYLIB_DPDK_INIT_H

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include "../../include/mylib/core.h"

/* DPDK配置参数 */
#define MEMPOOL_CACHE_SIZE 256
#define NUM_MBUFS 8191
#define MBUF_SIZE (1600 + RTE_PKTMBUF_HEADROOM)
#define RX_RING_SIZE 128
#define TX_RING_SIZE 128

/* 函数声明 */
mylib_error_t init_dpdk(void);
mylib_error_t init_port(uint16_t port_id);
mylib_error_t init_mempool(void);
void cleanup_dpdk(void);

#endif /* MYLIB_DPDK_INIT_H */ 
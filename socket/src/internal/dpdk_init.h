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
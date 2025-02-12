#ifndef __DPDK_INIT_H__
#define __DPDK_INIT_H__

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_malloc.h>

// 日志级别定义
#define SOCKET_LOG_ERROR 0
#define SOCKET_LOG_INFO  1

// 错误码定义
#define SOCKET_SUCCESS       0
#define SOCKET_ERROR_INVALID -1
#define SOCKET_ERROR_NOMEM   -2

// 基本配置
#define NUM_MBUFS 8192
#define MBUF_CACHE_SIZE 250
#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

// 简单的日志宏
#define SOCKET_LOG(level, fmt, ...) \
    printf("[%s] " fmt "\n", \
        (level) == SOCKET_LOG_ERROR ? "ERROR" : "INFO", \
        ##__VA_ARGS__)

// 全局变量声明
extern struct rte_mempool *g_mbuf_pool;
extern uint8_t g_src_mac[6];
extern struct ring_pair *g_ring;

// 环形缓冲区结构
struct ring_pair {
    struct rte_ring *in;
    struct rte_ring *out;
};

// 函数声明
int init_dpdk(void);

#endif /* __DPDK_INIT_H__ */ 
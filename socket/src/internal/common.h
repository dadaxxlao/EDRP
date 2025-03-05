/**
 * @file common.h
 * @brief 公共头文件
 *
 * 定义了内部使用的数据结构和函数声明。
 * 基于DPDK实现高性能网络通信。
 *
 * @author 冯昊阳
 * @date 2025年2月18日
 */
#ifndef MYLIB_INTERNAL_COMMON_H
#define MYLIB_INTERNAL_COMMON_H

#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_ip4.h>
#include <pthread.h>
#include "../../include/mylib/core.h"

/* 内部使用的链表操作宏 */
#define LL_ADD(item, list) do {        \
    item->prev = NULL;                 \
    item->next = list;                 \
    if (list != NULL) list->prev = item; \
    list = item;                       \
} while(0)

#define LL_REMOVE(item, list) do {     \
    if (item->prev != NULL) item->prev->next = item->next; \
    if (item->next != NULL) item->next->prev = item->prev; \
    if (list == item) list = item->next; \
    item->prev = item->next = NULL;    \
} while(0)

/* TCP序列号比较宏 */
#define SEQ_LT(a,b) ((int32_t)((a)-(b)) < 0)
#define SEQ_LEQ(a,b) ((int32_t)((a)-(b)) <= 0)
#define SEQ_GT(a,b) ((int32_t)((a)-(b)) > 0)
#define SEQ_GEQ(a,b) ((int32_t)((a)-(b)) >= 0)

/* 内部Socket结构定义 */
struct mylib_socket {
    int fd;                     /* 文件描述符 */
    uint32_t local_ip;         /* 本地IP地址 */
    uint16_t local_port;       /* 本地端口 */
    uint8_t protocol;          /* 协议类型 */
    int non_blocking;          /* 非阻塞标志 */
    
    /* 缓冲区 */
    struct rte_ring *send_buf;
    struct rte_ring *recv_buf;
    
    /* 同步原语 */
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    
    /* 链表指针 */
    struct mylib_socket *prev;
    struct mylib_socket *next;
};

/* 全局变量声明 */
extern struct tcp_control_block *g_tcb_list;
extern struct udp_control_block *g_ucb_list;
extern pthread_mutex_t g_tcp_mutex;
extern pthread_mutex_t g_udp_mutex;

/* 内部配置结构定义 */
struct mylib_config {
    mylib_config_t public_config;  /* 公共配置 */
    pthread_mutex_t mutex;         /* 配置互斥锁 */
};

/* 内部全局变量声明 */
extern struct rte_mempool *g_mbuf_pool;
extern struct rte_ring *g_in_ring;
extern struct rte_ring *g_out_ring;
extern uint8_t g_local_mac[RTE_ETHER_ADDR_LEN];
extern uint32_t g_local_ip;

/* 内部函数声明 */
mylib_error_t init_dpdk(void);
mylib_error_t init_rings(void);
void cleanup_rings(void);
int check_port_in_use(uint16_t port);
int allocate_fd(void);
void release_fd(int fd);

#endif /* MYLIB_INTERNAL_COMMON_H */ 
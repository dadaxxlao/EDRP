/**
 * @file arp_impl.h
 * @brief ARP协议实现
 *
 * 实现ARP协议的核心功能，包括ARP表管理、ARP请求队列管理、ARP解析回调等。
 * 基于DPDK实现高性能网络通信。
 *
 * @author 冯昊阳
 * @date 2025年2月18日
 */
#ifndef MYLIB_INTERNAL_ARP_IMPL_H
#define MYLIB_INTERNAL_ARP_IMPL_H

#include <rte_arp.h>
#include <limits.h>  
#include "common.h"

/* ARP表项状态 */
#define ARP_ENTRY_STATE_DYNAMIC    0
#define ARP_ENTRY_STATE_STATIC     1
#define ARP_ENTRY_STATE_PENDING    2

/* ARP表项超时时间（秒） */
#define ARP_ENTRY_TIMEOUT         600    /* 10分钟 */
#define ARP_PENDING_TIMEOUT       2      /* 2秒 */

/* ARP表持久化相关定义 */
#define ARP_TABLE_VERSION         1     /* 文件格式版本号 */
#define ARP_TABLE_FILE           "/home/dpdk1/EDRP/socket/arp_table.txt"
#define ARP_TABLE_SAVE_INTERVAL  300    /* 定期保存间隔(秒) */
#define ARP_TABLE_FILE_MODE      0600   /* 文件权限 */
#define ARP_TABLE_DIR_MODE       0755   /* 目录权限 */

/* ARP表项结构 */
struct arp_entry {
    uint32_t ip;                        /* IP地址 */
    uint8_t mac[RTE_ETHER_ADDR_LEN];    /* MAC地址 */
    uint8_t state;                      /* 状态 */
    time_t timestamp;                   /* 最后更新时间 */
    struct arp_entry *prev;
    struct arp_entry *next;
};

/* ARP请求队列项 */
struct arp_request {
    uint32_t ip;                        /* 目标IP */
    struct rte_mbuf *pending_packet;    /* 等待发送的数据包 */
    time_t timestamp;                   /* 请求发起时间 */
    uint8_t retry_count;                /* 重试次数 */
    struct arp_request *prev;
    struct arp_request *next;
};

/* 函数声明 */
mylib_error_t arp_init(void);
void arp_cleanup(void);
mylib_error_t arp_process_packet(struct rte_mbuf *mbuf);
struct rte_mbuf *arp_create_request(uint32_t target_ip);
struct rte_mbuf *arp_create_reply(uint32_t sender_ip, uint32_t target_ip,
                                const uint8_t *target_mac);

/* ARP表管理函数 */
struct arp_entry *arp_lookup(uint32_t ip);
mylib_error_t arp_add_entry(uint32_t ip, const uint8_t *mac, 
                           uint8_t state, time_t timestamp);
void arp_remove_entry(struct arp_entry *entry);
void arp_update_entry(struct arp_entry *entry, const uint8_t *mac);

/* ARP请求队列管理函数 */
mylib_error_t arp_queue_packet(uint32_t ip, struct rte_mbuf *mbuf);
void arp_process_pending_requests(void);
void arp_cleanup_pending_requests(void);

/* ARP解析回调函数 */
mylib_error_t tcp_handle_arp_resolution(uint32_t ip, const uint8_t *mac);

/* 定时器处理函数 */
void arp_timer_handler(void);

/* ARP表持久化函数与定义 */
mylib_error_t arp_save_table(void);
mylib_error_t arp_load_table(void);
extern volatile int g_arp_table_dirty;
extern volatile int g_static_entry_count;

#endif /* MYLIB_INTERNAL_ARP_IMPL_H */ 
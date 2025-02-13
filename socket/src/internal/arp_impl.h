#ifndef MYLIB_INTERNAL_ARP_IMPL_H
#define MYLIB_INTERNAL_ARP_IMPL_H

#include <rte_arp.h>
#include "common.h"

/* ARP表项状态 */
#define ARP_ENTRY_STATE_DYNAMIC    0
#define ARP_ENTRY_STATE_STATIC     1
#define ARP_ENTRY_STATE_PENDING    2

/* ARP表项超时时间（秒） */
#define ARP_ENTRY_TIMEOUT         600    /* 10分钟 */
#define ARP_PENDING_TIMEOUT       2      /* 2秒 */

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
mylib_error_t arp_add_entry(uint32_t ip, const uint8_t *mac, uint8_t state);
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

#endif /* MYLIB_INTERNAL_ARP_IMPL_H */ 
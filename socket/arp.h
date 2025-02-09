#ifndef __EDRP_ARP_H__
#define __EDRP_ARP_H__

#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_arp.h>

#include "socket.h"

#define ARP_ENTRY_STATUS_DYNAMIC 0
#define ARP_ENTRY_STATUS_STATIC  1

#define LL_ADD(item, list) do {		\
	item->prev = NULL;				\
	item->next = list;				\
	if (list != NULL) list->prev = item; \
	list = item;					\
} while(0)


#define LL_REMOVE(item, list) do {		\
	if (item->prev != NULL) item->prev->next = item->next;	\
	if (item->next != NULL) item->next->prev = item->prev;	\
	if (list == item) list = item->next;	\
	item->prev = item->next = NULL;			\
} while(0)


struct arp_entry {
    uint32_t ip;
    uint8_t hwaddr[RTE_ETHER_ADDR_LEN];
    uint8_t type; // ARP_ENTRY_STATUS_DYNAMIC or STATIC
    struct arp_entry *next;
    struct arp_entry *prev;
};

struct arp_table {
    struct arp_entry *entries;
    int count;
};

struct offload { //

	uint32_t sip;
	uint32_t dip;

	uint16_t sport;
	uint16_t dport; //

	int protocol;

	unsigned char *data;
	uint16_t length;
	
};

/**
 * @brief 获取ARP表实例
 */
struct arp_table *arp_table_instance(void);

/**
 * @brief 根据IP地址查找目标MAC地址
 */
uint8_t* arp_get_dst_macaddr(uint32_t ip);

/**
 * @brief 插入新的ARP表项
 */
int arp_add_entry(uint32_t ip, uint8_t *hwaddr, uint8_t type);

/**
 * @brief 发送ARP请求包
 */
struct rte_mbuf *arp_send_request(struct rte_mempool *mbuf_pool, uint32_t dip);

/**
 * @brief 发送ARP应答包
 */
struct rte_mbuf *arp_send_reply(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip, uint8_t *dst_mac);

#endif

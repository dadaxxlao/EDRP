#include "arp.h"
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_eal.h>
#include <stdio.h>
#include <string.h>

static struct arp_table *arpt = NULL;

/**
 * @brief 获取ARP表实例
 */
struct arp_table *arp_table_instance(void) {
    if (arpt == NULL) {
        arpt = rte_malloc("arp_table", sizeof(struct arp_table), 0);
        if (arpt == NULL) {
            rte_exit(EXIT_FAILURE, "ARP table allocation failed\n");
        }
        memset(arpt, 0, sizeof(struct arp_table));
    }
    return arpt;
}

/**
 * @brief 根据IP地址查找目标MAC地址
 */
uint8_t* arp_get_dst_macaddr(uint32_t ip) {
    struct arp_entry *iter;
    struct arp_table *table = arp_table_instance();
    for (iter = table->entries; iter != NULL; iter = iter->next) {
        if (iter->ip == ip) {
            return iter->hwaddr;
        }
    }
    return NULL;
}

/**
 * @brief 插入新的ARP表项
 */
int arp_add_entry(uint32_t ip, uint8_t *hwaddr, uint8_t type) {
    struct arp_table *table = arp_table_instance();
    struct arp_entry *entry = rte_malloc("arp_entry", sizeof(struct arp_entry), 0);
    if (entry == NULL) {
        return -1;
    }

    memset(entry, 0, sizeof(struct arp_entry));
    entry->ip = ip;
    rte_memcpy(entry->hwaddr, hwaddr, RTE_ETHER_ADDR_LEN);
    entry->type = type;

    entry->next = table->entries;
    if (table->entries != NULL) {
        table->entries->prev = entry;
    }
    table->entries = entry;
    table->count++;
    return 0;
}

/**
 * @brief 发送ARP请求包
 */
struct rte_mbuf *arp_send_request(struct rte_mempool *mbuf_pool, uint32_t dip) {
    const unsigned total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "ARP request mbuf allocation failed\n");
    }

    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;
    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt_data;

    // 以太网头部
    rte_memcpy(eth->src_addr.addr_bytes, g_src_mac, RTE_ETHER_ADDR_LEN);
    uint8_t mac[RTE_ETHER_ADDR_LEN] = {0};
    rte_memcpy(eth->dst_addr.addr_bytes, mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

    // ARP头部
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
    arp->arp_hardware = htons(1);
    arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp->arp_plen = sizeof(uint32_t);
    arp->arp_opcode = htons(RTE_ARP_OP_REQUEST);

    rte_memcpy(arp->arp_data.arp_sha.addr_bytes, g_src_mac, RTE_ETHER_ADDR_LEN);
    memset(arp->arp_data.arp_tha.addr_bytes, 0, RTE_ETHER_ADDR_LEN); // 目标MAC地址为零
    arp->arp_data.arp_sip = g_local_ip;
    arp->arp_data.arp_tip = dip;

    return mbuf;
}

/**
 * @brief 发送ARP应答包
 */
struct rte_mbuf *arp_send_reply(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip, uint8_t *dst_mac) {
    const unsigned total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "ARP reply mbuf allocation failed\n");
    }

    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;
    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt_data;

    // 以太网头部
    rte_memcpy(eth->src_addr.addr_bytes, g_src_mac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->dst_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

    // ARP头部
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
    arp->arp_hardware = htons(1);
    arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp->arp_plen = sizeof(uint32_t);
    arp->arp_opcode = htons(RTE_ARP_OP_REPLY);

    rte_memcpy(arp->arp_data.arp_sha.addr_bytes, g_src_mac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    arp->arp_data.arp_sip = sip;
    arp->arp_data.arp_tip = dip;

    return mbuf;
}

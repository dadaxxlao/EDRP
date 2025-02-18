#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_icmp.h>
#include <rte_malloc.h>

#include "internal/icmp_impl.h"
#include "internal/logging.h"
#include "internal/common.h"

/* ICMP校验和计算 */
uint16_t icmp_checksum(const void *buf, size_t len) {
    const uint16_t *ptr = (const uint16_t *)buf;
    uint32_t sum = 0;

    /* 按16位累加 */
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    /* 处理剩余的字节 */
    if (len == 1) {
        sum += *((const uint8_t *)ptr);
    }

    /* 处理进位 */
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (uint16_t)~sum;
}

/* ICMP初始化 */
mylib_error_t icmp_init(void) {
    MYLIB_LOG(LOG_LEVEL_INFO, "ICMP module initialized");
    return MYLIB_SUCCESS;
}

/* ICMP清理 */
void icmp_cleanup(void) {
    MYLIB_LOG(LOG_LEVEL_INFO, "ICMP module cleaned up");
}

/* ICMP报文处理 */
mylib_error_t icmp_process_packet(struct rte_mbuf *mbuf) {
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ip_hdr;
    struct rte_icmp_hdr *icmp_hdr;
    uint16_t icmp_len;

    /* 获取以太网头部 */
    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

    /* 获取IP头部 */
    ip_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, 
                                    sizeof(struct rte_ether_hdr));
    
    /* 获取ICMP头部 */
    icmp_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_icmp_hdr *,
                                      sizeof(struct rte_ether_hdr) + 
                                      sizeof(struct rte_ipv4_hdr));

    /* 计算ICMP长度 */
    icmp_len = ntohs(ip_hdr->total_length) - sizeof(struct rte_ipv4_hdr);

    /* 验证ICMP校验和 */
    if (icmp_checksum(icmp_hdr, icmp_len) != 0) {
        MYLIB_LOG(LOG_LEVEL_WARNING, "Invalid ICMP checksum");
        return MYLIB_ERROR_INVALID;
    }

    /* 更新ARP表 */
    struct arp_entry *entry = arp_lookup(ip_hdr->src_addr);
    if (entry) {
        /* 更新已存在的表项 */
        arp_update_entry(entry, eth_hdr->src_addr.addr_bytes);
        MYLIB_LOG(LOG_LEVEL_DEBUG, "Updated ARP entry from ICMP packet");
    } else {
        /* 添加新表项 */
        if (arp_add_entry(ip_hdr->src_addr, eth_hdr->src_addr.addr_bytes, 
                         ARP_ENTRY_STATE_DYNAMIC, time(NULL)) != MYLIB_SUCCESS) {
            MYLIB_LOG(LOG_LEVEL_WARNING, "Failed to add ARP entry from ICMP packet");
        } else {
            MYLIB_LOG(LOG_LEVEL_DEBUG, "Added new ARP entry from ICMP packet");
        }
    }

    /* 处理Echo Request */
    if (icmp_hdr->icmp_type == RTE_ICMP_TYPE_ECHO_REQUEST) {
        /* 修改ICMP类型为Reply */
        icmp_hdr->icmp_type = RTE_ICMP_TYPE_ECHO_REPLY;
        icmp_hdr->icmp_code = 0;
        icmp_hdr->icmp_cksum = 0;
        icmp_hdr->icmp_cksum = icmp_checksum(icmp_hdr, icmp_len);

        /* 交换源目MAC地址 */
        struct rte_ether_addr tmp_mac;
        rte_memcpy(&tmp_mac, &eth_hdr->src_addr, sizeof(struct rte_ether_addr));
        rte_memcpy(&eth_hdr->src_addr, &eth_hdr->dst_addr, sizeof(struct rte_ether_addr));
        rte_memcpy(&eth_hdr->dst_addr, &tmp_mac, sizeof(struct rte_ether_addr));

        /* 交换源目IP地址 */
        uint32_t tmp_ip = ip_hdr->src_addr;
        ip_hdr->src_addr = ip_hdr->dst_addr;
        ip_hdr->dst_addr = tmp_ip;
        ip_hdr->time_to_live = 64;

        /* 重新计算IP校验和 */
        ip_hdr->hdr_checksum = 0;
        ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

        /* 发送Echo Reply */
        if (rte_ring_enqueue(g_out_ring, mbuf) < 0) {
            MYLIB_LOG(LOG_LEVEL_WARNING, "Failed to enqueue ICMP reply");
            rte_pktmbuf_free(mbuf);
            return MYLIB_ERROR_INVALID;
        }

        MYLIB_LOG(LOG_LEVEL_DEBUG, "Sent ICMP Echo Reply");
        return MYLIB_SUCCESS;
    }

    /* 其他ICMP类型暂不处理 */
    MYLIB_LOG(LOG_LEVEL_DEBUG, "Unsupported ICMP type: %d", icmp_hdr->icmp_type);
    rte_pktmbuf_free(mbuf);
    return MYLIB_SUCCESS;
} 
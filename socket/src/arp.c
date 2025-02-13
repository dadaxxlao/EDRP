#include <rte_arp.h>
#include <rte_malloc.h>
#include <string.h>
#include <time.h>

#include "internal/arp_impl.h"
#include "internal/logging.h"
#include "internal/common.h"

/* 全局变量 */
static struct arp_entry *g_arp_table = NULL;
static struct arp_request *g_arp_requests = NULL;
static pthread_mutex_t g_arp_mutex = PTHREAD_MUTEX_INITIALIZER;

mylib_error_t arp_init(void) {
    pthread_mutex_lock(&g_arp_mutex);
    g_arp_table = NULL;
    g_arp_requests = NULL;
    pthread_mutex_unlock(&g_arp_mutex);
    
    MYLIB_LOG(LOG_LEVEL_INFO, "ARP module initialized");
    return MYLIB_SUCCESS;
}

void arp_cleanup(void) {
    pthread_mutex_lock(&g_arp_mutex);
    
    /* 清理ARP表 */
    struct arp_entry *entry = g_arp_table;
    while (entry) {
        struct arp_entry *next = entry->next;
        rte_free(entry);
        entry = next;
    }
    g_arp_table = NULL;
    
    /* 清理请求队列 */
    struct arp_request *req = g_arp_requests;
    while (req) {
        struct arp_request *next = req->next;
        if (req->pending_packet) {
            rte_pktmbuf_free(req->pending_packet);
        }
        rte_free(req);
        req = next;
    }
    g_arp_requests = NULL;
    
    pthread_mutex_unlock(&g_arp_mutex);
    
    MYLIB_LOG(LOG_LEVEL_INFO, "ARP module cleaned up");
}

struct arp_entry *arp_lookup(uint32_t ip) {
    pthread_mutex_lock(&g_arp_mutex);
    
    struct arp_entry *entry;
    for (entry = g_arp_table; entry != NULL; entry = entry->next) {
        if (entry->ip == ip) {
            break;
        }
    }
    
    pthread_mutex_unlock(&g_arp_mutex);
    return entry;
}

mylib_error_t arp_add_entry(uint32_t ip, const uint8_t *mac, uint8_t state) {
    struct arp_entry *entry = rte_malloc("arp_entry", sizeof(struct arp_entry), 0);
    if (!entry) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to allocate ARP entry");
        return MYLIB_ERROR_NOMEM;
    }

    /* 初始化表项 */
    entry->ip = ip;
    rte_memcpy(entry->mac, mac, RTE_ETHER_ADDR_LEN);
    entry->state = state;
    entry->timestamp = time(NULL);
    
    /* 添加到ARP表 */
    pthread_mutex_lock(&g_arp_mutex);
    LL_ADD(entry, g_arp_table);
    pthread_mutex_unlock(&g_arp_mutex);
    
    MYLIB_LOG(LOG_LEVEL_DEBUG, "Added ARP entry for IP %u.%u.%u.%u",
            (ip & 0xFF),
            (ip >> 8) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 24) & 0xFF);
    return MYLIB_SUCCESS;
}

void arp_remove_entry(struct arp_entry *entry) {
    if (!entry) return;

    pthread_mutex_lock(&g_arp_mutex);
    LL_REMOVE(entry, g_arp_table);
    rte_free(entry);
    pthread_mutex_unlock(&g_arp_mutex);
    
    MYLIB_LOG(LOG_LEVEL_DEBUG, "Removed ARP entry");
}

void arp_update_entry(struct arp_entry *entry, const uint8_t *mac) {
    if (!entry) return;

    pthread_mutex_lock(&g_arp_mutex);
    rte_memcpy(entry->mac, mac, RTE_ETHER_ADDR_LEN);
    entry->timestamp = time(NULL);
    pthread_mutex_unlock(&g_arp_mutex);
    
    MYLIB_LOG(LOG_LEVEL_DEBUG, "Updated ARP entry for IP %u.%u.%u.%u", 
            (entry->ip & 0xFF),
            (entry->ip >> 8) & 0xFF,
            (entry->ip >> 16) & 0xFF,
            (entry->ip >> 24) & 0xFF);
}

mylib_error_t arp_queue_packet(uint32_t ip, struct rte_mbuf *mbuf) {
    struct arp_request *req = rte_malloc("arp_request", sizeof(struct arp_request), 0);
    if (!req) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to allocate ARP request");
        return MYLIB_ERROR_NOMEM;
    }

    /* 初始化请求 */
    req->ip = ip;
    req->pending_packet = mbuf;
    req->timestamp = time(NULL);
    req->retry_count = 0;
    
    /* 添加到请求队列 */
    pthread_mutex_lock(&g_arp_mutex);
    LL_ADD(req, g_arp_requests);
    pthread_mutex_unlock(&g_arp_mutex);
    
    //MYLIB_LOG(LOG_LEVEL_DEBUG, "Queued packet for IP 0x%x", ip);
    MYLIB_LOG(LOG_LEVEL_DEBUG, "Queued packet for IP %u.%u.%u.%u", 
            (ip & 0xFF),
            (ip >> 8) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 24) & 0xFF); 
    return MYLIB_SUCCESS;
}

void arp_process_pending_requests(void) {
    pthread_mutex_lock(&g_arp_mutex);
    
    time_t now = time(NULL);
    struct arp_request *req = g_arp_requests;
    
    while (req) {
        struct arp_request *next = req->next;
        
        /* 检查是否超时 */
        if (now - req->timestamp >= ARP_PENDING_TIMEOUT) {
            if (req->retry_count < 3) {
                /* 重新发送ARP请求 */
                struct rte_mbuf *arp_req = arp_create_request(req->ip);
                if (arp_req) {
                    rte_ring_mp_enqueue(g_out_ring, arp_req);
                    req->timestamp = now;
                    req->retry_count++;
                }
            } else {
                /* 超过重试次数，放弃该请求 */
                if (req->pending_packet) {
                    rte_pktmbuf_free(req->pending_packet);
                }
                LL_REMOVE(req, g_arp_requests);
                rte_free(req);
            }
        }
        
        req = next;
    }
    
    pthread_mutex_unlock(&g_arp_mutex);
}

void arp_cleanup_pending_requests(void) {
    pthread_mutex_lock(&g_arp_mutex);
    
    struct arp_request *req = g_arp_requests;
    while (req) {
        struct arp_request *next = req->next;
        if (req->pending_packet) {
            rte_pktmbuf_free(req->pending_packet);
        }
        rte_free(req);
        req = next;
    }
    g_arp_requests = NULL;
    
    pthread_mutex_unlock(&g_arp_mutex);
}

struct rte_mbuf *arp_create_request(uint32_t target_ip) {
    /* 分配mbuf */
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(g_mbuf_pool);
    if (!mbuf) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to allocate mbuf for ARP request");
        return NULL;
    }

    /* 计算总长度 */
    uint16_t total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    
    /* 初始化mbuf */
    mbuf->data_len = total_len;
    mbuf->pkt_len = total_len;
    
    /* 构建以太网头 */
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    rte_memcpy(eth_hdr->src_addr.addr_bytes, g_local_mac, RTE_ETHER_ADDR_LEN);
    memset(eth_hdr->dst_addr.addr_bytes, 0xFF, RTE_ETHER_ADDR_LEN);  // 广播
    eth_hdr->ether_type = htons(RTE_ETHER_TYPE_ARP);
    
    /* 构建ARP头 */
    struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);
    arp_hdr->arp_hardware = htons(RTE_ARP_HRD_ETHER);
    arp_hdr->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp_hdr->arp_plen = sizeof(uint32_t);
    arp_hdr->arp_opcode = htons(RTE_ARP_OP_REQUEST);
    
    rte_memcpy(arp_hdr->arp_data.arp_sha.addr_bytes, g_local_mac, RTE_ETHER_ADDR_LEN);
    arp_hdr->arp_data.arp_sip = g_local_ip;
    memset(arp_hdr->arp_data.arp_tha.addr_bytes, 0, RTE_ETHER_ADDR_LEN);
    arp_hdr->arp_data.arp_tip = target_ip;
    
    return mbuf;
}

struct rte_mbuf *arp_create_reply(uint32_t sender_ip, uint32_t target_ip,
                                const uint8_t *target_mac) {
    /* 分配mbuf */
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(g_mbuf_pool);
    if (!mbuf) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to allocate mbuf for ARP reply");
        return NULL;
    }

    /* 计算总长度 */
    uint16_t total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    
    /* 初始化mbuf */
    mbuf->data_len = total_len;
    mbuf->pkt_len = total_len;
    
    /* 构建以太网头 */
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    rte_memcpy(eth_hdr->src_addr.addr_bytes, g_local_mac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth_hdr->dst_addr.addr_bytes, target_mac, RTE_ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(RTE_ETHER_TYPE_ARP);
    
    /* 构建ARP头 */
    struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);
    arp_hdr->arp_hardware = htons(RTE_ARP_HRD_ETHER);
    arp_hdr->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp_hdr->arp_plen = sizeof(uint32_t);
    arp_hdr->arp_opcode = htons(RTE_ARP_OP_REPLY);
    
    rte_memcpy(arp_hdr->arp_data.arp_sha.addr_bytes, g_local_mac, RTE_ETHER_ADDR_LEN);
    arp_hdr->arp_data.arp_sip = sender_ip;
    rte_memcpy(arp_hdr->arp_data.arp_tha.addr_bytes, target_mac, RTE_ETHER_ADDR_LEN);
    arp_hdr->arp_data.arp_tip = target_ip;
    
    return mbuf;
}

mylib_error_t arp_process_packet(struct rte_mbuf *mbuf) {
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);
    
    /* 检查ARP包类型 */
    if (ntohs(arp_hdr->arp_hardware) != RTE_ARP_HRD_ETHER ||
        ntohs(arp_hdr->arp_protocol) != RTE_ETHER_TYPE_IPV4 ||
        arp_hdr->arp_hlen != RTE_ETHER_ADDR_LEN ||
        arp_hdr->arp_plen != sizeof(uint32_t)) {
        MYLIB_LOG(LOG_LEVEL_WARNING, "Invalid ARP packet format");
        return MYLIB_ERROR_INVALID;
    }

    uint16_t opcode = ntohs(arp_hdr->arp_opcode);
    switch (opcode) {
        case RTE_ARP_OP_REQUEST:
            /* 处理ARP请求 */
            if (arp_hdr->arp_data.arp_tip == g_local_ip) {
                /* 发送ARP应答 */
                struct rte_mbuf *reply = arp_create_reply(g_local_ip,
                                                        arp_hdr->arp_data.arp_sip,
                                                        arp_hdr->arp_data.arp_sha.addr_bytes);
                if (reply) {
                    rte_ring_mp_enqueue(g_out_ring, reply);
                }
            }
            break;
            
        case RTE_ARP_OP_REPLY:
            /* 处理ARP应答 */
            {
                struct arp_entry *entry = arp_lookup(arp_hdr->arp_data.arp_sip);
                if (entry) {
                    /* 更新已存在的表项 */
                    arp_update_entry(entry, arp_hdr->arp_data.arp_sha.addr_bytes);
                } else {
                    /* 添加新表项 */
                    arp_add_entry(arp_hdr->arp_data.arp_sip,
                                arp_hdr->arp_data.arp_sha.addr_bytes,
                                ARP_ENTRY_STATE_DYNAMIC);
                }
                
                /* 处理等待该IP的数据包 */
                pthread_mutex_lock(&g_arp_mutex);
                struct arp_request *req = g_arp_requests;
                while (req) {
                    if (req->ip == arp_hdr->arp_data.arp_sip) {
                        if (req->pending_packet) {
                            /* 更新数据包的目标MAC地址并发送 */
                            struct rte_ether_hdr *pkt_eth = rte_pktmbuf_mtod(req->pending_packet,
                                                                           struct rte_ether_hdr *);
                            rte_memcpy(pkt_eth->dst_addr.addr_bytes,
                                     arp_hdr->arp_data.arp_sha.addr_bytes,
                                     RTE_ETHER_ADDR_LEN);
                            rte_ring_mp_enqueue(g_out_ring, req->pending_packet);
                            req->pending_packet = NULL;
                        }
                        struct arp_request *next = req->next;
                        LL_REMOVE(req, g_arp_requests);
                        rte_free(req);
                        req = next;
                    } else {
                        req = req->next;
                    }
                }
                pthread_mutex_unlock(&g_arp_mutex);
                /* 通知TCP模块ARP已解析 */
                tcp_handle_arp_resolution(arp_hdr->arp_data.arp_sip,
                                arp_hdr->arp_data.arp_sha.addr_bytes);
            }
            break;
            
        default:
            MYLIB_LOG(LOG_LEVEL_WARNING, "Unknown ARP opcode: %d", opcode);
            return MYLIB_ERROR_INVALID;
    }
    
    return MYLIB_SUCCESS;
}

void arp_timer_handler(void) {
    pthread_mutex_lock(&g_arp_mutex);
    
    time_t now = time(NULL);
    struct arp_entry *entry = g_arp_table;
    
    while (entry) {
        struct arp_entry *next = entry->next;
        
        /* 检查动态表项是否超时 */
        if (entry->state == ARP_ENTRY_STATE_DYNAMIC &&
            now - entry->timestamp >= ARP_ENTRY_TIMEOUT) {
            LL_REMOVE(entry, g_arp_table);
            rte_free(entry);
        }
        
        entry = next;
    }
    
    pthread_mutex_unlock(&g_arp_mutex);
    
    /* 处理等待中的ARP请求 */
    arp_process_pending_requests();
} 
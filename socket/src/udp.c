#include <rte_udp.h>
#include <rte_malloc.h>
#include <string.h>

#include "internal/udp_impl.h"
#include "internal/logging.h"
#include "internal/common.h"

/* 全局变量 */
struct udp_control_block *g_ucb_list = NULL;
pthread_mutex_t g_udp_mutex = PTHREAD_MUTEX_INITIALIZER;

mylib_error_t udp_init(void) {
    pthread_mutex_lock(&g_udp_mutex);
    g_ucb_list = NULL;
    pthread_mutex_unlock(&g_udp_mutex);
    
    MYLIB_LOG(LOG_LEVEL_INFO, "UDP module initialized");
    return MYLIB_SUCCESS;
}

void udp_cleanup(void) {
    pthread_mutex_lock(&g_udp_mutex);
    
    /* 清理所有UDP控制块 */
    struct udp_control_block *ucb = g_ucb_list;
    while (ucb) {
        struct udp_control_block *next = ucb->next;
        udp_destroy_ucb(ucb);
        ucb = next;
    }
    g_ucb_list = NULL;
    
    pthread_mutex_unlock(&g_udp_mutex);
    
    MYLIB_LOG(LOG_LEVEL_INFO, "UDP module cleaned up");
}

struct udp_control_block *udp_create_ucb(struct mylib_socket *sock) {
    struct udp_control_block *ucb = rte_malloc("udp_cb", 
                                             sizeof(struct udp_control_block), 0);
    if (!ucb) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to allocate UDP control block");
        return NULL;
    }

    /* 初始化UCB */
    memset(ucb, 0, sizeof(struct udp_control_block));
    ucb->sock = sock;
    
    /* 添加到全局列表 */
    pthread_mutex_lock(&g_udp_mutex);
    LL_ADD(ucb, g_ucb_list);
    pthread_mutex_unlock(&g_udp_mutex);
    
    MYLIB_LOG(LOG_LEVEL_DEBUG, "Created UDP control block for socket fd=%d", 
              sock->fd);
    return ucb;
}

void udp_destroy_ucb(struct udp_control_block *ucb) {
    if (!ucb) return;

    pthread_mutex_lock(&g_udp_mutex);
    
    /* 从全局列表中移除 */
    LL_REMOVE(ucb, g_ucb_list);
    
    /* 释放资源 */
    rte_free(ucb);
    
    pthread_mutex_unlock(&g_udp_mutex);
    
    MYLIB_LOG(LOG_LEVEL_DEBUG, "Destroyed UDP control block");
}

struct udp_control_block *udp_find_ucb(uint32_t local_ip, uint16_t local_port) {
    pthread_mutex_lock(&g_udp_mutex);
    
    struct udp_control_block *ucb;
    for (ucb = g_ucb_list; ucb != NULL; ucb = ucb->next) {
        if (ucb->sock->local_ip == local_ip && 
            ucb->sock->local_port == local_port) {
            break;
        }
    }
    
    pthread_mutex_unlock(&g_udp_mutex);
    return ucb;
}

mylib_error_t udp_process_packet(struct rte_mbuf *mbuf) {
    struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(mbuf, 
                                                         struct rte_ipv4_hdr *, 
                                                         sizeof(struct rte_ether_hdr));
    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
    
    /* 查找对应的UCB */
    struct udp_control_block *ucb = udp_find_ucb(ip_hdr->dst_addr, 
                                                udp_hdr->dst_port);
    if (!ucb) {
        MYLIB_LOG(LOG_LEVEL_WARNING, "No UDP control block found for port %d",
                  ntohs(udp_hdr->dst_port));
        return MYLIB_ERROR_INVALID;
    }
    ucb->remote_ip = ip_hdr->src_addr;
    ucb->remote_port = udp_hdr->src_port;
    /* 创建UDP数据包结构 */
    struct udp_packet pkt;
    pkt.src_ip = ip_hdr->src_addr;
    pkt.dst_ip = ip_hdr->dst_addr;
    pkt.src_port = udp_hdr->src_port;
    pkt.dst_port = udp_hdr->dst_port;
    
    /* 计算数据长度 */
    pkt.length = ntohs(udp_hdr->dgram_len) - sizeof(struct rte_udp_hdr);
    
    if (pkt.length > 0) {
        pkt.data = rte_malloc("udp_data", pkt.length, 0);
        if (!pkt.data) {
            MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to allocate memory for UDP data");
            return MYLIB_ERROR_NOMEM;
        }
        rte_memcpy(pkt.data, (uint8_t *)(udp_hdr + 1), pkt.length);
    } else {
        pkt.data = NULL;
    }

    /* 处理UDP数据包 */
    udp_input(ucb, &pkt);
    
    /* 更新统计信息 */
    ucb->packets_received++;
    ucb->bytes_received += pkt.length;
    
    /* 清理资源 */
    if (pkt.data) {
        rte_free(pkt.data);
    }
    
    return MYLIB_SUCCESS;
}

struct rte_mbuf *udp_create_packet(struct udp_control_block *ucb,
                                 struct udp_packet *pkt) {
    /* 分配mbuf */
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(g_mbuf_pool);
    if (!mbuf) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to allocate mbuf for UDP packet");
        return NULL;
    }

    /* 计算总长度 */
    uint16_t total_len = sizeof(struct rte_ether_hdr) + 
                        sizeof(struct rte_ipv4_hdr) +
                        sizeof(struct rte_udp_hdr) +
                        pkt->length;
    
    /* 初始化mbuf */
    mbuf->data_len = total_len;
    mbuf->pkt_len = total_len;
    
    /* 构建以太网头 */
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    rte_memcpy(eth_hdr->src_addr.addr_bytes, g_local_mac, RTE_ETHER_ADDR_LEN);

    /* 获取目标MAC地址 */
    uint8_t *dst_mac = NULL;
    struct arp_entry *arp_entry = arp_lookup(pkt->dst_ip);
    if (arp_entry) {
        /* ARP表中存在对应表项 */
        dst_mac = arp_entry->mac;
        rte_memcpy(eth_hdr->dst_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    } else {
        /* 需要发送ARP请求并将数据包加入等待队列 */
        MYLIB_LOG(LOG_LEVEL_DEBUG, "No ARP entry found for IP %u.%u.%u.%u, sending ARP request", 
                  (pkt->dst_ip & 0xFF),
                  (pkt->dst_ip >> 8) & 0xFF,
                  (pkt->dst_ip >> 16) & 0xFF,
                  (pkt->dst_ip >> 24) & 0xFF);
                  
        /* 将数据包加入ARP等待队列 */
        if (arp_queue_packet(pkt->dst_ip, mbuf) != MYLIB_SUCCESS) {
            MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to queue packet for ARP");
            rte_pktmbuf_free(mbuf);
            return NULL;
        }
        
        /* 发送ARP请求 */
        struct rte_mbuf *arp_req = arp_create_request(pkt->dst_ip);
        if (arp_req) {
            if (rte_ring_mp_enqueue(g_out_ring, arp_req) < 0) {
                MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to enqueue ARP request");
                rte_pktmbuf_free(arp_req);
                /* 注意：数据包已经在ARP队列中，不需要释放 */
            }
        }
        
        return NULL; /* 数据包已加入等待队列 */
    }

    eth_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);
    
    /* 构建IP头 */
    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    ip_hdr->version_ihl = 0x45;
    ip_hdr->type_of_service = 0;
    ip_hdr->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    ip_hdr->packet_id = 0;
    ip_hdr->fragment_offset = 0;
    ip_hdr->time_to_live = 64;
    ip_hdr->next_proto_id = IPPROTO_UDP;
    ip_hdr->src_addr = pkt->src_ip;
    ip_hdr->dst_addr = pkt->dst_ip;
    ip_hdr->hdr_checksum = 0;
    ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
    
    /* 构建UDP头 */
    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
    udp_hdr->src_port = pkt->src_port;
    udp_hdr->dst_port = pkt->dst_port;
    udp_hdr->dgram_len = htons(sizeof(struct rte_udp_hdr) + pkt->length);
    udp_hdr->dgram_cksum = 0;
    
    /* 复制数据 */
    if (pkt->length > 0 && pkt->data) {
        uint8_t *payload = (uint8_t *)(udp_hdr + 1);
        rte_memcpy(payload, pkt->data, pkt->length);
    }
    
    /* 计算UDP校验和 */
    udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr, udp_hdr);
    
    return mbuf;
}

void udp_input(struct udp_control_block *ucb, struct udp_packet *pkt) {
    /* 将数据放入接收缓冲区 */
    if (pkt->length > 0 && pkt->data) {
        void *data = rte_malloc("udp_data", pkt->length, 0);
        if (data) {
            rte_memcpy(data, pkt->data, pkt->length);
            if (rte_ring_mp_enqueue(ucb->sock->recv_buf, data) < 0) {
                rte_free(data);
                MYLIB_LOG(LOG_LEVEL_WARNING, "Failed to enqueue UDP data");
                return;
            }
            
            /* 通知应用层有数据到达 */
            pthread_mutex_lock(&ucb->sock->mutex);
            pthread_cond_signal(&ucb->sock->cond);
            pthread_mutex_unlock(&ucb->sock->mutex);
        }
    }
}

mylib_error_t udp_output(struct udp_control_block *ucb) {
    /* 检查发送缓冲区 */
    void *data;
    if (rte_ring_mc_dequeue(ucb->sock->send_buf, &data) < 0) {
        return MYLIB_SUCCESS;  // 没有数据要发送
    }

    /* 创建UDP数据包 */
    struct udp_packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.src_ip = ucb->sock->local_ip;
    pkt.dst_ip = ucb->remote_ip;
    pkt.src_port = ucb->sock->local_port;
    pkt.dst_port = ucb->remote_port;
    pkt.data = data;
    pkt.length = strlen(data);  // TODO: 需要正确设置数据长度
    
    /* 创建并发送数据包 */
    struct rte_mbuf *mbuf = udp_create_packet(ucb, &pkt);
    if (!mbuf) {
        rte_free(data);
        return MYLIB_ERROR_NOMEM;
        MYLIB_LOG(LOG_LEVEL_WARNING, "Failed to create UDP data");
    }
    
    /* 将数据包放入发送队列 */
    if (rte_ring_mp_enqueue(g_out_ring, mbuf) < 0) {
        rte_pktmbuf_free(mbuf);
        rte_free(data);
        return MYLIB_ERROR_SEND;
    }
    
    /* 更新统计信息 */
    ucb->packets_sent++;
    ucb->bytes_sent += pkt.length;
    
    rte_free(data);
    return MYLIB_SUCCESS;
} 
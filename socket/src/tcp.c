#include <rte_tcp.h>
#include <rte_malloc.h>
#include <string.h>

#include "internal/tcp_impl.h"
#include "internal/logging.h"
#include "internal/common.h"

/* 全局变量 */
struct tcp_control_block *g_tcb_list = NULL;
pthread_mutex_t g_tcp_mutex = PTHREAD_MUTEX_INITIALIZER;

/* TCP选项长度 */
#define TCP_OPTION_LENGTH 10

mylib_error_t tcp_init(void) {
    pthread_mutex_lock(&g_tcp_mutex);
    g_tcb_list = NULL;
    pthread_mutex_unlock(&g_tcp_mutex);
    
    MYLIB_LOG(LOG_LEVEL_INFO, "TCP module initialized");
    return MYLIB_SUCCESS;
}

void tcp_cleanup(void) {
    pthread_mutex_lock(&g_tcp_mutex);
    
    /* 清理所有TCP控制块 */
    struct tcp_control_block *tcb = g_tcb_list;
    while (tcb) {
        struct tcp_control_block *next = tcb->next;
        tcp_destroy_tcb(tcb);
        tcb = next;
    }
    g_tcb_list = NULL;
    
    pthread_mutex_unlock(&g_tcp_mutex);
    
    MYLIB_LOG(LOG_LEVEL_INFO, "TCP module cleaned up");
}

struct tcp_control_block *tcp_create_tcb(struct mylib_socket *sock) {
    struct tcp_control_block *tcb = rte_malloc("tcp_cb", 
                                             sizeof(struct tcp_control_block), 0);
    if (!tcb) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to allocate TCP control block");
        return NULL;
    }

    /* 初始化TCB */
    memset(tcb, 0, sizeof(struct tcp_control_block));
    tcb->sock = sock;
    tcb->state = TCP_STATE_CLOSED;
    tcb->window = 65535; /* 初始窗口大小 */
    
    /* 添加到全局列表 */
    pthread_mutex_lock(&g_tcp_mutex);
    LL_ADD(tcb, g_tcb_list);
    pthread_mutex_unlock(&g_tcp_mutex);
    
    MYLIB_LOG(LOG_LEVEL_DEBUG, "Created TCP control block for socket fd=%d", 
              sock->fd);
    return tcb;
}

void tcp_destroy_tcb(struct tcp_control_block *tcb) {
    if (!tcb) return;

    pthread_mutex_lock(&g_tcp_mutex);
    
    /* 从全局列表中移除 */
    LL_REMOVE(tcb, g_tcb_list);
    
    /* 释放资源 */
    rte_free(tcb);
    
    pthread_mutex_unlock(&g_tcp_mutex);
    
    MYLIB_LOG(LOG_LEVEL_DEBUG, "Destroyed TCP control block");
}

struct tcp_control_block *tcp_find_tcb(uint32_t local_ip, uint16_t local_port) {
    pthread_mutex_lock(&g_tcp_mutex);
    
    struct tcp_control_block *tcb;
    for (tcb = g_tcb_list; tcb != NULL; tcb = tcb->next) {
        if (tcb->sock->local_ip == local_ip && 
            tcb->sock->local_port == local_port) {
            break;
        }
    }
    
    pthread_mutex_unlock(&g_tcp_mutex);
    return tcb;
}

mylib_error_t tcp_process_packet(struct rte_mbuf *mbuf) {
    struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(mbuf, 
                                                         struct rte_ipv4_hdr *, 
                                                         sizeof(struct rte_ether_hdr));
    struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ip_hdr + 1);
    
    /* 查找对应的TCB */
    pthread_mutex_lock(&g_tcp_mutex);
    struct tcp_control_block *tcb;
    for (tcb = g_tcb_list; tcb != NULL; tcb = tcb->next) {
        if (tcb->sock->local_port == tcp_hdr->dst_port) {
            break;
        }
    }
    pthread_mutex_unlock(&g_tcp_mutex);
    
    if (!tcb) {
        MYLIB_LOG(LOG_LEVEL_WARNING, "No TCP control block found for port %d",
                  ntohs(tcp_hdr->dst_port));
        return MYLIB_ERROR_INVALID;
    }

    /* 创建TCP段结构 */
    struct tcp_segment seg;
    seg.seq = ntohl(tcp_hdr->sent_seq);
    seg.ack = ntohl(tcp_hdr->recv_ack);
    seg.flags = tcp_hdr->tcp_flags;
    seg.window = ntohs(tcp_hdr->rx_win);
    
    /* 计算数据长度 */
    uint16_t tcp_len = ntohs(ip_hdr->total_length) - sizeof(struct rte_ipv4_hdr);
    uint8_t data_offset = tcp_hdr->data_off >> 4;
    seg.length = tcp_len - (data_offset * 4);
    
    if (seg.length > 0) {
        seg.data = rte_malloc("tcp_data", seg.length, 0);
        if (!seg.data) {
            MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to allocate memory for TCP data");
            return MYLIB_ERROR_NOMEM;
        }
        rte_memcpy(seg.data, (uint8_t *)tcp_hdr + (data_offset * 4), seg.length);
    } else {
        seg.data = NULL;
    }

    /* 处理TCP段 */
    tcp_input(tcb, &seg);
    
    /* 清理资源 */
    if (seg.data) {
        rte_free(seg.data);
    }
    
    return MYLIB_SUCCESS;
}

struct rte_mbuf *tcp_create_packet(struct tcp_control_block *tcb, 
                                 struct tcp_segment *seg) {
    /* 分配mbuf */
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(g_mbuf_pool);
    if (!mbuf) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to allocate mbuf for TCP packet");
        return NULL;
    }

    /* 计算总长度 */
    uint16_t total_len = sizeof(struct rte_ether_hdr) + 
                        sizeof(struct rte_ipv4_hdr) +
                        sizeof(struct rte_tcp_hdr) +
                        seg->length;
    
    /* 初始化mbuf */
    mbuf->data_len = total_len;
    mbuf->pkt_len = total_len;

    // 获取目标MAC地址
    struct arp_entry *arp_entry = arp_lookup(tcb->remote_ip);
    if (!arp_entry) {
        // 将数据包加入ARP请求队列
        mylib_error_t err = arp_queue_packet(tcb->remote_ip, mbuf);
        if (err != MYLIB_SUCCESS) {
            MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to queue TCP packet for ARP resolution");
            rte_pktmbuf_free(mbuf);
            return NULL;
        }
        
        // 发送ARP请求
        struct rte_mbuf *arp_req = arp_create_request(tcb->remote_ip);
        if (arp_req) {
            rte_ring_mp_enqueue(g_out_ring, arp_req);
        }
        
        MYLIB_LOG(LOG_LEVEL_DEBUG, "TCP packet queued for ARP resolution");
        return NULL;
    }
    
    /* 构建以太网头 */
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    rte_memcpy(eth_hdr->src_addr.addr_bytes, g_local_mac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth_hdr->dst_addr.addr_bytes, arp_entry->mac, RTE_ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);
    
    /* 构建IP头 */
    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    ip_hdr->version_ihl = 0x45;
    ip_hdr->type_of_service = 0;
    ip_hdr->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    ip_hdr->packet_id = 0;
    ip_hdr->fragment_offset = 0;
    ip_hdr->time_to_live = 64;
    ip_hdr->next_proto_id = IPPROTO_TCP;
    ip_hdr->src_addr = g_local_ip;
    ip_hdr->dst_addr = tcb->sock->local_ip;  // TODO: 需要正确设置目标IP
    ip_hdr->hdr_checksum = 0;
    ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
    
    /* 构建TCP头 */
    struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ip_hdr + 1);
    tcp_hdr->src_port = tcb->sock->local_port;
    tcp_hdr->dst_port = tcb->remote_port;  // TODO: 需要正确设置目标端口
    tcp_hdr->sent_seq = htonl(seg->seq);
    tcp_hdr->recv_ack = htonl(seg->ack);
    tcp_hdr->data_off = 0x50;  // 5 * 4 = 20 bytes
    tcp_hdr->tcp_flags = seg->flags;
    tcp_hdr->rx_win = htons(seg->window);
    tcp_hdr->cksum = 0;
    tcp_hdr->tcp_urp = 0;
    
    /* 复制数据 */
    if (seg->length > 0 && seg->data) {
        uint8_t *payload = (uint8_t *)(tcp_hdr + 1);
        rte_memcpy(payload, seg->data, seg->length);
    }
    
    /* 计算TCP校验和 */
    tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ip_hdr, tcp_hdr);
    
    return mbuf;
}

void tcp_input(struct tcp_control_block *tcb, struct tcp_segment *seg) {
    switch (tcb->state) {
        case TCP_STATE_LISTEN:
            if (seg->flags & RTE_TCP_SYN_FLAG) {
                /* 收到SYN，进入SYN_RCVD状态 */
                tcb->state = TCP_STATE_SYN_RCVD;
                tcb->rcv_nxt = seg->seq + 1;
                
                /* 发送SYN+ACK */
                struct tcp_segment reply;
                memset(&reply, 0, sizeof(reply));
                reply.seq = tcb->snd_nxt;
                reply.ack = tcb->rcv_nxt;
                reply.flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
                reply.window = tcb->window;
                
                struct rte_mbuf *mbuf = tcp_create_packet(tcb, &reply);
                if (mbuf) {
                    rte_ring_mp_enqueue(g_out_ring, mbuf);
                }
            }
            break;
            
        case TCP_STATE_SYN_RCVD:
            if (seg->flags & RTE_TCP_ACK_FLAG) {
                /* 收到ACK，进入ESTABLISHED状态 */
                tcb->state = TCP_STATE_ESTABLISHED;
                tcb->snd_una = seg->ack;
                
                /* 通知应用层连接已建立 */
                pthread_mutex_lock(&tcb->sock->mutex);
                pthread_cond_signal(&tcb->sock->cond);
                pthread_mutex_unlock(&tcb->sock->mutex);
            }
            break;
            
        case TCP_STATE_ESTABLISHED:
            /* 处理数据 */
            if (seg->length > 0) {
                /* 将数据放入接收缓冲区 */
                rte_ring_mp_enqueue(tcb->sock->recv_buf, seg->data);
                
                /* 发送ACK */
                struct tcp_segment ack;
                memset(&ack, 0, sizeof(ack));
                ack.seq = tcb->snd_nxt;
                ack.ack = tcb->rcv_nxt + seg->length;
                ack.flags = RTE_TCP_ACK_FLAG;
                ack.window = tcb->window;
                
                struct rte_mbuf *mbuf = tcp_create_packet(tcb, &ack);
                if (mbuf) {
                    rte_ring_mp_enqueue(g_out_ring, mbuf);
                }
                
                tcb->rcv_nxt += seg->length;
            }
            break;
            
        default:
            break;
    }
}

mylib_error_t tcp_output(struct tcp_control_block *tcb) {
    /* 检查发送缓冲区 */
    void *data;
    if (rte_ring_mc_dequeue(tcb->sock->send_buf, &data) < 0) {
        return MYLIB_SUCCESS;  // 没有数据要发送
    }

    /* 创建TCP段 */
    struct tcp_segment seg;
    memset(&seg, 0, sizeof(seg));
    seg.seq = tcb->snd_nxt;
    seg.ack = tcb->rcv_nxt;
    seg.flags = RTE_TCP_PSH_FLAG | RTE_TCP_ACK_FLAG;
    seg.window = tcb->window;
    seg.data = data;
    seg.length = strlen(data);  // TODO: 需要正确设置数据长度
    
    /* 创建并发送数据包 */
    struct rte_mbuf *mbuf = tcp_create_packet(tcb, &seg);
    if (!mbuf) {
        rte_free(data);
        return MYLIB_ERROR_NOMEM;
    }
    
    /* 更新序列号 */
    tcb->snd_nxt += seg.length;
    
    /* 将数据包放入发送队列 */
    if (rte_ring_mp_enqueue(g_out_ring, mbuf) < 0) {
        rte_pktmbuf_free(mbuf);
        rte_free(data);
        return MYLIB_ERROR_SEND;
    }
    
    rte_free(data);
    return MYLIB_SUCCESS;
}

struct tcp_control_block *tcp_get_accept_tcb(uint16_t listen_port) {
    pthread_mutex_lock(&g_tcp_mutex);
    
    struct tcp_control_block *tcb;
    for (tcb = g_tcb_list; tcb != NULL; tcb = tcb->next) {
        if (tcb->sock->local_port == listen_port && 
            tcb->state == TCP_STATE_ESTABLISHED) {
            /* 找到一个已建立连接的TCB */
            LL_REMOVE(tcb, g_tcb_list);  /* 从全局列表中移除 */
            break;
        }
    }
    
    pthread_mutex_unlock(&g_tcp_mutex);
    return tcb;
} 

mylib_error_t tcp_handle_arp_resolution(uint32_t ip, const uint8_t *mac) {
    MYLIB_LOG(LOG_LEVEL_DEBUG, "TCP handling ARP resolution for IP %u.%u.%u.%u", 
              (ip & 0xFF),
              (ip >> 8) & 0xFF,
              (ip >> 16) & 0xFF,
              (ip >> 24) & 0xFF);
    return MYLIB_SUCCESS;
}
#include "tcp.h"
#include "arp.h"
#include <rte_tcp.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

/**
 * @brief 获取TCP流管理实例
 */
struct ng_tcp_table *tcp_table_instance(void) {
    if (tcp_table == NULL) {
        tcp_table = rte_malloc("ng_tcp_table", sizeof(struct ng_tcp_table), 0);
        if (tcp_table == NULL) {
            rte_exit(EXIT_FAILURE, "TCP table allocation failed\n");
        }
        memset(tcp_table, 0, sizeof(struct ng_tcp_table));
    }
    return tcp_table;
}

/**
 * @brief 根据IP和端口查找TCP流
 */
struct ng_tcp_stream *tcp_find_stream(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {
    struct ng_tcp_table *table = tcp_table_instance();
    struct ng_tcp_stream *stream;
    for (stream = table->tcb_set; stream != NULL; stream = stream->next) {
        if (stream->sip == sip && stream->dip == dip && 
            stream->sport == sport && stream->dport == dport) {
            return stream;
        }
    }
    return NULL;
}

/**
 * @brief TCP状态机处理
 */
int tcp_process(struct rte_mbuf *tcpmbuf) {
    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(tcpmbuf, struct rte_ipv4_hdr *,
                                                         sizeof(struct rte_ether_hdr));
    struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(iphdr + 1);

    uint16_t tcpcksum = tcphdr->cksum;
    tcphdr->cksum = 0;
    uint16_t cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);
    if (cksum != tcpcksum) {
        printf("TCP checksum mismatch: calculated %x, received %x\n", cksum, tcpcksum);
        return -1;
    }

    struct ng_tcp_stream *stream = tcp_find_stream(iphdr->src_addr, iphdr->dst_addr,
                                                   tcphdr->src_port, tcphdr->dst_port);
    if (!stream) {
        return -2;
    }

    switch (stream->status) {
        case NG_TCP_STATUS_LISTEN:
            if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {
                stream->status = NG_TCP_STATUS_SYN_RCVD;
                stream->rcv_nxt = ntohl(tcphdr->sent_seq) + 1;
                stream->snd_nxt = 0; // Example sequence
            }
            break;

        case NG_TCP_STATUS_ESTABLISHED:
            if (tcphdr->tcp_flags & RTE_TCP_PSH_FLAG) {
                uint8_t hdrlen = tcphdr->data_off >> 4;
                int payloadlen = ntohs(iphdr->total_length) - hdrlen * 4 - sizeof(struct rte_tcp_hdr);
                if (payloadlen > 0) {
                    uint8_t *payload = (uint8_t *)tcphdr + hdrlen * 4;
                    rte_ring_mp_enqueue(stream->rcvbuf, payload);
                }
                stream->rcv_nxt = ntohl(tcphdr->sent_seq) + payloadlen;
            }
            break;

        case NG_TCP_STATUS_CLOSE_WAIT:
            if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) {
                stream->status = NG_TCP_STATUS_LAST_ACK;
            }
            break;

        case NG_TCP_STATUS_LAST_ACK:
            if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {
                stream->status = NG_TCP_STATUS_CLOSED;
            }
            break;

        default:
            break;
    }
    return 0;
}

/**
 * @brief 发送TCP包
 */
struct rte_mbuf* tcp_send_packet(struct rte_mempool *mbuf_pool, struct ng_tcp_stream *stream, 
                                 uint8_t *payload, uint16_t length, uint8_t flags) {
    const unsigned total_len = length + sizeof(struct rte_ether_hdr) +
                               sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr);

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "TCP packet mbuf allocation failed\n");
    }
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t *);
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pktdata;
    rte_memcpy(eth->src_addr.addr_bytes, stream->localmac, RTE_ETHER_ADDR_LEN);
    uint8_t *dstmac = arp_get_dst_macaddr(stream->dip);
    rte_memcpy(eth->dst_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(pktdata + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    ip->src_addr = stream->dip;
    ip->dst_addr = stream->sip;
    ip->next_proto_id = IPPROTO_TCP;

    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
    tcp->src_port = stream->sport;
    tcp->dst_port = stream->dport;
    tcp->sent_seq = htonl(stream->snd_nxt);
    tcp->recv_ack = htonl(stream->rcv_nxt);
    tcp->tcp_flags = flags;

    if (payload && length > 0) {
        rte_memcpy((uint8_t *)(tcp + 1), payload, length);
    }

    return mbuf;
}

/**
 * @brief TCP流的输出处理
 */
int tcp_out(struct rte_mempool *mbuf_pool) {
    struct ng_tcp_table *table = tcp_table_instance();
    struct ng_tcp_stream *stream;
    for (stream = table->tcb_set; stream != NULL; stream = stream->next) {
        struct rte_mbuf *tcpmbuf = tcp_send_packet(mbuf_pool, stream, NULL, 0, RTE_TCP_ACK_FLAG);
        if (tcpmbuf) {
            rte_pktmbuf_free(tcpmbuf);
        }
    }
    return 0;
}

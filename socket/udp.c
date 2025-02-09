#include "udp.h"
#include "arp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

/**
 * @brief 获取UDP接收和发送缓冲区
 */
struct localhost* udp_get_host_by_ip_port(uint32_t dip, uint16_t port) {
    struct localhost *host;
    for (host = lhost; host != NULL; host = host->next) {
        if (dip == host->localip && port == host->localport) {
            return host;
        }
    }
    return NULL;
}

/**
 * @brief 处理接收到的UDP数据
 */
int udp_process(struct rte_mbuf *udpmbuf) {
    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(udpmbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

    struct in_addr addr;
    addr.s_addr = iphdr->src_addr;
    printf("udp_process ---> src: %s:%d \n", inet_ntoa(addr), ntohs(udphdr->src_port));

    struct localhost *host = udp_get_host_by_ip_port(iphdr->dst_addr, udphdr->dst_port);
    if (host == NULL) {
        rte_pktmbuf_free(udpmbuf);
        return -3;
    }

    struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
    if (ol == NULL) {
        rte_pktmbuf_free(udpmbuf);
        return -1;
    }

    ol->dip = iphdr->dst_addr;
    ol->sip = iphdr->src_addr;
    ol->sport = udphdr->src_port;
    ol->dport = udphdr->dst_port;
    ol->protocol = IPPROTO_UDP;
    ol->length = ntohs(udphdr->dgram_len);

    ol->data = rte_malloc("unsigned char*", ol->length - sizeof(struct rte_udp_hdr), 0);
    if (ol->data == NULL) {
        rte_pktmbuf_free(udpmbuf);
        rte_free(ol);
        return -2;
    }

    rte_memcpy(ol->data, (unsigned char *)(udphdr + 1), ol->length - sizeof(struct rte_udp_hdr));
    rte_ring_mp_enqueue(host->rcvbuf, ol);

    pthread_mutex_lock(&host->mutex);
    pthread_cond_signal(&host->cond);
    pthread_mutex_unlock(&host->mutex);

    rte_pktmbuf_free(udpmbuf);
    return 0;
}

/**
 * @brief 从UDP数据包中提取数据并准备发送
 */
int udp_out(struct rte_mempool *mbuf_pool) {
    struct localhost *host;
    for (host = lhost; host != NULL; host = host->next) {
        struct offload *ol;
        int nb_snd = rte_ring_mc_dequeue(host->sndbuf, (void **)&ol);
        if (nb_snd < 0) continue;

        struct in_addr addr;
        addr.s_addr = ol->dip;
        printf("udp_out ---> src: %s:%d \n", inet_ntoa(addr), ntohs(ol->dport));

        uint8_t *dstmac = arp_get_dst_macaddr(ol->dip);
        if (dstmac == NULL) {
            struct rte_mbuf *arpbuf = arp_send_request(mbuf_pool, ol->dip);
            struct inout_ring *ring = ringInstance();
            rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);
            rte_ring_mp_enqueue(host->sndbuf, ol);
        } else {
            struct rte_mbuf *udpbuf = udp_send_packet(mbuf_pool, ol->sip, ol->dip, ol->sport, ol->dport,
                                                      host->localmac, dstmac, ol->data, ol->length);

            struct inout_ring *ring = ringInstance();
            rte_ring_mp_enqueue_burst(ring->out, (void **)&udpbuf, 1, NULL);
        }
    }
    return 0;
}

/**
 * @brief 发送UDP包
 */
struct rte_mbuf* udp_send_packet(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip, 
                                 uint16_t sport, uint16_t dport, uint8_t *srcmac, 
                                 uint8_t *dstmac, unsigned char *data, uint16_t total_len) {
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "UDP mbuf allocation failed\n");
    }
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;
    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

    // 构造以太网头
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pktdata;
    rte_memcpy(eth->src_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->dst_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    // 构造IP头
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(pktdata + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64; // ttl = 64
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = sip;
    ip->dst_addr = dip;
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    // 构造UDP头
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(pktdata + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udp->src_port = sport;
    udp->dst_port = dport;
    uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
    udp->dgram_len = htons(udplen);
    rte_memcpy((uint8_t*)(udp + 1), data, udplen);
    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

    return mbuf;
}

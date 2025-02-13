#ifndef __NG_UDP_H__
#define __NG_UDP_H__

#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_malloc.h>
#include <rte_ip4.h>
#include <rte_udp.h>

#define UDP_APP_RECV_BUFFER_SIZE 128

struct localhost {
    int fd;
    uint32_t localip;
    uint8_t localmac[RTE_ETHER_ADDR_LEN];
    uint16_t localport;
    uint8_t protocol;
    struct rte_ring *sndbuf;
    struct rte_ring *rcvbuf;
    struct localhost *prev;
    struct localhost *next;
    pthread_cond_t cond;
    pthread_mutex_t mutex;
    int non_blocking;
};
static struct localhost *lhost = NULL;
/**
 * @brief 获取UDP接收和发送缓冲区
 */
struct localhost* udp_get_host_by_ip_port(uint32_t dip, uint16_t port);

/**
 * @brief 处理接收到的UDP数据
 */
int udp_process(struct rte_mbuf *udpmbuf);

/**
 * @brief 从UDP数据包中提取数据并准备发送
 */
int udp_out(struct rte_mempool *mbuf_pool);

/**
 * @brief 发送UDP包
 */
struct rte_mbuf* udp_send_packet(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip, 
                                 uint16_t sport, uint16_t dport, uint8_t *srcmac, 
                                 uint8_t *dstmac, unsigned char *data, uint16_t total_len);

#endif

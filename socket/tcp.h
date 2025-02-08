#ifndef __NG_TCP_H__
#define __NG_TCP_H__

#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_malloc.h>
#include <rte_tcp.h>
#include <pthread.h>

#define TCP_INITIAL_WINDOW 14600
#define TCP_OPTION_LENGTH 10

typedef enum _NG_TCP_STATUS {
    NG_TCP_STATUS_CLOSED = 0,
    NG_TCP_STATUS_LISTEN,
    NG_TCP_STATUS_SYN_RCVD,
    NG_TCP_STATUS_SYN_SENT,
    NG_TCP_STATUS_ESTABLISHED,
    NG_TCP_STATUS_FIN_WAIT_1,
    NG_TCP_STATUS_FIN_WAIT_2,
    NG_TCP_STATUS_CLOSING,
    NG_TCP_STATUS_TIME_WAIT,
    NG_TCP_STATUS_CLOSE_WAIT,
    NG_TCP_STATUS_LAST_ACK
} NG_TCP_STATUS;

struct ng_tcp_stream {
    int fd;
    uint32_t sip; // Source IP
    uint32_t dip; // Destination IP
    uint16_t sport; // Source port
    uint16_t dport; // Destination port
    uint8_t localmac[RTE_ETHER_ADDR_LEN];
    uint8_t protocol;
    uint32_t snd_nxt; // Next sequence number
    uint32_t rcv_nxt; // Next expected sequence number
    NG_TCP_STATUS status;
    struct rte_ring *sndbuf; // Send buffer
    struct rte_ring *rcvbuf; // Receive buffer
    struct ng_tcp_stream *prev;
    struct ng_tcp_stream *next;
    pthread_cond_t cond;
    pthread_mutex_t mutex;
    int non_blocking;
};

struct ng_tcp_table {
    int count;
    struct ng_tcp_stream *tcb_set;
};

/**
 * @brief 获取TCP流管理实例
 */
struct ng_tcp_table *tcp_table_instance(void);

/**
 * @brief 根据IP和端口查找TCP流
 */
struct ng_tcp_stream *tcp_find_stream(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport);

/**
 * @brief TCP状态机处理
 */
int tcp_process(struct rte_mbuf *tcpmbuf);

/**
 * @brief 发送TCP包
 */
struct rte_mbuf* tcp_send_packet(struct rte_mempool *mbuf_pool, struct ng_tcp_stream *stream, 
                                 uint8_t *payload, uint16_t length, uint8_t flags);

/**
 * @brief TCP流的输出处理
 */
int tcp_out(struct rte_mempool *mbuf_pool);

#endif

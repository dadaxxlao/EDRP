#ifndef MYLIB_INTERNAL_TCP_IMPL_H
#define MYLIB_INTERNAL_TCP_IMPL_H

#include <rte_tcp.h>
#include "common.h"
#include "arp_impl.h" /*作为填充UDP包头时，获取相应的MAC*/

/* TCP状态定义 */
typedef enum {
    TCP_STATE_CLOSED = 0,
    TCP_STATE_LISTEN,
    TCP_STATE_SYN_RCVD,
    TCP_STATE_SYN_SENT,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSING,
    TCP_STATE_TIME_WAIT,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_LAST_ACK
} tcp_state_t;

/* TCP连接控制块 */
struct tcp_control_block {
    struct mylib_socket *sock;     /* 关联的socket */
    tcp_state_t state;            /* TCP状态 */
    
    /* 地址信息 */
    uint32_t remote_ip;          /* 远程IP */
    uint16_t remote_port;        /* 远程端口 */
    
    /* 序列号管理 */
    uint32_t snd_una;    /* 最早未确认的发送序号 */
    uint32_t snd_nxt;    /* 下一个发送序号 */
    uint32_t rcv_nxt;    /* 期望接收的下一个序号 */
    uint16_t window;     /* 接收窗口大小 */
    
    /* 定时器 */
    uint32_t rto;        /* 重传超时时间 */
    uint32_t srtt;       /* 平滑往返时间 */
    
    /* 链表指针 */
    struct tcp_control_block *prev;
    struct tcp_control_block *next;
};

/* TCP分片结构 */
struct tcp_segment {
    uint32_t seq;        /* 序列号 */
    uint32_t ack;        /* 确认号 */
    uint16_t flags;      /* TCP标志 */
    uint16_t window;     /* 窗口大小 */
    uint8_t *data;       /* 数据指针 */
    uint16_t length;     /* 数据长度 */
};

/* 函数声明 */
mylib_error_t tcp_init(void);
void tcp_cleanup(void);
mylib_error_t tcp_process_packet(struct rte_mbuf *mbuf);
struct rte_mbuf *tcp_create_packet(struct tcp_control_block *tcb, 
                                 struct tcp_segment *seg);
mylib_error_t tcp_output(struct tcp_control_block *tcb);
void tcp_input(struct tcp_control_block *tcb, struct tcp_segment *seg);
struct tcp_control_block *tcp_create_tcb(struct mylib_socket *sock);
void tcp_destroy_tcb(struct tcp_control_block *tcb);


/* 查找和接受连接相关的函数 */
struct tcp_control_block *tcp_find_tcb(uint32_t local_ip, uint16_t local_port);
struct tcp_control_block *tcp_get_accept_tcb(uint16_t listen_port);

#endif /* MYLIB_INTERNAL_TCP_IMPL_H */  
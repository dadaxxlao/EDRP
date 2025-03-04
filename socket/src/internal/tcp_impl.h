/**
 * @file tcp_impl.h
 * @brief TCP协议实现的内部头文件
 *
 * 本文件定义了EDRP网络协议栈中TCP协议实现所需的数据结构、枚举类型
 * 和函数接口。基于DPDK实现高性能网络通信，包含TCP状态机、计时器管理和
 * 连接控制等功能。
 *
 * @author 冯昊阳
 * @date 2025年3月4日
 */

#ifndef MYLIB_INTERNAL_TCP_IMPL_H
#define MYLIB_INTERNAL_TCP_IMPL_H

#include <rte_tcp.h>
#include "common.h"
#include "arp_impl.h" /* 用于获取MAC地址，填充TCP包头 */

/**
 * @defgroup TCP_STATE TCP状态定义
 * @{
 */

/**
 * @brief TCP连接状态枚举
 *
 * 按照RFC793定义的TCP状态机状态
 */
typedef enum {
    TCP_STATE_CLOSED = 0,    /**< 关闭状态 */
    TCP_STATE_LISTEN,        /**< 监听状态 */
    TCP_STATE_SYN_RCVD,      /**< 已收到SYN请求 */
    TCP_STATE_SYN_SENT,      /**< 已发送SYN请求 */
    TCP_STATE_ESTABLISHED,   /**< 连接已建立 */
    TCP_STATE_FIN_WAIT_1,    /**< 等待对方响应关闭请求，或者FIN的ACK */
    TCP_STATE_FIN_WAIT_2,    /**< 关闭连接的一半，等待另一半关闭 */
    TCP_STATE_CLOSING,       /**< 两端同时关闭，等待ACK */
    TCP_STATE_TIME_WAIT,     /**< 完成双向关闭，等待所有分段消失 */
    TCP_STATE_CLOSE_WAIT,    /**< 等待上层应用关闭 */
    TCP_STATE_LAST_ACK       /**< 等待最后的ACK */
} tcp_state_t;

/** @} */ /* TCP_STATE组结束 */

/**
 * @defgroup TCP_TIMER TCP计时器定义
 * @{
 */

/**
 * @brief TCP计时器类型枚举
 *
 * 定义TCP协议中各种不同用途的计时器类型
 */
typedef enum {
    TCP_TIMER_RETRANSMIT = 0,  /**< 重传计时器 - 用于未确认数据的重传 */
    TCP_TIMER_PERSIST,         /**< 持久计时器 - 用于零窗口探测 */
    TCP_TIMER_KEEPALIVE,       /**< 保活计时器 - 检测空闲连接 */
    TCP_TIMER_TIME_WAIT,       /**< TIME_WAIT计时器 - 2MSL等待 */
    TCP_TIMER_MAX              /**< 计时器类型数量 */
} tcp_timer_type_t;

/**
 * @brief TCP计时器控制块
 *
 * 每个TCP计时器的管理结构
 */
struct tcp_timer {
    struct rte_timer timer;            /**< DPDK计时器 */
    struct tcp_control_block *tcb;     /**< 关联的TCP控制块 */
    tcp_timer_type_t type;             /**< 计时器类型 */
};

/** @} */ /* TCP_TIMER组结束 */

/**
 * @defgroup TCP_DATA TCP数据结构定义
 * @{
 */

/**
 * @brief TCP控制块结构
 *
 * 用于管理单个TCP连接的所有状态和数据
 */
struct tcp_control_block {
    struct mylib_socket *sock;     /**< 关联的socket */
    tcp_state_t state;             /**< TCP连接状态 */
    
    /* 地址信息 */
    uint32_t remote_ip;            /**< 远程IP地址 */
    uint16_t remote_port;          /**< 远程端口 */
    
    /* 序列号管理 */
    uint32_t snd_una;              /**< 最早未确认的发送序号 */
    uint32_t snd_nxt;              /**< 下一个发送序号 */
    uint32_t rcv_nxt;              /**< 期望接收的下一个序号 */
    uint16_t window;               /**< 接收窗口大小 */
    
    /* 定时器相关数据 */
    uint64_t rto;                  /**< 当前重传超时值(ns) */
    uint64_t srtt;                 /**< 平滑往返时间(ns) */
    uint64_t rttvar;               /**< RTT变化量(ns) */
    struct tcp_timer timers[TCP_TIMER_MAX];  /**< 各类计时器 */
    
    /* 链表指针 */
    struct tcp_control_block *prev;  /**< 前一个TCB */
    struct tcp_control_block *next;  /**< 后一个TCB */
};

/**
 * @brief TCP段结构
 *
 * 表示TCP协议层中的一个数据段，用于传递给上层或从网络接收
 */
struct tcp_segment {
    uint32_t seq;        /**< 序列号 */
    uint32_t ack;        /**< 确认号 */
    uint16_t flags;      /**< TCP标志 */
    uint16_t window;     /**< 窗口大小 */
    uint8_t *data;       /**< 数据指针 */
    uint16_t length;     /**< 数据长度 */
    uint32_t src_ip;     /**< 源IP地址 */
    uint16_t src_port;   /**< 源端口 */
};

/** @} */ /* TCP_DATA组结束 */

/*---------------------------------------------------------------------------*/
/* 函数声明部分 */

/**
 * @defgroup TCP_INIT TCP初始化与清理
 * @{
 */

/**
 * @brief 初始化TCP模块
 *
 * 设置全局变量和计时器系统
 *
 * @return MYLIB_SUCCESS成功，其他错误码表示失败
 */
mylib_error_t tcp_init(void);

/**
 * @brief 清理TCP模块资源
 *
 * 释放所有分配的资源，停止计时器
 */
void tcp_cleanup(void);

/** @} */ /* TCP_INIT组结束 */

/**
 * @defgroup TCP_CONNECTION TCP连接管理
 * @{
 */

/**
 * @brief 创建新的TCP控制块
 *
 * @param sock 关联的socket
 * @return 创建的TCP控制块指针，失败返回NULL
 */
struct tcp_control_block *tcp_create_tcb(struct mylib_socket *sock);

/**
 * @brief 销毁TCP控制块并释放相关资源
 *
 * @param tcb 要销毁的TCP控制块
 */
void tcp_destroy_tcb(struct tcp_control_block *tcb);

/**
 * @brief 查找指定IP和端口对应的TCP控制块
 *
 * @param local_ip 本地IP地址
 * @param local_port 本地端口
 * @return 找到的TCP控制块指针，未找到返回NULL
 */
struct tcp_control_block *tcp_find_tcb(uint32_t local_ip, uint16_t local_port);

/**
 * @brief 获取等待accept的TCP控制块
 *
 * @param listen_port 监听端口
 * @return 可用于accept的TCP控制块指针，无可用连接时返回NULL
 */
struct tcp_control_block *tcp_get_accept_tcb(uint16_t listen_port);

/**
 * @brief 主动发起TCP连接
 *
 * @param tcb TCP控制块
 * @param dst_ip 目标IP地址
 * @param dst_port 目标端口
 * @return MYLIB_SUCCESS成功，其他错误码表示失败
 */
mylib_error_t tcp_connect(struct tcp_control_block *tcb, uint32_t dst_ip, uint16_t dst_port);

/**
 * @brief 主动关闭TCP连接
 *
 * @param tcb TCP控制块
 * @return MYLIB_SUCCESS成功，其他错误码表示失败
 */
mylib_error_t tcp_close(struct tcp_control_block *tcb);

/** @} */ /* TCP_CONNECTION组结束 */

/**
 * @defgroup TCP_DATA_PROCESSING TCP数据处理
 * @{
 */

/**
 * @brief 处理接收到的TCP数据包
 *
 * 从MBUF中提取TCP数据，根据TCP控制块状态进行处理
 *
 * @param mbuf 包含TCP数据的MBUF
 * @return MYLIB_SUCCESS成功，其他错误码表示失败
 */
mylib_error_t tcp_process_packet(struct rte_mbuf *mbuf);

/**
 * @brief 创建TCP数据包
 *
 * 根据TCP控制块和TCP段信息创建数据包
 *
 * @param tcb TCP控制块
 * @param seg TCP段信息
 * @return 创建的MBUF指针，失败返回NULL
 */
struct rte_mbuf *tcp_create_packet(struct tcp_control_block *tcb, 
                                  struct tcp_segment *seg);

/**
 * @brief TCP输出函数
 *
 * 从发送缓冲区获取数据，创建TCP段并发送
 *
 * @param tcb TCP控制块
 * @return MYLIB_SUCCESS成功，其他错误码表示失败
 */
mylib_error_t tcp_output(struct tcp_control_block *tcb);

/**
 * @brief TCP输入函数
 *
 * 处理接收到的TCP段，实现TCP状态机
 *
 * @param tcb TCP控制块
 * @param seg 接收到的TCP段
 */
void tcp_input(struct tcp_control_block *tcb, struct tcp_segment *seg);

/**
 * @brief 处理ARP解析结果
 *
 * 当ARP解析完成后，处理待发送的TCP数据包
 *
 * @param ip 已解析的IP地址
 * @param mac 对应的MAC地址
 * @return MYLIB_SUCCESS成功，其他错误码表示失败
 */
mylib_error_t tcp_handle_arp_resolution(uint32_t ip, const uint8_t *mac);

/** @} */ /* TCP_DATA_PROCESSING组结束 */

/**
 * @defgroup TCP_TIMER_API TCP计时器API
 * @{
 */

/**
 * @brief 初始化TCP计时器系统
 *
 * @return MYLIB_SUCCESS成功，其他错误码表示失败
 */
mylib_error_t tcp_timer_init(void);

/**
 * @brief 清理TCP计时器系统资源
 */
void tcp_timer_cleanup(void);

/**
 * @brief 启动指定类型的TCP计时器
 *
 * @param tcb TCP控制块
 * @param type 计时器类型
 * @param timeout_ns 超时时间(纳秒)
 * @return MYLIB_SUCCESS成功，其他错误码表示失败
 */
mylib_error_t tcp_timer_start(struct tcp_control_block *tcb, tcp_timer_type_t type, uint64_t timeout_ns);

/**
 * @brief 停止指定类型的TCP计时器
 *
 * @param tcb TCP控制块
 * @param type 计时器类型
 */
void tcp_timer_stop(struct tcp_control_block *tcb, tcp_timer_type_t type);

/**
 * @brief 重置指定类型的TCP计时器
 *
 * @param tcb TCP控制块
 * @param type 计时器类型
 * @param timeout_ns 超时时间(纳秒)
 */
void tcp_timer_reset(struct tcp_control_block *tcb, tcp_timer_type_t type, uint64_t timeout_ns);

/**
 * @brief 更新RTT和RTO
 *
 * 根据测量的RTT更新SRTT、RTTVAR和RTO值
 * 
 * @param tcb TCP控制块
 * @param measured_rtt_ns 测量的RTT值(纳秒)
 */
void tcp_update_rtt(struct tcp_control_block *tcb, uint64_t measured_rtt_ns);

/** @} */ /* TCP_TIMER_API组结束 */

#endif /* MYLIB_INTERNAL_TCP_IMPL_H */  
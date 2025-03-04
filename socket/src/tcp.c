/**
 * @file tcp.c
 * @brief TCP协议实现
 *
 * 实现TCP协议的核心功能，包括连接管理、状态机、数据收发和计时器系统。
 * 基于DPDK实现高性能网络通信。
 *
 * @author 冯昊阳
 * @date 2025年3月4日
 */

#include <rte_tcp.h>
#include <rte_malloc.h>
#include <string.h>
#include <time.h>

#include "internal/tcp_impl.h"
#include "internal/logging.h"
#include "internal/common.h"

/*---------------------------------------------------------------------------*/
/* 全局变量定义 */

/** TCP控制块链表头 */
struct tcp_control_block *g_tcb_list = NULL;

/** TCP互斥锁 */
pthread_mutex_t g_tcp_mutex = PTHREAD_MUTEX_INITIALIZER;

/** TCP选项长度 */
#define TCP_OPTION_LENGTH 10

/** 全局计时器管理器 */
static struct rte_timer tcp_timer_manager;

/** 计时器初始化标志 */
static uint8_t tcp_timer_initialized = 0;

/** 计时器回调函数数组 */
static rte_timer_cb_t tcp_timer_callbacks[TCP_TIMER_MAX];

/*---------------------------------------------------------------------------*/
/* 内部函数前向声明 */

static void tcp_retransmit_timer_cb(struct rte_timer *timer, void *arg);
static void tcp_persist_timer_cb(struct rte_timer *timer, void *arg);
static void tcp_keepalive_timer_cb(struct rte_timer *timer, void *arg);
static void tcp_time_wait_timer_cb(struct rte_timer *timer, void *arg);
static void tcp_timer_manage_cb(struct rte_timer *timer, void *arg);

/*===========================================================================*/
/*                        计时器系统实现                                      */
/*===========================================================================*/

/**
 * @brief TCP计时器管理函数
 *
 * 定期执行，管理所有TCP计时器，检查过期连接等
 *
 * @param timer 触发的计时器
 * @param arg 用户参数
 */
static void tcp_timer_manage_cb(__rte_unused struct rte_timer *timer, void *arg) {
    /* 可以添加全局计时器管理逻辑 */
    MYLIB_LOG(LOG_LEVEL_DEBUG, "TCP计时器管理回调执行");
}

/**
 * @brief TCP重传计时器回调
 *
 * 当重传计时器超时时调用，重新发送未确认的数据
 *
 * @param timer 触发的计时器
 * @param arg 用户参数
 */
static void tcp_retransmit_timer_cb(struct rte_timer *timer, void *arg) {
    struct tcp_timer *tcp_timer = container_of(timer, struct tcp_timer, timer);
    struct tcp_control_block *tcb = tcp_timer->tcb;
    
    MYLIB_LOG(LOG_LEVEL_DEBUG, "TCP重传计时器触发，连接状态=%d", tcb->state);
    
    pthread_mutex_lock(&g_tcp_mutex);
    
    /* 只有在合适的状态下才进行重传 */
    if (tcb->state != TCP_STATE_CLOSED && 
        tcb->state != TCP_STATE_LISTEN && 
        tcb->state != TCP_STATE_TIME_WAIT) {
        
        /* 重传逻辑 */
        MYLIB_LOG(LOG_LEVEL_INFO, "执行TCP数据重传");
        
        struct tcp_segment seg;
        memset(&seg, 0, sizeof(seg));
        seg.seq = tcb->snd_una;
        seg.ack = tcb->rcv_nxt;
        seg.flags = RTE_TCP_ACK_FLAG;
        seg.window = tcb->window;
        
        /* 未确认数据的重传逻辑会在这里添加 */
        
        struct rte_mbuf *mbuf = tcp_create_packet(tcb, &seg);
        if (mbuf) {
            rte_ring_mp_enqueue(g_out_ring, mbuf);
        }
        
        /* 更新RTO（指数退避） */
        tcb->rto = tcb->rto * 2;
        if (tcb->rto > 60000000000ULL) { /* 最大60秒 */
            tcb->rto = 60000000000ULL;
        }
        
        /* 重新启动重传计时器 */
        tcp_timer_reset(tcb, TCP_TIMER_RETRANSMIT, tcb->rto);
    }
    
    pthread_mutex_unlock(&g_tcp_mutex);
}

/**
 * @brief TCP持久计时器回调
 *
 * 处理零窗口情况，发送窗口探测段
 *
 * @param timer 触发的计时器
 * @param arg 用户参数
 */
static void tcp_persist_timer_cb(struct rte_timer *timer, void *arg) {
    struct tcp_timer *tcp_timer = container_of(timer, struct tcp_timer, timer);
    struct tcp_control_block *tcb = tcp_timer->tcb;
    
    MYLIB_LOG(LOG_LEVEL_DEBUG, "TCP持久计时器触发，连接状态=%d", tcb->state);
    
    pthread_mutex_lock(&g_tcp_mutex);
    
    /* 只有在ESTABLISHED状态且对方窗口为0时才进行窗口探测 */
    if (tcb->state == TCP_STATE_ESTABLISHED && tcb->window == 0) {
        /* 发送窗口探测段 */
        struct tcp_segment seg;
        memset(&seg, 0, sizeof(seg));
        seg.seq = tcb->snd_una;
        seg.ack = tcb->rcv_nxt;
        seg.flags = RTE_TCP_ACK_FLAG;
        seg.window = 0;
        
        /* 只携带1字节数据作为探测 */
        seg.data = rte_malloc("tcp_probe", 1, 0);
        if (seg.data) {
            seg.data[0] = 0;
            seg.length = 1;
            
            struct rte_mbuf *mbuf = tcp_create_packet(tcb, &seg);
            if (mbuf) {
                rte_ring_mp_enqueue(g_out_ring, mbuf);
            }
            
            rte_free(seg.data);
        }
        
        /* 重新启动持久计时器，使用退避策略 */
        tcp_timer_reset(tcb, TCP_TIMER_PERSIST, tcb->rto);
    }
    
    pthread_mutex_unlock(&g_tcp_mutex);
}

/**
 * @brief TCP保活计时器回调
 *
 * 处理连接保活，发送探测段以确保连接活跃
 *
 * @param timer 触发的计时器
 * @param arg 用户参数
 */
static void tcp_keepalive_timer_cb(struct rte_timer *timer, void *arg) {
    struct tcp_timer *tcp_timer = container_of(timer, struct tcp_timer, timer);
    struct tcp_control_block *tcb = tcp_timer->tcb;
    
    MYLIB_LOG(LOG_LEVEL_DEBUG, "TCP保活计时器触发，连接状态=%d", tcb->state);
    
    pthread_mutex_lock(&g_tcp_mutex);
    
    /* 只有在ESTABLISHED状态且长时间空闲时才发送保活探测 */
    if (tcb->state == TCP_STATE_ESTABLISHED) {
        /* 发送保活探测段 */
        struct tcp_segment seg;
        memset(&seg, 0, sizeof(seg));
        seg.seq = tcb->snd_una - 1;  /* 使用无效序列号触发对方ACK */
        seg.ack = tcb->rcv_nxt;
        seg.flags = RTE_TCP_ACK_FLAG;
        seg.window = tcb->window;
        
        struct rte_mbuf *mbuf = tcp_create_packet(tcb, &seg);
        if (mbuf) {
            rte_ring_mp_enqueue(g_out_ring, mbuf);
        }
        
        /* 重新启动保活计时器 */
        tcp_timer_reset(tcb, TCP_TIMER_KEEPALIVE, 75000000000ULL); /* 75秒 */
    }
    
    pthread_mutex_unlock(&g_tcp_mutex);
}

/**
 * @brief TIME_WAIT计时器回调
 *
 * 处理TIME_WAIT状态超时，关闭连接并释放资源
 *
 * @param timer 触发的计时器
 * @param arg 用户参数
 */
static void tcp_time_wait_timer_cb(struct rte_timer *timer, void *arg) {
    struct tcp_timer *tcp_timer = container_of(timer, struct tcp_timer, timer);
    struct tcp_control_block *tcb = tcp_timer->tcb;
    
    MYLIB_LOG(LOG_LEVEL_DEBUG, "TCP TIME_WAIT计时器触发，连接状态=%d", tcb->state);
    
    pthread_mutex_lock(&g_tcp_mutex);
    
    /* 只处理TIME_WAIT状态 */
    if (tcb->state == TCP_STATE_TIME_WAIT) {
        /* 2MSL超时，关闭连接 */
        MYLIB_LOG(LOG_LEVEL_INFO, "TIME_WAIT超时，关闭TCP连接");
        tcb->state = TCP_STATE_CLOSED;
        
        /* 从TCB链表中移除 */
        if (tcb->prev) {
            tcb->prev->next = tcb->next;
        } else {
            g_tcb_list = tcb->next;
        }
        
        if (tcb->next) {
            tcb->next->prev = tcb->prev;
        }
        
        /* 通知应用层连接已关闭 */
        pthread_mutex_lock(&tcb->sock->mutex);
        pthread_cond_signal(&tcb->sock->cond);
        pthread_mutex_unlock(&tcb->sock->mutex);
        
        /* 释放TCB资源 */
        tcp_destroy_tcb(tcb);
    }
    
    pthread_mutex_unlock(&g_tcp_mutex);
}

/**
 * @brief 初始化TCP计时器系统
 *
 * 设置计时器回调函数并启动计时器管理器
 *
 * @return MYLIB_SUCCESS成功，其他错误码表示失败
 */
mylib_error_t tcp_timer_init(void) {
    if (tcp_timer_initialized) {
        return MYLIB_SUCCESS;  /* 已经初始化过 */
    }
    
    MYLIB_LOG(LOG_LEVEL_INFO, "初始化TCP计时器系统");
    
    /* 设置计时器回调函数 */
    tcp_timer_callbacks[TCP_TIMER_RETRANSMIT] = tcp_retransmit_timer_cb;
    tcp_timer_callbacks[TCP_TIMER_PERSIST] = tcp_persist_timer_cb;
    tcp_timer_callbacks[TCP_TIMER_KEEPALIVE] = tcp_keepalive_timer_cb;
    tcp_timer_callbacks[TCP_TIMER_TIME_WAIT] = tcp_time_wait_timer_cb;
    
    /* 初始化DPDK计时器子系统 */
    int ret = rte_timer_subsystem_init();
    if (ret < 0) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "DPDK计时器子系统初始化失败");
        return MYLIB_ERROR_INIT;
    }
    
    /* 初始化TCP计时器管理器 */
    rte_timer_init(&tcp_timer_manager);
    
    /* 启动TCP计时器管理循环 */
    uint64_t hz = rte_get_timer_hz();  /* 获取DPDK时钟频率 */
    ret = rte_timer_reset(&tcp_timer_manager, 
                         hz / 10,  /* 每100ms执行一次 */
                         PERIODICAL,
                         rte_lcore_id(),
                         tcp_timer_manage_cb,
                         NULL);
    
    if (ret < 0) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "TCP计时器管理器启动失败");
        return MYLIB_ERROR_INIT;
    }
    
    tcp_timer_initialized = 1;
    MYLIB_LOG(LOG_LEVEL_INFO, "TCP计时器系统初始化成功");
    return MYLIB_SUCCESS;
}

/**
 * @brief 清理TCP计时器系统
 *
 * 停止所有计时器并释放资源
 */
void tcp_timer_cleanup(void) {
    if (!tcp_timer_initialized) {
        return;
    }
    
    MYLIB_LOG(LOG_LEVEL_INFO, "清理TCP计时器系统");
    
    /* 停止计时器管理器 */
    rte_timer_stop(&tcp_timer_manager);
    
    /* 停止所有活动的TCP计时器 */
    pthread_mutex_lock(&g_tcp_mutex);
    struct tcp_control_block *tcb;
    for (tcb = g_tcb_list; tcb != NULL; tcb = tcb->next) {
        for (int i = 0; i < TCP_TIMER_MAX; i++) {
            rte_timer_stop(&tcb->timers[i].timer);
        }
    }
    pthread_mutex_unlock(&g_tcp_mutex);
    
    tcp_timer_initialized = 0;
    MYLIB_LOG(LOG_LEVEL_INFO, "TCP计时器系统清理完成");
}

/**
 * @brief 启动特定类型的TCP计时器
 *
 * @param tcb TCP控制块
 * @param type 计时器类型
 * @param timeout_ns 超时时间(纳秒)
 * @return MYLIB_SUCCESS成功，其他错误码表示失败
 */
mylib_error_t tcp_timer_start(struct tcp_control_block *tcb, tcp_timer_type_t type, uint64_t timeout_ns) {
    if (type >= TCP_TIMER_MAX || !tcb) {
        return MYLIB_ERROR_INVALID;
    }
    
    MYLIB_LOG(LOG_LEVEL_DEBUG, "启动TCP计时器，类型=%d，超时=%llu ns", type, timeout_ns);
    
    struct tcp_timer *timer = &tcb->timers[type];
    timer->tcb = tcb;
    timer->type = type;
    
    /* 初始化计时器 */
    rte_timer_init(&timer->timer);
    
    /* 计算ticks */
    uint64_t hz = rte_get_timer_hz();
    uint64_t ticks = (timeout_ns * hz) / 1000000000ULL;
    
    if (ticks == 0) ticks = 1; /* 确保至少有1个tick */
    
    /* 设置计时器 */
    int ret = rte_timer_reset(&timer->timer,
                            ticks,
                            SINGLE,
                            rte_lcore_id(),
                            tcp_timer_callbacks[type],
                            NULL);
                            
    if (ret < 0) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "TCP计时器启动失败，类型=%d", type);
        return MYLIB_ERROR_TIMER;
    }
    
    return MYLIB_SUCCESS;
}

/**
 * @brief 停止特定类型的TCP计时器
 *
 * @param tcb TCP控制块
 * @param type 计时器类型
 */
void tcp_timer_stop(struct tcp_control_block *tcb, tcp_timer_type_t type) {
    if (type >= TCP_TIMER_MAX || !tcb) {
        return;
    }
    
    MYLIB_LOG(LOG_LEVEL_DEBUG, "停止TCP计时器，类型=%d", type);
    rte_timer_stop(&tcb->timers[type].timer);
}

/**
 * @brief 重置特定类型的TCP计时器
 *
 * @param tcb TCP控制块
 * @param type 计时器类型
 * @param timeout_ns 超时时间(纳秒)
 */
void tcp_timer_reset(struct tcp_control_block *tcb, tcp_timer_type_t type, uint64_t timeout_ns) {
    if (type >= TCP_TIMER_MAX || !tcb) {
        return;
    }
    
    MYLIB_LOG(LOG_LEVEL_DEBUG, "重置TCP计时器，类型=%d，超时=%llu ns", type, timeout_ns);
    
    /* 计算ticks */
    uint64_t hz = rte_get_timer_hz();
    uint64_t ticks = (timeout_ns * hz) / 1000000000ULL;
    
    if (ticks == 0) ticks = 1; /* 确保至少有1个tick */
    
    /* 重置计时器 */
    rte_timer_reset(&tcb->timers[type].timer,
                   ticks,
                   SINGLE,
                   rte_lcore_id(),
                   tcp_timer_callbacks[type],
                   NULL);
}

/**
 * @brief 更新RTT和RTO
 *
 * 根据测量的RTT更新SRTT、RTTVAR和RTO值，使用RFC6298算法
 * 
 * @param tcb TCP控制块
 * @param measured_rtt_ns 测量的RTT值(纳秒)
 */
void tcp_update_rtt(struct tcp_control_block *tcb, uint64_t measured_rtt_ns) {
    MYLIB_LOG(LOG_LEVEL_DEBUG, "更新RTT: 测量值=%llu ns", measured_rtt_ns);
    
    if (tcb->srtt == 0) {
        /* 首次测量 */
        tcb->srtt = measured_rtt_ns;
        tcb->rttvar = measured_rtt_ns / 2;
    } else {
        /* 更新RTTVAR和SRTT，使用RFC6298中的算法 */
        tcb->rttvar = (3 * tcb->rttvar + labs((int64_t)tcb->srtt - (int64_t)measured_rtt_ns)) / 4;
        tcb->srtt = (7 * tcb->srtt + measured_rtt_ns) / 8;
    }
    
    /* 计算新的RTO */
    tcb->rto = tcb->srtt + 4 * tcb->rttvar;
    
    /* 设置最小和最大限制 */
    if (tcb->rto < 1000000ULL) { /* 最小1ms */
        tcb->rto = 1000000ULL;
    }
    if (tcb->rto > 60000000000ULL) { /* 最大60s */
        tcb->rto = 60000000000ULL;
    }
    
    MYLIB_LOG(LOG_LEVEL_DEBUG, "更新RTO: 新值=%llu ns", tcb->rto);
}

/*===========================================================================*/
/*                        TCP模块初始化和清理                                 */
/*===========================================================================*/

/**
 * @brief 初始化TCP模块
 *
 * 初始化全局变量和计时器系统
 *
 * @return MYLIB_SUCCESS成功，其他错误码表示失败
 */
mylib_error_t tcp_init(void) {
    MYLIB_LOG(LOG_LEVEL_INFO, "初始化TCP模块");
    
    /* 初始化全局变量 */
    g_tcb_list = NULL;
    
    /* 初始化TCP计时器系统 */
    mylib_error_t ret = tcp_timer_init();
    if (ret != MYLIB_SUCCESS) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "TCP计时器初始化失败");
        return ret;
    }
    
    MYLIB_LOG(LOG_LEVEL_INFO, "TCP模块初始化成功");
    return MYLIB_SUCCESS;
}

/**
 * @brief 清理TCP模块资源
 *
 * 释放所有TCP控制块和计时器资源
 */
void tcp_cleanup(void) {
    MYLIB_LOG(LOG_LEVEL_INFO, "清理TCP模块");
    
    /* 清理计时器系统 */
    tcp_timer_cleanup();
    
    /* 释放所有TCP控制块 */
    pthread_mutex_lock(&g_tcp_mutex);
    struct tcp_control_block *tcb = g_tcb_list;
    while (tcb != NULL) {
        struct tcp_control_block *next = tcb->next;
        tcp_destroy_tcb(tcb);
        tcb = next;
    }
    g_tcb_list = NULL;
    pthread_mutex_unlock(&g_tcp_mutex);
    
    MYLIB_LOG(LOG_LEVEL_INFO, "TCP模块清理完成");
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
    
    /* 初始化计时器相关字段 */
    for (int i = 0; i < TCP_TIMER_MAX; i++) {
        tcb->timers[i].tcb = tcb;
        tcb->timers[i].type = i;
        rte_timer_init(&tcb->timers[i].timer);
    }
    
    /* 设置初始RTO值（例如1秒） */
    tcb->rto = 1000000000ULL;  /* 1秒，单位ns */
    tcb->srtt = 0;
    tcb->rttvar = 0;
    
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

/*===========================================================================*/
/*                       TCP状态机实现                                        */
/*===========================================================================*/

/**
 * @brief TCP输入处理函数
 *
 * 实现TCP状态机，处理收到的TCP段
 *
 * @param tcb TCP控制块
 * @param seg 收到的TCP段
 */
void tcp_input(struct tcp_control_block *tcb, struct tcp_segment *seg) {
    MYLIB_LOG(LOG_LEVEL_DEBUG, "TCP输入处理: 状态=%d, 标志=%02x, 序列号=%u, 确认号=%u",
              tcb->state, seg->flags, seg->seq, seg->ack);
    
    /* 通用RST处理 */
    if (seg->flags & RTE_TCP_RST_FLAG) {
        MYLIB_LOG(LOG_LEVEL_INFO, "收到RST标志，关闭连接");
        
        /* 对于连接请求的RST，通知用户 */
        if (tcb->state == TCP_STATE_SYN_SENT) {
            /* 连接被拒绝 */
            tcb->sock->error = MYLIB_ERROR_CONNECTION;
            pthread_mutex_lock(&tcb->sock->mutex);
            pthread_cond_signal(&tcb->sock->cond);
            pthread_mutex_unlock(&tcb->sock->mutex);
        }
        
        /* 设置状态为CLOSED */
        tcb->state = TCP_STATE_CLOSED;
        
        /* 停止所有计时器 */
        for (int i = 0; i < TCP_TIMER_MAX; i++) {
            tcp_timer_stop(tcb, i);
        }
        
        return;
    }
    
    /* 根据当前状态处理 */
    switch (tcb->state) {
        case TCP_STATE_CLOSED:
            /* 在CLOSED状态下收到数据包，应该回复RST */
            {
                struct tcp_segment rst;
                memset(&rst, 0, sizeof(rst));
                
                if (seg->flags & RTE_TCP_ACK_FLAG) {
                    rst.seq = seg->ack;
                    rst.flags = RTE_TCP_RST_FLAG;
                } else {
                    rst.seq = 0;
                    rst.ack = seg->seq + seg->length + 
                              ((seg->flags & RTE_TCP_SYN_FLAG) ? 1 : 0) + 
                              ((seg->flags & RTE_TCP_FIN_FLAG) ? 1 : 0);
                    rst.flags = RTE_TCP_RST_FLAG | RTE_TCP_ACK_FLAG;
                }
                
                struct rte_mbuf *mbuf = tcp_create_packet(tcb, &rst);
                if (mbuf) {
                    rte_ring_mp_enqueue(g_out_ring, mbuf);
                }
            }
            break;
            
        case TCP_STATE_LISTEN:
            /* 监听状态，处理SYN请求 */
            if (seg->flags & RTE_TCP_SYN_FLAG) {
                MYLIB_LOG(LOG_LEVEL_INFO, "LISTEN状态收到SYN请求");
                
                /* 生成ISN */
                tcb->snd_una = tcb->snd_nxt = (uint32_t)time(NULL);
                
                /* 记录远程地址和端口 */
                tcb->remote_ip = seg->src_ip;
                tcb->remote_port = seg->src_port;
                
                /* 记录对方的ISN */
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
                    tcb->snd_nxt++;
                    tcb->state = TCP_STATE_SYN_RCVD;
                    
                    /* 启动重传计时器 */
                    tcp_timer_start(tcb, TCP_TIMER_RETRANSMIT, tcb->rto);
                }
            }
            break;
            
        case TCP_STATE_SYN_SENT:
            /* 已发送SYN，等待对方响应 */
            if ((seg->flags & (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG)) == 
                             (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG)) {
                /* 收到SYN+ACK */
                MYLIB_LOG(LOG_LEVEL_INFO, "SYN_SENT状态收到SYN+ACK响应");
                
                /* 检查ACK是否确认了我们的SYN */
                if (seg->ack == tcb->snd_nxt) {
                    /* 更新确认信息 */
                    tcb->snd_una = seg->ack;
                    
                    /* 记录对方的ISN */
                    tcb->rcv_nxt = seg->seq + 1;
                    
                    /* 发送ACK */
                    struct tcp_segment ack;
                    memset(&ack, 0, sizeof(ack));
                    ack.seq = tcb->snd_nxt;
                    ack.ack = tcb->rcv_nxt;
                    ack.flags = RTE_TCP_ACK_FLAG;
                    ack.window = tcb->window;
                    
                    struct rte_mbuf *mbuf = tcp_create_packet(tcb, &ack);
                    if (mbuf) {
                        rte_ring_mp_enqueue(g_out_ring, mbuf);
                        
                        /* 连接建立成功 */
                        tcb->state = TCP_STATE_ESTABLISHED;
                        
                        /* 停止重传计时器 */
                        tcp_timer_stop(tcb, TCP_TIMER_RETRANSMIT);
                        
                        /* 启动保活计时器 */
                        tcp_timer_start(tcb, TCP_TIMER_KEEPALIVE, 7200000000000ULL); /* 2小时 */
                        
                        /* 通知等待的应用程序 */
                        pthread_mutex_lock(&tcb->sock->mutex);
                        pthread_cond_signal(&tcb->sock->cond);
                        pthread_mutex_unlock(&tcb->sock->mutex);
                    }
                }
            } else if (seg->flags & RTE_TCP_SYN_FLAG) {
                /* 同时打开情况，收到SYN */
                MYLIB_LOG(LOG_LEVEL_INFO, "SYN_SENT状态收到SYN请求（同时打开）");
                
                /* 记录对方的ISN */
                tcb->rcv_nxt = seg->seq + 1;
                
                /* 发送SYN+ACK */
                struct tcp_segment reply;
                memset(&reply, 0, sizeof(reply));
                reply.seq = tcb->snd_una;  /* 使用初始序列号 */
                reply.ack = tcb->rcv_nxt;
                reply.flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
                reply.window = tcb->window;
                
                struct rte_mbuf *mbuf = tcp_create_packet(tcb, &reply);
                if (mbuf) {
                    rte_ring_mp_enqueue(g_out_ring, mbuf);
                    tcb->state = TCP_STATE_SYN_RCVD;
                }
            }
            break;
            
        case TCP_STATE_SYN_RCVD:
            /* 已收到SYN并回复SYN+ACK，等待最终ACK */
            if (seg->flags & RTE_TCP_ACK_FLAG) {
                /* 检查ACK是否确认了我们的SYN */
                if (seg->ack == tcb->snd_nxt) {
                    MYLIB_LOG(LOG_LEVEL_INFO, "SYN_RCVD状态收到ACK，连接建立");
                    
                    /* 更新确认信息 */
                    tcb->snd_una = seg->ack;
                    
                    /* 连接建立成功 */
                    tcb->state = TCP_STATE_ESTABLISHED;
                    
                    /* 停止重传计时器 */
                    tcp_timer_stop(tcb, TCP_TIMER_RETRANSMIT);
                    
                    /* 启动保活计时器 */
                    tcp_timer_start(tcb, TCP_TIMER_KEEPALIVE, 7200000000000ULL); /* 2小时 */
                    
                    /* 通知等待的应用程序 */
                    pthread_mutex_lock(&tcb->sock->mutex);
                    pthread_cond_signal(&tcb->sock->cond);
                    pthread_mutex_unlock(&tcb->sock->mutex);
                }
            }
            break;
            
        case TCP_STATE_ESTABLISHED:
            /* 连接已建立，处理数据传输 */
            if (seg->flags & RTE_TCP_ACK_FLAG) {
                /* 更新已确认序列号 */
                if (SEQ_GT(seg->ack, tcb->snd_una)) {
                    tcb->snd_una = seg->ack;
                    
                    /* 有新的确认，重置重传计时器 */
                    if (tcb->snd_una != tcb->snd_nxt) {
                        tcp_timer_reset(tcb, TCP_TIMER_RETRANSMIT, tcb->rto);
                    } else {
                        /* 所有数据都已确认，停止重传计时器 */
                        tcp_timer_stop(tcb, TCP_TIMER_RETRANSMIT);
                    }
                }
            }
            
            /* 处理数据部分 */
            if (seg->length > 0) {
                /* 检查序列号是否符合预期 */
                if (seg->seq == tcb->rcv_nxt) {
                    MYLIB_LOG(LOG_LEVEL_DEBUG, "接收到%u字节有序数据", seg->length);
                    
                    /* 将数据放入接收缓冲区 */
                    /* 这里需要实现数据缓存逻辑 */
                    
                    /* 更新接收窗口 */
                    tcb->rcv_nxt += seg->length;
                    
                    /* 发送ACK */
                    struct tcp_segment ack;
                    memset(&ack, 0, sizeof(ack));
                    ack.seq = tcb->snd_nxt;
                    ack.ack = tcb->rcv_nxt;
                    ack.flags = RTE_TCP_ACK_FLAG;
                    ack.window = tcb->window;
                    
                    struct rte_mbuf *mbuf = tcp_create_packet(tcb, &ack);
                    if (mbuf) {
                        rte_ring_mp_enqueue(g_out_ring, mbuf);
                    }
                    
                    /* 通知应用程序有数据可读 */
                    pthread_mutex_lock(&tcb->sock->mutex);
                    pthread_cond_signal(&tcb->sock->cond);
                    pthread_mutex_unlock(&tcb->sock->mutex);
                } else {
                    /* 乱序数据，只回复ACK */
                    struct tcp_segment ack;
                    memset(&ack, 0, sizeof(ack));
                    ack.seq = tcb->snd_nxt;
                    ack.ack = tcb->rcv_nxt;
                    ack.flags = RTE_TCP_ACK_FLAG;
                    ack.window = tcb->window;
                    
                    struct rte_mbuf *mbuf = tcp_create_packet(tcb, &ack);
                    if (mbuf) {
                        rte_ring_mp_enqueue(g_out_ring, mbuf);
                    }
                }
            }
            
            /* 处理FIN标志 */
            if (seg->flags & RTE_TCP_FIN_FLAG) {
                MYLIB_LOG(LOG_LEVEL_INFO, "ESTABLISHED状态收到FIN");
                
                /* 更新接收序列号 */
                tcb->rcv_nxt = seg->seq + 1;
                
                /* 发送ACK */
                struct tcp_segment ack;
                memset(&ack, 0, sizeof(ack));
                ack.seq = tcb->snd_nxt;
                ack.ack = tcb->rcv_nxt;
                ack.flags = RTE_TCP_ACK_FLAG;
                ack.window = tcb->window;
                
                struct rte_mbuf *mbuf = tcp_create_packet(tcb, &ack);
                if (mbuf) {
                    rte_ring_mp_enqueue(g_out_ring, mbuf);
                    
                    /* 被动关闭，转到CLOSE_WAIT状态 */
                    tcb->state = TCP_STATE_CLOSE_WAIT;
                    
                    /* 通知应用程序连接正在关闭 */
                    pthread_mutex_lock(&tcb->sock->mutex);
                    pthread_cond_signal(&tcb->sock->cond);
                    pthread_mutex_unlock(&tcb->sock->mutex);
                }
            }
            break;
            
        case TCP_STATE_FIN_WAIT_1:
            /* 已发送FIN，等待ACK和对方的FIN */
            if (seg->flags & RTE_TCP_ACK_FLAG) {
                /* 检查是否确认了我们的FIN */
                if (seg->ack == tcb->snd_nxt) {
                    MYLIB_LOG(LOG_LEVEL_INFO, "FIN_WAIT_1状态收到ACK");
                    
                    /* 更新已确认序列号 */
                    tcb->snd_una = seg->ack;
                    
                    /* 如果同时收到了FIN */
                    if (seg->flags & RTE_TCP_FIN_FLAG) {
                        /* 更新接收序列号 */
                        tcb->rcv_nxt = seg->seq + 1;
                        
                        /* 发送ACK */
                        struct tcp_segment ack;
                        memset(&ack, 0, sizeof(ack));
                        ack.seq = tcb->snd_nxt;
                        ack.ack = tcb->rcv_nxt;
                        ack.flags = RTE_TCP_ACK_FLAG;
                        ack.window = tcb->window;
                        
                        struct rte_mbuf *mbuf = tcp_create_packet(tcb, &ack);
                        if (mbuf) {
                            rte_ring_mp_enqueue(g_out_ring, mbuf);
                            
                            /* 转到TIME_WAIT状态 */
                            tcb->state = TCP_STATE_TIME_WAIT;
                            
                            /* 启动TIME_WAIT计时器 (2MSL) */
                            tcp_timer_start(tcb, TCP_TIMER_TIME_WAIT, 60000000000ULL); /* 60秒 */
                        }
                    } else {
                        /* 只收到ACK，进入FIN_WAIT_2 */
                        tcb->state = TCP_STATE_FIN_WAIT_2;
                        
                        /* 停止重传计时器 */
                        tcp_timer_stop(tcb, TCP_TIMER_RETRANSMIT);
                    }
                }
            } else if (seg->flags & RTE_TCP_FIN_FLAG) {
                /* 收到FIN但没有ACK，进入CLOSING状态 */
                MYLIB_LOG(LOG_LEVEL_INFO, "FIN_WAIT_1状态收到FIN");
                
                /* 更新接收序列号 */
                tcb->rcv_nxt = seg->seq + 1;
                
                /* 发送ACK */
                struct tcp_segment ack;
                memset(&ack, 0, sizeof(ack));
                ack.seq = tcb->snd_nxt;
                ack.ack = tcb->rcv_nxt;
                ack.flags = RTE_TCP_ACK_FLAG;
                ack.window = tcb->window;
                
                struct rte_mbuf *mbuf = tcp_create_packet(tcb, &ack);
                if (mbuf) {
                    rte_ring_mp_enqueue(g_out_ring, mbuf);
                    
                    /* 转到CLOSING状态 */
                    tcb->state = TCP_STATE_CLOSING;
                }
            }
            break;
            
        case TCP_STATE_FIN_WAIT_2:
            /* 等待对方的FIN */
            if (seg->flags & RTE_TCP_FIN_FLAG) {
                MYLIB_LOG(LOG_LEVEL_INFO, "FIN_WAIT_2状态收到FIN");
                
                /* 更新接收序列号 */
                tcb->rcv_nxt = seg->seq + 1;
                
                /* 发送ACK */
                struct tcp_segment ack;
                memset(&ack, 0, sizeof(ack));
                ack.seq = tcb->snd_nxt;
                ack.ack = tcb->rcv_nxt;
                ack.flags = RTE_TCP_ACK_FLAG;
                ack.window = tcb->window;
                
                struct rte_mbuf *mbuf = tcp_create_packet(tcb, &ack);
                if (mbuf) {
                    rte_ring_mp_enqueue(g_out_ring, mbuf);
                    
                    /* 转到TIME_WAIT状态 */
                    tcb->state = TCP_STATE_TIME_WAIT;
                    
                    /* 启动TIME_WAIT计时器 (2MSL) */
                    tcp_timer_start(tcb, TCP_TIMER_TIME_WAIT, 60000000000ULL); /* 60秒 */
                }
            } else if (seg->length > 0) {
                /* 在FIN_WAIT_2状态下仍可能收到数据 */
                if (seg->seq == tcb->rcv_nxt) {
                    /* 更新接收窗口 */
                    tcb->rcv_nxt += seg->length;
                    
                    /* 发送ACK */
                    struct tcp_segment ack;
                    memset(&ack, 0, sizeof(ack));
                    ack.seq = tcb->snd_nxt;
                    ack.ack = tcb->rcv_nxt;
                    ack.flags = RTE_TCP_ACK_FLAG;
                    ack.window = tcb->window;
                    
                    struct rte_mbuf *mbuf = tcp_create_packet(tcb, &ack);
                    if (mbuf) {
                        rte_ring_mp_enqueue(g_out_ring, mbuf);
                    }
                }
            }
            break;
            
        case TCP_STATE_CLOSING:
            /* 等待对方确认我们的FIN */
            if (seg->flags & RTE_TCP_ACK_FLAG) {
                /* 检查是否确认了我们的FIN */
                if (seg->ack == tcb->snd_nxt) {
                    MYLIB_LOG(LOG_LEVEL_INFO, "CLOSING状态收到ACK");
                    
                    /* 更新已确认序列号 */
                    tcb->snd_una = seg->ack;
                    
                    /* 转到TIME_WAIT状态 */
                    tcb->state = TCP_STATE_TIME_WAIT;
                    
                    /* 停止重传计时器 */
                    tcp_timer_stop(tcb, TCP_TIMER_RETRANSMIT);
                    
                    /* 启动TIME_WAIT计时器 (2MSL) */
                    tcp_timer_start(tcb, TCP_TIMER_TIME_WAIT, 60000000000ULL); /* 60秒 */
                }
            }
            break;
            
        case TCP_STATE_TIME_WAIT:
            /* 收到新的FIN，需要再次发送ACK */
            if (seg->flags & RTE_TCP_FIN_FLAG) {
                MYLIB_LOG(LOG_LEVEL_INFO, "TIME_WAIT状态收到FIN，重新发送ACK");
                
                /* 发送ACK */
                struct tcp_segment ack;
                memset(&ack, 0, sizeof(ack));
                ack.seq = tcb->snd_nxt;
                ack.ack = tcb->rcv_nxt;
                ack.flags = RTE_TCP_ACK_FLAG;
                ack.window = tcb->window;
                
                struct rte_mbuf *mbuf = tcp_create_packet(tcb, &ack);
                if (mbuf) {
                    rte_ring_mp_enqueue(g_out_ring, mbuf);
                    
                    /* 重置TIME_WAIT计时器 */
                    tcp_timer_reset(tcb, TCP_TIMER_TIME_WAIT, 60000000000ULL); /* 60秒 */
                }
            }
            break;
            
        case TCP_STATE_CLOSE_WAIT:
            /* 等待应用层调用close */
            /* 此状态下通常不会处理任何输入 */
            if (seg->flags & RTE_TCP_ACK_FLAG) {
                /* 可能更新窗口信息等 */
                MYLIB_LOG(LOG_LEVEL_DEBUG, "CLOSE_WAIT状态收到ACK");
            }
            break;
            
        case TCP_STATE_LAST_ACK:
            /* 等待对方确认我们的FIN */
            if (seg->flags & RTE_TCP_ACK_FLAG) {
                /* 检查是否确认了我们的FIN */
                if (seg->ack == tcb->snd_nxt) {
                    MYLIB_LOG(LOG_LEVEL_INFO, "LAST_ACK状态收到ACK，连接关闭");
                    
                    /* 更新已确认序列号 */
                    tcb->snd_una = seg->ack;
                    
                    /* 连接可以完全关闭 */
                    tcb->state = TCP_STATE_CLOSED;
                    
                    /* 停止重传计时器 */
                    tcp_timer_stop(tcb, TCP_TIMER_RETRANSMIT);
                    
                    /* 通知应用程序连接已关闭 */
                    pthread_mutex_lock(&tcb->sock->mutex);
                    pthread_cond_signal(&tcb->sock->cond);
                    pthread_mutex_unlock(&tcb->sock->mutex);
                    
                    /* 从TCB链表中移除 */
                    if (tcb->prev) {
                        tcb->prev->next = tcb->next;
                    } else {
                        g_tcb_list = tcb->next;
                    }
                    
                    if (tcb->next) {
                        tcb->next->prev = tcb->prev;
                    }
                    
                    /* 释放TCB资源 */
                    tcp_destroy_tcb(tcb);
                }
            }
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

mylib_error_t tcp_connect(struct tcp_control_block *tcb, uint32_t dst_ip, uint16_t dst_port) {
    MYLIB_LOG(LOG_LEVEL_INFO, "发起TCP连接: 目标IP=%u, 目标端口=%u", dst_ip, dst_port);
    
    /* 设置远程地址 */
    tcb->remote_ip = dst_ip;
    tcb->remote_port = dst_port;
    
    /* 生成初始序列号 */
    tcb->snd_una = tcb->snd_nxt = (uint32_t)time(NULL); /* 简单使用当前时间作为ISN */
    tcb->rcv_nxt = 0;
    
    /* 设置状态为SYN_SENT */
    tcb->state = TCP_STATE_SYN_SENT;
    
    /* 创建SYN包 */
    struct tcp_segment syn;
    memset(&syn, 0, sizeof(syn));
    syn.seq = tcb->snd_nxt;
    syn.flags = RTE_TCP_SYN_FLAG;
    syn.window = tcb->window;
    
    /* 创建并发送数据包 */
    struct rte_mbuf *mbuf = tcp_create_packet(tcb, &syn);
    if (!mbuf) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "创建SYN包失败");
        return MYLIB_ERROR_PKT_CREATE;
    }
    
    /* 入队等待发送 */
    if (rte_ring_mp_enqueue(g_out_ring, mbuf) != 0) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "SYN包入队失败");
        rte_pktmbuf_free(mbuf);
        return MYLIB_ERROR_FULL;
    }
    
    /* 增加序列号 */
    tcb->snd_nxt++;
    
    /* 启动重传计时器 */
    tcp_timer_start(tcb, TCP_TIMER_RETRANSMIT, tcb->rto);
    
    MYLIB_LOG(LOG_LEVEL_INFO, "TCP连接请求已发送");
    return MYLIB_SUCCESS;
}

mylib_error_t tcp_close(struct tcp_control_block *tcb) {
    MYLIB_LOG(LOG_LEVEL_INFO, "关闭TCP连接，当前状态=%d", tcb->state);
    
    /* 根据当前状态执行不同的关闭操作 */
    switch (tcb->state) {
        case TCP_STATE_CLOSED:
        case TCP_STATE_LISTEN:
        case TCP_STATE_SYN_SENT:
            /* 直接关闭 */
            tcb->state = TCP_STATE_CLOSED;
            break;
            
        case TCP_STATE_SYN_RCVD:
        case TCP_STATE_ESTABLISHED:
            /* 发送FIN包 */
            {
                struct tcp_segment fin;
                memset(&fin, 0, sizeof(fin));
                fin.seq = tcb->snd_nxt;
                fin.ack = tcb->rcv_nxt;
                fin.flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
                fin.window = tcb->window;
                
                struct rte_mbuf *mbuf = tcp_create_packet(tcb, &fin);
                if (mbuf) {
                    rte_ring_mp_enqueue(g_out_ring, mbuf);
                    tcb->snd_nxt++;
                    tcb->state = TCP_STATE_FIN_WAIT_1;
                    /* 启动重传计时器 */
                    tcp_timer_start(tcb, TCP_TIMER_RETRANSMIT, tcb->rto);
                }
            }
            break;
            
        case TCP_STATE_CLOSE_WAIT:
            /* 发送FIN包 */
            {
                struct tcp_segment fin;
                memset(&fin, 0, sizeof(fin));
                fin.seq = tcb->snd_nxt;
                fin.ack = tcb->rcv_nxt;
                fin.flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
                fin.window = tcb->window;
                
                struct rte_mbuf *mbuf = tcp_create_packet(tcb, &fin);
                if (mbuf) {
                    rte_ring_mp_enqueue(g_out_ring, mbuf);
                    tcb->snd_nxt++;
                    tcb->state = TCP_STATE_LAST_ACK;
                    /* 启动重传计时器 */
                    tcp_timer_start(tcb, TCP_TIMER_RETRANSMIT, tcb->rto);
                }
            }
            break;
            
        case TCP_STATE_FIN_WAIT_1:
        case TCP_STATE_FIN_WAIT_2:
        case TCP_STATE_CLOSING:
        case TCP_STATE_LAST_ACK:
        case TCP_STATE_TIME_WAIT:
            /* 已经在关闭过程中，不需要额外操作 */
            break;
    }
    
    return MYLIB_SUCCESS;
}
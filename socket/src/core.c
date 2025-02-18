#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <rte_malloc.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <time.h>

#include "internal/common.h"
#include "internal/logging.h"
#include "internal/tcp_impl.h"
#include "internal/udp_impl.h"
#include "internal/arp_impl.h"
#include "internal/icmp_impl.h"

/* 全局变量定义 */
static struct mylib_config *g_config = NULL;
static int g_initialized = 0;
static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned rx_core_id = 1;        /* 接收线程使用的核心ID */
static unsigned tx_core_id = 2;        /* 发送线程使用的核心ID */
static unsigned protocol_core_id = 3;  /* 协议处理线程使用的核心ID */

/* DPDK相关全局变量 */
struct rte_mempool *g_mbuf_pool = NULL;
struct rte_ring *g_in_ring = NULL;
struct rte_ring *g_out_ring = NULL;
uint8_t g_local_mac[RTE_ETHER_ADDR_LEN] = {0};
uint32_t g_local_ip = 0;

/* 内部函数声明 */
static mylib_error_t validate_config(const mylib_config_t* config);
static int rx_thread_launch(__attribute__((unused)) void *arg);
static int tx_thread_launch(__attribute__((unused)) void *arg);
static int protocol_thread_launch(__attribute__((unused)) void *arg);
static mylib_error_t process_ip_packet(struct rte_mbuf *mbuf);

/* 线程相关变量 */
static volatile int g_threads_running = 0;

mylib_error_t mylib_init(const mylib_config_t* config) {
    mylib_error_t ret;
    
    pthread_mutex_lock(&g_init_mutex);
    
    if (g_initialized) {
        pthread_mutex_unlock(&g_init_mutex);
        MYLIB_LOG(LOG_LEVEL_WARNING, "Library already initialized");
        return MYLIB_SUCCESS;
    }

    /* 验证配置 */
    if ((ret = validate_config(config)) != MYLIB_SUCCESS) {
        pthread_mutex_unlock(&g_init_mutex);
        return ret;
    }
    
    /* 创建全局配置 */
    g_config = (struct mylib_config *)malloc(sizeof(struct mylib_config));
    memset(g_config, 0, sizeof(struct mylib_config));
    if (!g_config) {
        pthread_mutex_unlock(&g_init_mutex);
        return MYLIB_ERROR_NOMEM;
    }

    /* 初始化配置 */
    memcpy(&g_config->public_config, config, sizeof(mylib_config_t));
    pthread_mutex_init(&g_config->mutex, NULL);
    /* 设置本地IP地址 */
    g_local_ip = config->network_config.ip_addr;

    /* 初始化日志系统 */
    logging_init();
    logging_set_level(config->log_level);

    /* 初始化DPDK */
    if ((ret = init_dpdk()) != MYLIB_SUCCESS) {
        rte_free(g_config);
        pthread_mutex_unlock(&g_init_mutex);
        return ret;
    }

    /* 初始化协议栈 */
    if ((ret = tcp_init()) != MYLIB_SUCCESS ||
        (ret = udp_init()) != MYLIB_SUCCESS ||
        (ret = arp_init()) != MYLIB_SUCCESS) {
        mylib_cleanup();
        pthread_mutex_unlock(&g_init_mutex);
        return ret;
    }

    /* 启动工作线程 */
    g_threads_running = 1;
    if (rte_eal_remote_launch(rx_thread_launch, NULL, rx_core_id) < 0 ||
        rte_eal_remote_launch(tx_thread_launch, NULL, tx_core_id) < 0 ||
        rte_eal_remote_launch(protocol_thread_launch, NULL, protocol_core_id) < 0) {
        g_threads_running = 0;
        mylib_cleanup();
        pthread_mutex_unlock(&g_init_mutex);
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to launch worker threads");
        return MYLIB_ERROR_INVALID;
    }

    MYLIB_LOG(LOG_LEVEL_INFO, "Worker threads launched successfully on cores %u, %u, %u",
              rx_core_id, tx_core_id, protocol_core_id);

    g_initialized = 1;
    pthread_mutex_unlock(&g_init_mutex);
    
    MYLIB_LOG(LOG_LEVEL_INFO, "Library initialized successfully");
    return MYLIB_SUCCESS;
}

void mylib_cleanup(void) {
    pthread_mutex_lock(&g_init_mutex);
    
    if (!g_initialized) {
        pthread_mutex_unlock(&g_init_mutex);
        return;
    }

    /* 停止工作线程 */
    g_threads_running = 0;

    /* 等待所有线程完成 */
    rte_eal_wait_lcore(rx_core_id);
    rte_eal_wait_lcore(tx_core_id);
    rte_eal_wait_lcore(protocol_core_id);

    /* 清理协议栈 */
    tcp_cleanup();
    udp_cleanup();
    arp_cleanup();

    /* 清理DPDK资源 */
    if (g_mbuf_pool) {
        rte_mempool_free(g_mbuf_pool);
        g_mbuf_pool = NULL;
    }

    cleanup_rings();

    /* 清理配置 */
    if (g_config) {
        pthread_mutex_destroy(&g_config->mutex);
        rte_free(g_config);
        g_config = NULL;
    }

    /* 清理日志系统 */
    logging_cleanup();

    g_initialized = 0;
    pthread_mutex_unlock(&g_init_mutex);
    
    MYLIB_LOG(LOG_LEVEL_INFO, "Library cleaned up successfully");
}

socket_handle_t mylib_socket(int domain, int type, int protocol) {
    
    if (!g_initialized) {
        errno = EINVAL;
        return NULL;
    }

    /* 验证参数 */
    if (domain != AF_INET || (type != SOCK_STREAM && type != SOCK_DGRAM)) {
        errno = EAFNOSUPPORT;
        return NULL;
    }

    /* 分配socket结构 */
    struct mylib_socket *sock = rte_malloc("mylib_socket", sizeof(struct mylib_socket), 0);
    if (!sock) {
        errno = ENOMEM;
        return NULL;
    }

    /* 初始化socket */
    memset(sock, 0, sizeof(struct mylib_socket));
    sock->protocol = (type == SOCK_STREAM) ? IPPROTO_TCP : IPPROTO_UDP;
    
    /* 分配文件描述符 */
    sock->fd = allocate_fd();
    if (sock->fd < 0) {
        rte_free(sock);
        errno = EMFILE;
        return NULL;
    }

    /* 创建缓冲区 */
    sock->send_buf = rte_ring_create("send_buf", g_config->public_config.ring_size,
                                    rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    sock->recv_buf = rte_ring_create("recv_buf", g_config->public_config.ring_size,
                                    rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    
    if (!sock->send_buf || !sock->recv_buf) {
        if (sock->send_buf) rte_ring_free(sock->send_buf);
        if (sock->recv_buf) rte_ring_free(sock->recv_buf);
        release_fd(sock->fd);
        rte_free(sock);
        errno = ENOMEM;
        return NULL;
    }

    /* 初始化同步原语 */
    pthread_mutex_init(&sock->mutex, NULL);
    pthread_cond_init(&sock->cond, NULL);

    MYLIB_LOG(LOG_LEVEL_DEBUG, "Created socket fd=%d, protocol=%d", 
              sock->fd, sock->protocol);
    
    return (socket_handle_t)sock;
}

mylib_error_t mylib_close(socket_handle_t handle) {
    struct mylib_socket *sock = (struct mylib_socket *)handle;
    
    if (!g_initialized || !sock) {
        return MYLIB_ERROR_INVALID;
    }

    /* 在释放之前保存需要的信息 */
    int fd = sock->fd;

    /* 释放资源 */
    if (sock->send_buf) rte_ring_free(sock->send_buf);
    if (sock->recv_buf) rte_ring_free(sock->recv_buf);
    
    pthread_mutex_destroy(&sock->mutex);
    pthread_cond_destroy(&sock->cond);
    
    release_fd(fd);
    rte_free(sock);

    MYLIB_LOG(LOG_LEVEL_DEBUG, "Closed socket fd=%d", fd);
    return MYLIB_SUCCESS;
}

/* 内部函数实现 */
static mylib_error_t validate_config(const mylib_config_t* config) {
    if (!config) {
        return MYLIB_ERROR_INVALID;
    }

    if (config->max_fds <= 0 || config->max_fds > 65535) {
        return MYLIB_ERROR_INVALID;
    }

    if (config->ring_size <= 0 || config->ring_size > 65535 ||
        (config->ring_size & (config->ring_size - 1)) != 0) {
        return MYLIB_ERROR_INVALID;
    }

    if (config->timeout_sec <= 0 || config->timeout_sec > 3600) {
        return MYLIB_ERROR_INVALID;
    }

    if (config->log_level < LOG_LEVEL_ERROR || 
        config->log_level > LOG_LEVEL_DEBUG) {
        return MYLIB_ERROR_INVALID;
    }

    /* 验证网络配置 */
    if (config->network_config.ip_addr == 0 || 
        config->network_config.ip_addr == INADDR_NONE) {
        return MYLIB_ERROR_INVALID;
    }

    if (config->network_config.port_range_start >= 
        config->network_config.port_range_end ||
        config->network_config.port_range_end > (uint16_t) 65535) {
        return MYLIB_ERROR_INVALID;
    }

    if (config->network_config.netmask == 0 || 
        config->network_config.netmask == INADDR_NONE) {
        return MYLIB_ERROR_INVALID;
    }

    /* 验证网关是否在同一子网 */
    if ((config->network_config.ip_addr & config->network_config.netmask) !=
        (config->network_config.gateway & config->network_config.netmask)) {
        return MYLIB_ERROR_INVALID;
    }

    /* 验证核心ID是否可用 */
    if (!rte_lcore_is_enabled(rx_core_id) ||
        !rte_lcore_is_enabled(tx_core_id) ||
        !rte_lcore_is_enabled(protocol_core_id)) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Required cores are not available");
        return MYLIB_ERROR_INVALID;
    }

    /* 确保核心ID不重复 */
    if (rx_core_id == tx_core_id ||
        rx_core_id == protocol_core_id ||
        tx_core_id == protocol_core_id) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Duplicate core IDs are not allowed");
        return MYLIB_ERROR_INVALID;
    }

    return MYLIB_SUCCESS;
}

static int rx_thread_launch(__attribute__((unused)) void *arg) {
    struct rte_mbuf *mbufs[32];
    unsigned int count;

    while (g_threads_running) {
        count = rte_eth_rx_burst(0, 0, mbufs, 32);
        if (count > 0) {
            unsigned int enqueued = rte_ring_sp_enqueue_burst(g_in_ring,
                                                            (void **)mbufs,
                                                            count,
                                                            NULL);
            for (unsigned int i = enqueued; i < count; i++) {
                rte_pktmbuf_free(mbufs[i]);
            }
        }
    }
    return 0;
}

static int tx_thread_launch(__attribute__((unused)) void *arg) {
    struct rte_mbuf *mbufs[32];
    unsigned int count;

    while (g_threads_running) {
        count = rte_ring_sc_dequeue_burst(g_out_ring,
                                        (void **)mbufs,
                                        32,
                                        NULL);
        if (count > 0) {
            unsigned int sent = rte_eth_tx_burst(0, 0, mbufs, count);
            for (unsigned int i = 0; i < sent; i++) {
                rte_pktmbuf_free(mbufs[i]);
            }
        }
    }
    return 0;
}

static int protocol_thread_launch(__attribute__((unused)) void *arg) {
    struct rte_mbuf *mbufs[32];
    unsigned int count;

    while (g_threads_running) {
        count = rte_ring_sc_dequeue_burst(g_in_ring,
                                        (void **)mbufs,
                                        32,
                                        NULL);
        
        if (count > 0) {
            for (unsigned int i = 0; i < count; i++) {
                struct rte_ether_hdr *eth_hdr = 
                    rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
                
                switch (ntohs(eth_hdr->ether_type)) {
                    case RTE_ETHER_TYPE_ARP:
                        if (arp_process_packet(mbufs[i]) != MYLIB_SUCCESS) {
                            //MYLIB_LOG(LOG_LEVEL_DEBUG, "Failed to process ARP packet");
                            break;
                        }
                        break;
                        
                    case RTE_ETHER_TYPE_IPV4:
                        if (process_ip_packet(mbufs[i]) != MYLIB_SUCCESS) {
                            //MYLIB_LOG(LOG_LEVEL_DEBUG, "Failed to process IP packet");
                            break;
                        }
                        break;
                        
                    default:
                        //MYLIB_LOG(LOG_LEVEL_DEBUG, 
                        //        "Unknown ethernet type: 0x%04x",
                        //        ntohs(eth_hdr->ether_type));
                        break;
                }
                
                rte_pktmbuf_free(mbufs[i]);
            }
        }
    }
    return 0;
}

static mylib_error_t process_ip_packet(struct rte_mbuf *mbuf) {
    struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(mbuf, 
                                                         struct rte_ipv4_hdr *, 
                                                         sizeof(struct rte_ether_hdr));
    
    /* 验证IP头部 */
    if (unlikely(mbuf->data_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr))) {
        MYLIB_LOG(LOG_LEVEL_WARNING, "IP packet too short");
        return MYLIB_ERROR_INVALID;
    }
    
    /* 验证版本号 */
    if (unlikely(((ip_hdr->version_ihl) >> 4) != 4)) {
        MYLIB_LOG(LOG_LEVEL_WARNING, "Invalid IP version");
        return MYLIB_ERROR_INVALID;
    }
    
    /* 验证校验和 */
    if (unlikely(rte_ipv4_cksum(ip_hdr) != 0)) {
        MYLIB_LOG(LOG_LEVEL_WARNING, "Invalid IP checksum");
        return MYLIB_ERROR_INVALID;
    }
    
    /* 检查目的IP是否为本机 */
    if (ip_hdr->dst_addr != g_local_ip) {
        //MYLIB_LOG(LOG_LEVEL_DEBUG, "IP packet not for us");
        return MYLIB_ERROR_INVALID;
    }
    
    /* 根据协议类型分发 */
    switch (ip_hdr->next_proto_id) {
        case IPPROTO_ICMP:
            return icmp_process_packet(mbuf);
            
        case IPPROTO_UDP:
            return udp_process_packet(mbuf);
            
        case IPPROTO_TCP:
            return tcp_process_packet(mbuf);
            
        default:
            MYLIB_LOG(LOG_LEVEL_DEBUG, "Unsupported IP protocol: %d", 
                     ip_hdr->next_proto_id);
            return MYLIB_ERROR_INVALID;
    }
}
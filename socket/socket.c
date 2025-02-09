#include "socket.h"
#include "udp.h"
#include "tcp.h"
#include "arp.h"
#include <errno.h>
#include <pthread.h>
#include <syslog.h>
#include <rte_malloc.h>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <linux/time.h>
#include "edrp_socket.h"

// 全局套接字位图（用于分配唯一的文件描述符）
static unsigned char fd_bitmap[1024] = {0};

// 在全局变量区域添加socket配置互斥锁
static pthread_mutex_t g_config_mutex;



// DPDK Initialization 宏定义
#define NUM_MBUFS 8192
#define BURST_SIZE 32
#define RING_SIZE 1024



// 添加线程相关的全局变量
static pthread_t g_rx_tid;
static pthread_t g_tx_tid;
static volatile int g_thread_running = 1;  // 线程运行状态控制

// DPDK Initialization 线程函数声明
static int rx_thread(__rte_unused void *arg);
static int tx_thread(__rte_unused void *arg);

//--------------------------------- Socket配置与检验函数实现 ---------------------------------//

/**
 * @brief 检查端口是否已被使用
 * @param port 要检查的端口号（网络字节序）
 * @return 如果端口已被使用返回1，否则返回0
 */
int check_port_in_use(uint16_t port) {
    // 检查UDP端口
    struct localhost *udp_host = lhost;
    while (udp_host != NULL) {
        if (udp_host->localport == port) {
            return 1;
        }
        udp_host = udp_host->next;
    }

    // 检查TCP端口
    struct ng_tcp_table *tcp_table = tcp_table_instance();
    if (tcp_table != NULL) {
        struct ng_tcp_stream *tcp_stream = tcp_table->tcb_set;
        while (tcp_stream != NULL) {
            if (tcp_stream->sport == port || 
                (tcp_stream->status == NG_TCP_STATUS_LISTEN && tcp_stream->dport == port)) {
                return 1;
            }
            tcp_stream = tcp_stream->next;
        }
    }

    return 0;
}

/**
 * @brief 验证socket配置参数的合法性
 */
static int validate_socket_config(const struct socket_config *config) {
    if (config == NULL) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Invalid config pointer");
        return SOCKET_ERROR_INVALID;
    }

    // 验证最大文件描述符数
    if (config->max_fds <= 0 || config->max_fds > 65535) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Invalid max_fds value: %d (should be between 1 and 65535)", 
                  config->max_fds);
        return SOCKET_ERROR_INVALID;
    }

    // 验证环形缓冲区大小
    if (config->ring_size <= 0 || config->ring_size > 65535 || 
        (config->ring_size & (config->ring_size - 1)) != 0) {  // 必须是2的幂
        SOCKET_LOG(SOCKET_LOG_ERROR, "Invalid ring_size value: %d (should be power of 2 and between 1 and 65535)", 
                  config->ring_size);
        return SOCKET_ERROR_INVALID;
    }

    // 验证超时时间
    if (config->timeout_sec <= 0 || config->timeout_sec > 3600) {  // 最大1小时
        SOCKET_LOG(SOCKET_LOG_ERROR, "Invalid timeout value: %d (should be between 1 and 3600)", 
                  config->timeout_sec);
        return SOCKET_ERROR_INVALID;
    }

    // 验证日志级别
    if (config->log_level < SOCKET_LOG_ERROR || config->log_level > SOCKET_LOG_DEBUG) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Invalid log level: %d", config->log_level);
        return SOCKET_ERROR_INVALID;
    }

    return SOCKET_SUCCESS;
}

/**
 * @brief 配置socket config设置
 */
int socket_set_config(const struct socket_config *config) {
    int ret = validate_socket_config(config);
    if (ret != SOCKET_SUCCESS) {
        return ret;
    }

    // 更新配置
    pthread_mutex_lock(&g_config_mutex);
    
    // 检查是否有正在使用的fd超过新的max_fds
    int max_used_fd = 0;
    for (int fd = 0; fd < g_config.max_fds; fd++) {
        int byte = fd / 8;
        int bit = fd % 8;
        if (fd_bitmap[byte] & (1 << bit)) {
            max_used_fd = fd;
        }
    }
    
    if (max_used_fd >= config->max_fds) {
        pthread_mutex_unlock(&g_config_mutex);
        SOCKET_LOG(SOCKET_LOG_ERROR, "Cannot reduce max_fds: active fd %d exceeds new limit %d",
                  max_used_fd, config->max_fds);
        return SOCKET_ERROR_INVALID;
    }

    g_config.max_fds = config->max_fds;
    g_config.ring_size = config->ring_size;
    g_config.timeout_sec = config->timeout_sec;
    g_config.log_level = config->log_level;
    
    // 更新日志级别
    setlogmask(LOG_UPTO(config->log_level));
    
    pthread_mutex_unlock(&g_config_mutex);

    SOCKET_LOG(SOCKET_LOG_INFO, "Socket configuration updated: max_fds=%d, ring_size=%d, timeout=%d, log_level=%d",
               g_config.max_fds, g_config.ring_size, g_config.timeout_sec, g_config.log_level);

    return SOCKET_SUCCESS;
}

/**
 * @brief 获取当前socket配置
 */
int socket_get_config(struct socket_config *config) {
    if (config == NULL) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Invalid config pointer");
        return SOCKET_ERROR_INVALID;
    }

    pthread_mutex_lock(&g_config_mutex);
    memcpy(config, &g_config, sizeof(struct socket_config));
    pthread_mutex_unlock(&g_config_mutex);

    return SOCKET_SUCCESS;
}

/**
 * @brief 设置日志级别
 */
void socket_set_log_level(int level) {
    // 验证日志级别的合法性
    if (level < SOCKET_LOG_ERROR || level > SOCKET_LOG_DEBUG) {
        SOCKET_LOG(SOCKET_LOG_WARNING, "Invalid log level: %d, using default INFO level", level);
        level = SOCKET_LOG_INFO;
    }

    // 更新日志级别
    pthread_mutex_lock(&g_config_mutex);
    g_config.log_level = level;
    pthread_mutex_unlock(&g_config_mutex);

    // 更新系统日志掩码
    switch (level) {
        case SOCKET_LOG_ERROR:
            setlogmask(LOG_UPTO(LOG_ERR));
            break;
        case SOCKET_LOG_WARNING:
            setlogmask(LOG_UPTO(SOCKET_LOG_WARNING));
            break;
        case SOCKET_LOG_INFO:
            setlogmask(LOG_UPTO(SOCKET_LOG_INFO));
            break;
        case SOCKET_LOG_DEBUG:
            setlogmask(LOG_UPTO(SOCKET_LOG_DEBUG));
            break;
    }

    SOCKET_LOG(SOCKET_LOG_INFO, "Log level set to %d", level);
}

/**
 * @brief 从位图中分配一个未使用的文件描述符
 */
static int allocate_fd(void) {
    pthread_mutex_lock(&g_config_mutex);
    
    for (int fd = 3; fd < g_config.max_fds; fd++) {
        int byte = fd / 8;
        int bit = fd % 8;
        if ((fd_bitmap[byte] & (1 << bit)) == 0) {
            fd_bitmap[byte] |= (1 << bit);
            pthread_mutex_unlock(&g_config_mutex);
            SOCKET_LOG(SOCKET_LOG_DEBUG, "Allocated fd=%d", fd);
            return fd;
        }
    }
    
    pthread_mutex_unlock(&g_config_mutex);
    SOCKET_LOG(SOCKET_LOG_ERROR, "No available file descriptors");
    return SOCKET_ERROR_NOMEM;
}

/**
 * @brief 资源统计函数
 */
void socket_stats(struct socket_statistics *stats) {
    stats->total_fds = 0;
    stats->used_fds = 0;
    
    for (int i = 0; i < g_config.max_fds / 8; i++) {
        for (int j = 0; j < 8; j++) {
            if (fd_bitmap[i] & (1 << j)) {
                stats->used_fds++;
            }
        }
    }
    stats->total_fds = g_config.max_fds;
    
    SOCKET_LOG(SOCKET_LOG_INFO, "Socket statistics: used_fds=%d, total_fds=%d",
               stats->used_fds, stats->total_fds);
}

/**
 * @brief 释放文件描述符
 */
static void release_fd(int fd) {
    if (fd < 3 || fd >= g_config.max_fds) {
        SOCKET_LOG(SOCKET_LOG_WARNING, "Invalid file descriptor: %d", fd);
        return;
    }

    pthread_mutex_lock(&g_config_mutex);
    int byte = fd / 8;
    int bit = fd % 8;
    fd_bitmap[byte] &= ~(1 << bit);
    pthread_mutex_unlock(&g_config_mutex);
    
    SOCKET_LOG(SOCKET_LOG_DEBUG, "Released fd=%d", fd);
}

/**
 * @brief 根据文件描述符获取TCP流或UDP上下文
 */
static void* get_context(int sockfd) {
    if (sockfd < 3 || sockfd >= g_config.max_fds) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Invalid socket descriptor: fd=%d", sockfd);
        return NULL;
    }

    // 检查fd是否已分配
    pthread_mutex_lock(&g_config_mutex);
    int byte = sockfd / 8;
    int bit = sockfd % 8;
    if ((fd_bitmap[byte] & (1 << bit)) == 0) {
        pthread_mutex_unlock(&g_config_mutex);
        SOCKET_LOG(SOCKET_LOG_ERROR, "Socket descriptor not allocated: fd=%d", sockfd);
        return NULL;
    }
    pthread_mutex_unlock(&g_config_mutex);

    // UDP上下文查找
    struct localhost *udp_ctx = udp_get_host_by_fd(sockfd);
    if (udp_ctx != NULL) {
        return udp_ctx;
    }

    // TCP流查找
    struct ng_tcp_stream *tcp_stream = tcp_find_stream_by_fd(sockfd);
    if (tcp_stream != NULL) {
        return tcp_stream;
    }

    SOCKET_LOG(SOCKET_LOG_ERROR, "No context found for socket descriptor: fd=%d", sockfd);
    return NULL;
}

//--------------------------------- Socket内部接口实现 ---------------------------------//

/**
 * @brief 创建套接字（支持非阻塞模式）
 */
int socket(int domain, int type, int protocol) {
    SOCKET_LOG(SOCKET_LOG_DEBUG, "Creating socket: domain=%d, type=%d, protocol=%d", domain, type, protocol);

    // 1. 参数验证
    int non_blocking = (type & SOCK_NONBLOCK);
    type &= ~SOCK_NONBLOCK;  // 清除标志位

    if (domain != AF_INET) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Unsupported domain: %d", domain);
        errno = EAFNOSUPPORT;
        return SOCKET_ERROR_INVALID;
    }

    if (type != SOCK_DGRAM && type != SOCK_STREAM) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Unsupported socket type: %d", type);
        errno = EPROTONOSUPPORT;
        return SOCKET_ERROR_INVALID;
    }

    if (protocol != 0 && protocol != IPPROTO_UDP && protocol != IPPROTO_TCP) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Unsupported protocol: %d", protocol);
        errno = EPROTONOSUPPORT;
        return SOCKET_ERROR_INVALID;
    }

    // 2. 分配文件描述符
    int fd = allocate_fd();
    if (fd < 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to allocate file descriptor");
        errno = EMFILE;
        return fd;  // 返回错误码
    }

    // 3. 创建socket上下文
    if (type == SOCK_DGRAM) {
        // 创建UDP上下文
        struct localhost *ctx = rte_malloc("udp_ctx", sizeof(struct localhost), 0);
        if (!ctx) {
            SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to allocate UDP context");
            release_fd(fd);
            errno = ENOMEM;
            return SOCKET_ERROR_NOMEM;
        }
        memset(ctx, 0, sizeof(struct localhost));

        // 初始化基本属性
        ctx->fd = fd;
        ctx->protocol = IPPROTO_UDP;
        ctx->non_blocking = non_blocking;
        
        // 创建收发缓冲区
        ctx->sndbuf = rte_ring_create("udp_snd", g_config.ring_size, 
                                     rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        ctx->rcvbuf = rte_ring_create("udp_rcv", g_config.ring_size,
                                     rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        
        if (!ctx->sndbuf || !ctx->rcvbuf) {
            SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to create ring buffers for UDP socket");
            if (ctx->sndbuf) rte_ring_free(ctx->sndbuf);
            if (ctx->rcvbuf) rte_ring_free(ctx->rcvbuf);
            rte_free(ctx);
            release_fd(fd);
            errno = ENOMEM;
            return SOCKET_ERROR_NOMEM;
        }

        // 初始化同步原语
        if (pthread_mutex_init(&ctx->mutex, NULL) != 0 || 
            pthread_cond_init(&ctx->cond, NULL) != 0) {
            SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to initialize synchronization primitives");
            if (ctx->sndbuf) rte_ring_free(ctx->sndbuf);
            if (ctx->rcvbuf) rte_ring_free(ctx->rcvbuf);
            rte_free(ctx);
            release_fd(fd);
            errno = ENOMEM;
            return SOCKET_ERROR_NOMEM;
        }
        
        // 添加到全局列表
        LL_ADD(ctx, lhost);
        SOCKET_LOG(SOCKET_LOG_INFO, "Created UDP socket with fd=%d", fd);
        
    } else if (type == SOCK_STREAM) {
        // 创建TCP流
        struct ng_tcp_stream *stream = rte_malloc("tcp_stream", sizeof(struct ng_tcp_stream), 0);
        if (!stream) {
            SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to allocate TCP stream");
            release_fd(fd);
            errno = ENOMEM;
            return SOCKET_ERROR_NOMEM;
        }
        memset(stream, 0, sizeof(struct ng_tcp_stream));

        // 初始化基本属性
        stream->fd = fd;
        stream->protocol = IPPROTO_TCP;
        stream->non_blocking = non_blocking;
        stream->status = NG_TCP_STATUS_CLOSED;
        
        // 创建收发缓冲区
        stream->sndbuf = rte_ring_create("tcp_snd", g_config.ring_size, 
                                        rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        stream->rcvbuf = rte_ring_create("tcp_rcv", g_config.ring_size,
                                        rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        
        if (!stream->sndbuf || !stream->rcvbuf) {
            SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to create ring buffers for TCP socket");
            if (stream->sndbuf) rte_ring_free(stream->sndbuf);
            if (stream->rcvbuf) rte_ring_free(stream->rcvbuf);
            rte_free(stream);
            release_fd(fd);
            errno = ENOMEM;
            return SOCKET_ERROR_NOMEM;
        }

        // 初始化同步原语
        if (pthread_mutex_init(&stream->mutex, NULL) != 0 || 
            pthread_cond_init(&stream->cond, NULL) != 0) {
            SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to initialize synchronization primitives");
            if (stream->sndbuf) rte_ring_free(stream->sndbuf);
            if (stream->rcvbuf) rte_ring_free(stream->rcvbuf);
            rte_free(stream);
            release_fd(fd);
            errno = ENOMEM;
            return SOCKET_ERROR_NOMEM;
        }

        // 添加到TCP表
        struct ng_tcp_table *table = tcp_table_instance();
        if (!table) {
            SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to get TCP table instance");
            if (stream->sndbuf) rte_ring_free(stream->sndbuf);
            if (stream->rcvbuf) rte_ring_free(stream->rcvbuf);
            pthread_mutex_destroy(&stream->mutex);
            pthread_cond_destroy(&stream->cond);
            rte_free(stream);
            release_fd(fd);
            errno = ENOMEM;
            return SOCKET_ERROR_NOMEM;
        }
        
        LL_ADD(stream, table->tcb_set);
        SOCKET_LOG(SOCKET_LOG_INFO, "Created TCP socket with fd=%d", fd);
    }
    
    return fd;
}

/**
 * @brief 绑定套接字
 */
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    SOCKET_LOG(SOCKET_LOG_DEBUG, "Binding socket fd=%d", sockfd);

    void *ctx = get_context(sockfd);
    if (!ctx) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Invalid socket descriptor: fd=%d", sockfd);
        errno = EBADF;
        return SOCKET_ERROR_INVALID;
    }

    const struct sockaddr_in *saddr = (const struct sockaddr_in*)addr;
    if (saddr->sin_family != AF_INET) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Unsupported address family: %d", saddr->sin_family);
        errno = EAFNOSUPPORT;
        return SOCKET_ERROR_INVALID;
    }

    // 检查端口是否已被使用
    if (check_port_in_use(saddr->sin_port)) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Port %d already in use", ntohs(saddr->sin_port));
        return SOCKET_ERROR_INUSE;
    }

    if (((struct localhost*)ctx)->protocol == IPPROTO_UDP) {
        struct localhost *udp_ctx = (struct localhost*)ctx;
        udp_ctx->localip = saddr->sin_addr.s_addr;
        udp_ctx->localport = saddr->sin_port;
        SOCKET_LOG(SOCKET_LOG_INFO, "UDP socket bound: fd=%d, ip=0x%x, port=%d", 
                  sockfd, ntohl(saddr->sin_addr.s_addr), ntohs(saddr->sin_port));
    } else if (((struct ng_tcp_stream*)ctx)->protocol == IPPROTO_TCP) {
        struct ng_tcp_stream *tcp_stream = (struct ng_tcp_stream*)ctx;
        tcp_stream->dip = saddr->sin_addr.s_addr;
        tcp_stream->dport = saddr->sin_port;
        SOCKET_LOG(SOCKET_LOG_INFO, "TCP socket bound: fd=%d, ip=0x%x, port=%d", 
                  sockfd, ntohl(saddr->sin_addr.s_addr), ntohs(saddr->sin_port));
    }
    return SOCKET_SUCCESS;
}

/**
 * @brief 监听套接字
 */
int listen(int sockfd, int backlog) {
    SOCKET_LOG(SOCKET_LOG_DEBUG, "Setting socket fd=%d to listen mode with backlog=%d", sockfd, backlog);

    struct ng_tcp_stream *stream = tcp_find_stream_by_fd(sockfd);
    if (!stream) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Invalid socket descriptor: fd=%d", sockfd);
        errno = EBADF;
        return SOCKET_ERROR_INVALID;
    }
    
    if (stream->protocol != IPPROTO_TCP) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Operation not supported on non-TCP socket: fd=%d", sockfd);
        errno = EOPNOTSUPP;
        return SOCKET_ERROR_INVALID;
    }

    if (backlog < 0 || backlog > SOMAXCONN) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Invalid backlog value: %d", backlog);
        errno = EINVAL;
        return SOCKET_ERROR_INVALID;
    }

    stream->status = NG_TCP_STATUS_LISTEN;
    SOCKET_LOG(SOCKET_LOG_INFO, "Socket fd=%d now listening with backlog=%d", sockfd, backlog);
    return SOCKET_SUCCESS;
}

/**
 * @brief 接受连接
 */
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    SOCKET_LOG(SOCKET_LOG_DEBUG, "Accepting connection on socket fd=%d", sockfd);

    struct ng_tcp_stream *listener = tcp_find_stream_by_fd(sockfd);
    if (!listener) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Invalid socket descriptor: fd=%d", sockfd);
        errno = EBADF;
        return SOCKET_ERROR_INVALID;
    }
    
    if (listener->status != NG_TCP_STATUS_LISTEN) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Socket fd=%d not in listen state", sockfd);
        errno = EINVAL;
        return SOCKET_ERROR_INVALID;
    }

    if (!addr || !addrlen) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Invalid address pointer or address length pointer");
        errno = EFAULT;
        return SOCKET_ERROR_INVALID;
    }

    // 阻塞直到有新连接或超时
    int non_blocking = listener->non_blocking;
    struct timespec start_time;
    if (!non_blocking) {
        clock_gettime(CLOCK_MONOTONIC, &start_time);
    }
    
    struct ng_tcp_stream *new_stream = NULL;
    pthread_mutex_lock(&listener->mutex);
    
    while ((new_stream = tcp_get_pending_connection(listener)) == NULL) {
        if (non_blocking) {
            SOCKET_LOG(SOCKET_LOG_DEBUG, "No pending connection available (non-blocking mode)");
            pthread_mutex_unlock(&listener->mutex);
            errno = EAGAIN;
            return SOCKET_ERROR_TIMEOUT;
        }
        
        // 阻塞模式检查超时
        struct timespec current_time;
        clock_gettime(CLOCK_MONOTONIC, &current_time);
        if (current_time.tv_sec - start_time.tv_sec >= g_config.timeout_sec) {
            SOCKET_LOG(SOCKET_LOG_WARNING, "Accept operation timed out after %d seconds", g_config.timeout_sec);
            pthread_mutex_unlock(&listener->mutex);
            errno = ETIMEDOUT;
            return SOCKET_ERROR_TIMEOUT;
        }
        
        pthread_cond_wait(&listener->cond, &listener->mutex);
    }
    pthread_mutex_unlock(&listener->mutex);

    // 分配新fd
    int new_fd = allocate_fd();
    if (new_fd == -1) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to allocate file descriptor for new connection");
        errno = EMFILE;
        return SOCKET_ERROR_NOMEM;
    }
    
    new_stream->fd = new_fd;
    new_stream->non_blocking = non_blocking;

    // 填充客户端地址
    struct sockaddr_in *saddr = (struct sockaddr_in*)addr;
    saddr->sin_family = AF_INET;
    saddr->sin_addr.s_addr = new_stream->sip;
    saddr->sin_port = new_stream->sport;
    *addrlen = sizeof(struct sockaddr_in);

    SOCKET_LOG(SOCKET_LOG_INFO, "Accepted new connection: fd=%d, remote_ip=0x%x, remote_port=%d", 
               new_fd, ntohl(new_stream->sip), ntohs(new_stream->sport));
    return new_fd;
}

/**
 * @brief 发送数据
 */
ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    SOCKET_LOG(SOCKET_LOG_DEBUG, "Sending data on socket fd=%d, len=%zu, flags=0x%x", sockfd, len, flags);

    // 1. 参数验证
    if (!buf || len == 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Invalid buffer or length");
        errno = EINVAL;
        return SOCKET_ERROR_INVALID;
    }

    if (len > UINT16_MAX) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Data length exceeds maximum allowed size");
        errno = EMSGSIZE;
        return SOCKET_ERROR_INVALID;
    }

    // 2. 获取上下文
    void *ctx = get_context(sockfd);
    if (!ctx) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Invalid socket descriptor: fd=%d", sockfd);
        errno = EBADF;
        return SOCKET_ERROR_INVALID;
    }

    // 3. 确定阻塞模式
    int non_blocking = 0;
    if (((struct localhost*)ctx)->protocol == IPPROTO_UDP) {
        non_blocking = ((struct localhost*)ctx)->non_blocking || (flags & MSG_DONTWAIT);
    } else {
        non_blocking = ((struct ng_tcp_stream*)ctx)->non_blocking || (flags & MSG_DONTWAIT);
    }

    // 4. 记录开始时间(用于超时控制)
    struct timespec start_time;
    if (!non_blocking) {
        clock_gettime(CLOCK_MONOTONIC, &start_time);
    }

    // 5. 根据协议类型处理
    if (((struct localhost*)ctx)->protocol == IPPROTO_UDP) {
        struct localhost *udp_ctx = (struct localhost*)ctx;
        
        // 创建offload结构
        struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
        if (!ol) {
            SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to allocate offload structure");
            errno = ENOMEM;
            return SOCKET_ERROR_NOMEM;
        }
        
        // 分配数据缓冲区
        ol->data = rte_malloc("payload", len, 0);
        if (!ol->data) {
            SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to allocate payload buffer");
            rte_free(ol);
            errno = ENOMEM;
            return SOCKET_ERROR_NOMEM;
        }

        // 初始化offload结构
        ol->length = len;
        ol->protocol = IPPROTO_UDP;
        rte_memcpy(ol->data, buf, len);
        ol->sip = udp_ctx->localip;
        ol->sport = udp_ctx->localport;
        
        // 非阻塞模式检查
        if (non_blocking && rte_ring_full(udp_ctx->sndbuf)) {
            SOCKET_LOG(SOCKET_LOG_WARNING, "UDP send buffer full (non-blocking mode)");
            rte_free(ol->data);
            rte_free(ol);
            errno = EAGAIN;
            return SOCKET_ERROR_SEND;
        }

        // 等待发送缓冲区可用
        pthread_mutex_lock(&udp_ctx->mutex);
        while (rte_ring_full(udp_ctx->sndbuf)) {
            if (non_blocking) {
                pthread_mutex_unlock(&udp_ctx->mutex);
                rte_free(ol->data);
                rte_free(ol);
                errno = EAGAIN;
                return SOCKET_ERROR_SEND;
            }
            
            // 检查超时
            struct timespec current_time;
            clock_gettime(CLOCK_MONOTONIC, &current_time);
            if (current_time.tv_sec - start_time.tv_sec >= g_config.timeout_sec) {
                pthread_mutex_unlock(&udp_ctx->mutex);
                rte_free(ol->data);
                rte_free(ol);
                SOCKET_LOG(SOCKET_LOG_WARNING, "Send operation timed out after %d seconds", g_config.timeout_sec);
                errno = ETIMEDOUT;
                return SOCKET_ERROR_TIMEOUT;
            }
            
            // 等待条件变量
            struct timespec wait_time = {0, 100000000}; // 100ms
            pthread_cond_timedwait(&udp_ctx->cond, &udp_ctx->mutex, &wait_time);
        }

        // 入队列
        if (rte_ring_mp_enqueue(udp_ctx->sndbuf, ol) < 0) {
            pthread_mutex_unlock(&udp_ctx->mutex);
            SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to enqueue UDP data");
            rte_free(ol->data);
            rte_free(ol);
            errno = ENOSPC;
            return SOCKET_ERROR_SEND;
        }
        
        pthread_mutex_unlock(&udp_ctx->mutex);
        SOCKET_LOG(SOCKET_LOG_INFO, "Successfully sent %zu bytes on UDP socket fd=%d", len, sockfd);
        return len;
        
    } else if (((struct ng_tcp_stream*)ctx)->protocol == IPPROTO_TCP) {
        struct ng_tcp_stream *stream = (struct ng_tcp_stream*)ctx;
        
        // 检查TCP状态
        if (stream->status != NG_TCP_STATUS_ESTABLISHED) {
            SOCKET_LOG(SOCKET_LOG_ERROR, "TCP socket not in established state");
            errno = ENOTCONN;
            return SOCKET_ERROR_INVALID;
        }

        // 创建TCP分片
        struct ng_tcp_fragment *frag = rte_malloc("tcp_frag", sizeof(struct ng_tcp_fragment), 0);
        if (!frag) {
            SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to allocate TCP fragment");
            errno = ENOMEM;
            return SOCKET_ERROR_NOMEM;
        }

        // 分配数据缓冲区
        frag->data = rte_malloc("payload", len, 0);
        if (!frag->data) {
            SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to allocate TCP payload buffer");
            rte_free(frag);
            errno = ENOMEM;
            return SOCKET_ERROR_NOMEM;
        }

        // 初始化分片结构
        frag->length = len;
        rte_memcpy(frag->data, buf, len);
        
        // 非阻塞模式检查
        if (non_blocking && rte_ring_full(stream->sndbuf)) {
            SOCKET_LOG(SOCKET_LOG_WARNING, "TCP send buffer full (non-blocking mode)");
            rte_free(frag->data);
            rte_free(frag);
            errno = EAGAIN;
            return SOCKET_ERROR_SEND;
        }

        // 等待发送缓冲区可用
        pthread_mutex_lock(&stream->mutex);
        while (rte_ring_full(stream->sndbuf)) {
            if (non_blocking) {
                pthread_mutex_unlock(&stream->mutex);
                rte_free(frag->data);
                rte_free(frag);
                errno = EAGAIN;
                return SOCKET_ERROR_SEND;
            }
            
            // 检查超时
            struct timespec current_time;
            clock_gettime(CLOCK_MONOTONIC, &current_time);
            if (current_time.tv_sec - start_time.tv_sec >= g_config.timeout_sec) {
                pthread_mutex_unlock(&stream->mutex);
                rte_free(frag->data);
                rte_free(frag);
                SOCKET_LOG(SOCKET_LOG_WARNING, "Send operation timed out after %d seconds", g_config.timeout_sec);
                errno = ETIMEDOUT;
                return SOCKET_ERROR_TIMEOUT;
            }
            
            // 等待条件变量
            struct timespec wait_time = {0, 100000000}; // 100ms
            pthread_cond_timedwait(&stream->cond, &stream->mutex, &wait_time);
        }

        // 入队列
        if (rte_ring_mp_enqueue(stream->sndbuf, frag) < 0) {
            pthread_mutex_unlock(&stream->mutex);
            SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to enqueue TCP data");
            rte_free(frag->data);
            rte_free(frag);
            errno = ENOSPC;
            return SOCKET_ERROR_SEND;
        }
        
        pthread_mutex_unlock(&stream->mutex);
        SOCKET_LOG(SOCKET_LOG_INFO, "Successfully sent %zu bytes on TCP socket fd=%d", len, sockfd);
        return len;
    }

    SOCKET_LOG(SOCKET_LOG_ERROR, "Invalid protocol");
    errno = EINVAL;
    return SOCKET_ERROR_INVALID;
}

/**
 * @brief 接收数据
 */
ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    SOCKET_LOG(SOCKET_LOG_DEBUG, "Receiving data on socket fd=%d, max_len=%zu, flags=0x%x", sockfd, len, flags);

    // 1. 参数验证
    if (!buf || len == 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Invalid buffer or length");
        errno = EINVAL;
        return SOCKET_ERROR_INVALID;
    }

    // 2. 获取上下文
    void *ctx = get_context(sockfd);
    if (!ctx) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Invalid socket descriptor: fd=%d", sockfd);
        errno = EBADF;
        return SOCKET_ERROR_INVALID;
    }

    // 3. 确定阻塞模式
    int non_blocking = 0;
    if (((struct localhost*)ctx)->protocol == IPPROTO_UDP) {
        struct localhost *udp_ctx = (struct localhost*)ctx;
        non_blocking = udp_ctx->non_blocking || (flags & MSG_DONTWAIT);
    } else {
        struct ng_tcp_stream *tcp_ctx = (struct ng_tcp_stream*)ctx;
        non_blocking = tcp_ctx->non_blocking || (flags & MSG_DONTWAIT);
    }

    // 4. 记录开始时间(用于超时控制)
    struct timespec start_time;
    if (!non_blocking) {
        clock_gettime(CLOCK_MONOTONIC, &start_time);
    }

    // 5. 根据协议类型处理
    if (((struct localhost*)ctx)->protocol == IPPROTO_UDP) {
        struct localhost *udp_ctx = (struct localhost*)ctx;
        struct offload *ol = NULL;
        
        // 非阻塞模式立即检查
        if (non_blocking && rte_ring_empty(udp_ctx->rcvbuf)) {
            SOCKET_LOG(SOCKET_LOG_DEBUG, "No data available for UDP socket (non-blocking mode)");
            errno = EAGAIN;
            return SOCKET_ERROR_TIMEOUT;
        }

        // 等待数据到达
        pthread_mutex_lock(&udp_ctx->mutex);
        while (rte_ring_mc_dequeue(udp_ctx->rcvbuf, (void**)&ol) < 0) {
            if (non_blocking) {
                pthread_mutex_unlock(&udp_ctx->mutex);
                SOCKET_LOG(SOCKET_LOG_DEBUG, "No data available for UDP socket");
                errno = EAGAIN;
                return SOCKET_ERROR_TIMEOUT;
            }
            
            // 检查超时
            struct timespec current_time;
            clock_gettime(CLOCK_MONOTONIC, &current_time);
            if (current_time.tv_sec - start_time.tv_sec >= g_config.timeout_sec) {
                pthread_mutex_unlock(&udp_ctx->mutex);
                SOCKET_LOG(SOCKET_LOG_WARNING, "Receive operation timed out after %d seconds", g_config.timeout_sec);
                errno = ETIMEDOUT;
                return SOCKET_ERROR_TIMEOUT;
            }
            
            // 等待条件变量
            struct timespec wait_time = {0, 100000000}; // 100ms
            pthread_cond_timedwait(&udp_ctx->cond, &udp_ctx->mutex, &wait_time);
        }

        // 复制数据
        size_t copy_len = (ol->length > len) ? len : ol->length;
        rte_memcpy(buf, ol->data, copy_len);
        
        // 清理资源
        rte_free(ol->data);
        rte_free(ol);
        
        pthread_mutex_unlock(&udp_ctx->mutex);
        SOCKET_LOG(SOCKET_LOG_INFO, "Successfully received %zu bytes on UDP socket fd=%d", copy_len, sockfd);
        return copy_len;
        
    } else if (((struct ng_tcp_stream*)ctx)->protocol == IPPROTO_TCP) {
        struct ng_tcp_stream *stream = (struct ng_tcp_stream*)ctx;
        struct ng_tcp_fragment *frag = NULL;
        
        // TCP连接状态检查
        if (stream->status != NG_TCP_STATUS_ESTABLISHED) {
            SOCKET_LOG(SOCKET_LOG_ERROR, "TCP socket not in established state");
            errno = ENOTCONN;
            return SOCKET_ERROR_INVALID;
        }

        // 非阻塞模式立即检查
        if (non_blocking && rte_ring_empty(stream->rcvbuf)) {
            SOCKET_LOG(SOCKET_LOG_DEBUG, "No data available for TCP socket (non-blocking mode)");
            errno = EAGAIN;
            return SOCKET_ERROR_TIMEOUT;
        }

        // 等待数据到达
        pthread_mutex_lock(&stream->mutex);
        while (rte_ring_mc_dequeue(stream->rcvbuf, (void**)&frag) < 0) {
            if (non_blocking) {
                pthread_mutex_unlock(&stream->mutex);
                SOCKET_LOG(SOCKET_LOG_DEBUG, "No data available for TCP socket");
                errno = EAGAIN;
                return SOCKET_ERROR_TIMEOUT;
            }

            // 检查超时
            struct timespec current_time;
            clock_gettime(CLOCK_MONOTONIC, &current_time);
            if (current_time.tv_sec - start_time.tv_sec >= g_config.timeout_sec) {
                pthread_mutex_unlock(&stream->mutex);
                SOCKET_LOG(SOCKET_LOG_WARNING, "Receive operation timed out after %d seconds", g_config.timeout_sec);
                errno = ETIMEDOUT;
                return SOCKET_ERROR_TIMEOUT;
            }
            
            // 等待条件变量
            struct timespec wait_time = {0, 100000000}; // 100ms
            pthread_cond_timedwait(&stream->cond, &stream->mutex, &wait_time);
        }

        // 复制数据
        size_t copy_len = (frag->length > len) ? len : frag->length;
        rte_memcpy(buf, frag->data, copy_len);
        
        // 清理资源
        rte_free(frag->data);
        rte_free(frag);
        
        pthread_mutex_unlock(&stream->mutex);
        SOCKET_LOG(SOCKET_LOG_INFO, "Successfully received %zu bytes on TCP socket fd=%d", copy_len, sockfd);
        return copy_len;
    }

    SOCKET_LOG(SOCKET_LOG_ERROR, "Invalid protocol");
    errno = EINVAL;
    return SOCKET_ERROR_INVALID;
}

/**
 * @brief 关闭套接字
 */
int close(int sockfd) {
    SOCKET_LOG(SOCKET_LOG_DEBUG, "Closing socket fd=%d", sockfd);

    // 1. 获取上下文
    void *ctx = get_context(sockfd);
    if (!ctx) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Invalid socket descriptor: fd=%d", sockfd);
        errno = EBADF;
        return SOCKET_ERROR_INVALID;
    }

    // 2. 根据协议类型清理资源
    if (((struct localhost*)ctx)->protocol == IPPROTO_UDP) {
        struct localhost *udp_ctx = (struct localhost*)ctx;
        
        // 从全局列表中移除
        LL_REMOVE(udp_ctx, lhost);
        
        // 清理环形缓冲区
        if (udp_ctx->sndbuf) {
            pthread_mutex_lock(&udp_ctx->mutex);
            while (!rte_ring_empty(udp_ctx->sndbuf)) {
                void *msg;
                if (rte_ring_dequeue(udp_ctx->sndbuf, &msg) == 0) {
                    struct offload *ol = (struct offload *)msg;
                    if (ol->data) rte_free(ol->data);
                    rte_free(ol);
                }
            }
            pthread_mutex_unlock(&udp_ctx->mutex);
            rte_ring_free(udp_ctx->sndbuf);
        }
        
        if (udp_ctx->rcvbuf) {
            pthread_mutex_lock(&udp_ctx->mutex);
            while (!rte_ring_empty(udp_ctx->rcvbuf)) {
                void *msg;
                if (rte_ring_dequeue(udp_ctx->rcvbuf, &msg) == 0) {
                    struct offload *ol = (struct offload *)msg;
                    if (ol->data) rte_free(ol->data);
                    rte_free(ol);
                }
            }
            pthread_mutex_unlock(&udp_ctx->mutex);
            rte_ring_free(udp_ctx->rcvbuf);
        }
        
        // 销毁同步原语
        pthread_mutex_destroy(&udp_ctx->mutex);
        pthread_cond_destroy(&udp_ctx->cond);
        
        // 释放上下文
        rte_free(udp_ctx);
        SOCKET_LOG(SOCKET_LOG_INFO, "UDP socket fd=%d closed successfully", sockfd);
        
    } else if (((struct ng_tcp_stream*)ctx)->protocol == IPPROTO_TCP) {
        struct ng_tcp_stream *stream = (struct ng_tcp_stream*)ctx;
        
        // 从TCP表中移除
        struct ng_tcp_table *table = tcp_table_instance();
        LL_REMOVE(stream, table->tcb_set);
        
        // 清理环形缓冲区
        if (stream->sndbuf) {
            pthread_mutex_lock(&stream->mutex);
            while (!rte_ring_empty(stream->sndbuf)) {
                void *msg;
                if (rte_ring_dequeue(stream->sndbuf, &msg) == 0) {
                    struct ng_tcp_fragment *frag = (struct ng_tcp_fragment *)msg;
                    if (frag->data) rte_free(frag->data);
                    rte_free(frag);
                }
            }
            pthread_mutex_unlock(&stream->mutex);
            rte_ring_free(stream->sndbuf);
        }
        
        if (stream->rcvbuf) {
            pthread_mutex_lock(&stream->mutex);
            while (!rte_ring_empty(stream->rcvbuf)) {
                void *msg;
                if (rte_ring_dequeue(stream->rcvbuf, &msg) == 0) {
                    struct ng_tcp_fragment *frag = (struct ng_tcp_fragment *)msg;
                    if (frag->data) rte_free(frag->data);
                    rte_free(frag);
                }
            }
            pthread_mutex_unlock(&stream->mutex);
            rte_ring_free(stream->rcvbuf);
        }
        
        // 销毁同步原语
        pthread_mutex_destroy(&stream->mutex);
        pthread_cond_destroy(&stream->cond);
        
        // 释放上下文
        rte_free(stream);
        SOCKET_LOG(SOCKET_LOG_INFO, "TCP socket fd=%d closed successfully", sockfd);
    }

    // 3. 释放文件描述符
    release_fd(sockfd);
    return SOCKET_SUCCESS;
}

//--------------------------------- Initialization 实现 ---------------------------------//
/**
 * @brief 初始化DPDK环境
 */
static int init_dpdk(void) {
    char *argv[] = {
        "socket_app",
        "-l", "0-1",        // 使用CPU核心0-1
        "-n", "4",          // 设置内存通道数
        "--proc-type=auto", // 自动设置进程类型
        NULL
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    
    // 初始化EAL
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Error with EAL init: %s", rte_strerror(rte_errno));
        return SOCKET_ERROR_INVALID;
    }

    // 创建内存池
    unsigned cache_size = 256;
    g_mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", 
                                         NUM_MBUFS,
                                         cache_size,
                                         0,  // private data size
                                         RTE_MBUF_DEFAULT_BUF_SIZE,
                                         rte_socket_id());
    if (!g_mbuf_pool) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Could not create mbuf pool: %s", rte_strerror(rte_errno));
        rte_eal_cleanup();
        return SOCKET_ERROR_NOMEM;
    }

    // 初始化环形缓冲区
    if (init_rings() != 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to initialize rings");
        rte_mempool_free(g_mbuf_pool);
        rte_eal_cleanup();
        return SOCKET_ERROR_NOMEM;
    }

    // 检查可用端口
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "No supported ports found");
        rte_mempool_free(g_mbuf_pool);
        rte_ring_free(g_ring->in);
        rte_ring_free(g_ring->out);
        rte_free(g_ring);
        rte_eal_cleanup();
        return SOCKET_ERROR_INVALID;
    }
    
    // 获取MAC地址
    ret = rte_eth_macaddr_get(0, (struct rte_ether_addr *)g_src_mac);
    if (ret < 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to get MAC address: %s", rte_strerror(-ret));
        rte_mempool_free(g_mbuf_pool);
        rte_ring_free(g_ring->in);
        rte_ring_free(g_ring->out);
        rte_free(g_ring);
        rte_eal_cleanup();
        return SOCKET_ERROR_INVALID;
    }
    
    // 配置端口
    // TODO: 这里只有单端口，需要修改
    struct rte_eth_conf port_conf = {0};
    ret = rte_eth_dev_configure(0, 1, 1, &port_conf);
    if (ret < 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Port configuration failed: %s", rte_strerror(-ret));
        rte_mempool_free(g_mbuf_pool);
        rte_ring_free(g_ring->in);
        rte_ring_free(g_ring->out);
        rte_free(g_ring);
        rte_eal_cleanup();
        return SOCKET_ERROR_INVALID;
    }

    // 设置接收队列
    ret = rte_eth_rx_queue_setup(0, 0, 1024, 
                                rte_eth_dev_socket_id(0), 
                                NULL, 
                                g_mbuf_pool);
    if (ret < 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "RX queue setup failed: %s", rte_strerror(-ret));
        rte_eth_dev_close(0);
        rte_mempool_free(g_mbuf_pool);
        rte_ring_free(g_ring->in);
        rte_ring_free(g_ring->out);
        rte_free(g_ring);
        rte_eal_cleanup();
        return SOCKET_ERROR_INVALID;
    }

    // 设置发送队列
    ret = rte_eth_tx_queue_setup(0, 0, 1024, 
                                rte_eth_dev_socket_id(0), 
                                NULL);
    if (ret < 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "TX queue setup failed: %s", rte_strerror(-ret));
        rte_eth_dev_close(0);
        rte_mempool_free(g_mbuf_pool);
        rte_ring_free(g_ring->in);
        rte_ring_free(g_ring->out);
        rte_free(g_ring);
        rte_eal_cleanup();
        return SOCKET_ERROR_INVALID;
    }

    // 启动端口
    ret = rte_eth_dev_start(0);
    if (ret < 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Port start failed: %s", rte_strerror(-ret));
        rte_eth_dev_close(0);
        rte_mempool_free(g_mbuf_pool);
        rte_ring_free(g_ring->in);
        rte_ring_free(g_ring->out);
        rte_free(g_ring);
        rte_eal_cleanup();
        return SOCKET_ERROR_INVALID;
    }

    return SOCKET_SUCCESS;
}

/**
 * @brief 初始化ring缓冲区
 */
static int init_rings(void) {
    // 分配ring结构内存
    g_ring = rte_malloc("inout_ring", sizeof(struct inout_ring), 0);
    if (!g_ring) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to allocate memory for ring structure: %s", 
                  rte_strerror(rte_errno));
        return SOCKET_ERROR_NOMEM;
    }

    // 初始化为NULL,防止清理时出错
    g_ring->in = NULL;
    g_ring->out = NULL;

    // 创建入口ring
    g_ring->in = rte_ring_create("in_ring", 
                                RING_SIZE,
                                rte_socket_id(),
                                RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!g_ring->in) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to create input ring: %s", 
                  rte_strerror(rte_errno));
        rte_free(g_ring);
        g_ring = NULL;
        return SOCKET_ERROR_NOMEM;
    }

    // 创建出口ring
    g_ring->out = rte_ring_create("out_ring",
                                 RING_SIZE,
                                 rte_socket_id(),
                                 RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!g_ring->out) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to create output ring: %s", 
                  rte_strerror(rte_errno));
        rte_ring_free(g_ring->in);
        rte_free(g_ring);
        g_ring = NULL;
        return SOCKET_ERROR_NOMEM;
    }

    SOCKET_LOG(SOCKET_LOG_INFO, "Ring buffers initialized successfully");
    return SOCKET_SUCCESS;
}

/**
 * @brief 修改后的socket_init函数
 */
int socket_init(void) {
    int ret;

    // 初始化配置互斥锁
    if (pthread_mutex_init(&g_config_mutex, NULL) != 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to initialize config mutex");
        return SOCKET_ERROR_INVALID;
    }
    
    // 初始化日志系统
    openlog("SOCKET", LOG_PID | LOG_CONS | LOG_PERROR, LOG_USER);
    setlogmask(LOG_UPTO(g_config.log_level));
    
    // 初始化DPDK环境
    ret = init_dpdk();
    if (ret != SOCKET_SUCCESS) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to initialize DPDK");
        pthread_mutex_destroy(&g_config_mutex);
        closelog();
        return ret;
    }

    // 初始化线程运行状态
    g_thread_running = 1;

    // 获取可用的逻辑核心
    unsigned lcore_rx = rte_get_next_lcore(-1, 1, 0);  // 获取第一个可用核心
    unsigned lcore_tx = rte_get_next_lcore(lcore_rx, 1, 0);  // 获取第二个可用核心

    if (lcore_rx == RTE_MAX_LCORE || lcore_tx == RTE_MAX_LCORE) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Not enough CPU cores available");
        socket_cleanup();
        return SOCKET_ERROR_INVALID;
    }

    // 在指定核心上启动接收线程
    ret = rte_eal_remote_launch((lcore_function_t *)rx_thread, NULL, lcore_rx);
    if (ret < 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to launch RX thread on core %u: %s", 
                  lcore_rx, rte_strerror(-ret));
        socket_cleanup();
        return SOCKET_ERROR_INVALID;
    }

    // 在指定核心上启动发送线程
    ret = rte_eal_remote_launch((lcore_function_t *)tx_thread, NULL, lcore_tx);
    if (ret < 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to launch TX thread on core %u: %s", 
                  lcore_tx, rte_strerror(-ret));
        g_thread_running = 0;  // 通知RX线程退出
        rte_eal_wait_lcore(lcore_rx);  // 等待RX线程退出
        socket_cleanup();
        return SOCKET_ERROR_INVALID;
    }

    SOCKET_LOG(SOCKET_LOG_INFO, "Socket initialization completed successfully (RX on core %u, TX on core %u)", 
               lcore_rx, lcore_tx);
    return SOCKET_SUCCESS;
}

/**
 * @brief 接收线程函数
 */
static int rx_thread(__rte_unused void *arg) {
    SOCKET_LOG(SOCKET_LOG_INFO, "RX thread starting on core %u", rte_lcore_id());
    
    struct rte_mbuf *rx_bufs[BURST_SIZE];
    uint16_t nb_rx;
    uint64_t prev_tsc = 0, cur_tsc, diff_tsc;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + 1000000ULL - 1) / 1000000ULL * 100; // ~100us

    while (g_thread_running) {
        // 检查是否需要处理超时事件
        cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {
            // 处理超时事件
            // TODO: 实现超时处理逻辑
            prev_tsc = cur_tsc;
        }

        // 从网卡接收数据包
        nb_rx = rte_eth_rx_burst(0, 0, rx_bufs, BURST_SIZE);
        if (unlikely(nb_rx > BURST_SIZE)) {
            SOCKET_LOG(SOCKET_LOG_ERROR, "Error receiving from eth: received %u packets", nb_rx);
            continue;
        }

        if (likely(nb_rx > 0)) {
            // 将数据包放入接收环形缓冲区
            uint16_t nb_enqueued = rte_ring_sp_enqueue_burst(g_ring->in, 
                                                            (void **)rx_bufs,
                                                            nb_rx,
                                                            NULL);
            
            // 如果有未能入队的数据包,释放它们
            if (unlikely(nb_enqueued < nb_rx)) {
                SOCKET_LOG(SOCKET_LOG_WARNING, "Failed to enqueue %u packets", nb_rx - nb_enqueued);
                for (uint16_t i = nb_enqueued; i < nb_rx; i++) {
                    rte_pktmbuf_free(rx_bufs[i]);
                }
            }
        }
    }

    SOCKET_LOG(SOCKET_LOG_INFO, "RX thread exiting from core %u", rte_lcore_id());
    return 0;
}

/**
 * @brief 发送线程函数
 */
static int tx_thread(__rte_unused void *arg) {
    SOCKET_LOG(SOCKET_LOG_INFO, "TX thread starting on core %u", rte_lcore_id());
    
    struct rte_mbuf *tx_bufs[BURST_SIZE];
    uint16_t nb_tx, nb_dequeued;
    uint64_t prev_tsc = 0, cur_tsc, diff_tsc;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + 1000000ULL - 1) / 1000000ULL * 100; // ~100us
    
    // 发送统计
    uint64_t total_tx = 0;
    uint64_t total_dropped = 0;

    while (g_thread_running) {
        // 检查是否需要处理超时事件
        cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {
            // 输出统计信息
            if (total_tx > 0 || total_dropped > 0) {
                SOCKET_LOG(SOCKET_LOG_DEBUG, "TX stats: sent=%lu dropped=%lu", 
                          total_tx, total_dropped);
            }
            prev_tsc = cur_tsc;
        }

        // 从发送环形缓冲区获取数据包
        nb_dequeued = rte_ring_sc_dequeue_burst(g_ring->out,
                                               (void **)tx_bufs,
                                               BURST_SIZE,
                                               NULL);
        if (likely(nb_dequeued > 0)) {
            // 发送数据包
            nb_tx = rte_eth_tx_burst(0, 0, tx_bufs, nb_dequeued);
            
            // 更新统计信息
            total_tx += nb_tx;
            
            // 如果有未能发送的数据包,释放它们
            if (unlikely(nb_tx < nb_dequeued)) {
                total_dropped += (nb_dequeued - nb_tx);
                SOCKET_LOG(SOCKET_LOG_WARNING, "Failed to send %u packets", nb_dequeued - nb_tx);
                for (uint16_t i = nb_tx; i < nb_dequeued; i++) {
                    rte_pktmbuf_free(tx_bufs[i]);
                }
            }
        }
    }

    SOCKET_LOG(SOCKET_LOG_INFO, "TX thread exiting from core %u (total sent=%lu dropped=%lu)", 
               rte_lcore_id(), total_tx, total_dropped);
    return 0;
}

/**
 * @brief 清理socket模块所有资源
 */
void socket_cleanup(void) {
    SOCKET_LOG(SOCKET_LOG_INFO, "Starting socket cleanup...");

    // 1. 首先通知线程退出
    SOCKET_LOG(SOCKET_LOG_DEBUG, "Stopping threads...");
    g_thread_running = 0;

    // 等待所有线程完成
    unsigned int lcore_id;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0) {
            SOCKET_LOG(SOCKET_LOG_WARNING, "Failed to stop thread on core %u", lcore_id);
        }
    }
    SOCKET_LOG(SOCKET_LOG_INFO, "All threads stopped");

    // 2. 关闭所有打开的套接字
    SOCKET_LOG(SOCKET_LOG_DEBUG, "Closing open sockets...");
    pthread_mutex_lock(&g_config_mutex);
    for (int fd = 3; fd < g_config.max_fds; fd++) {
        int byte = fd / 8;
        int bit = fd % 8;
        if (fd_bitmap[byte] & (1 << bit)) {
            close(fd);
        }
    }
    pthread_mutex_unlock(&g_config_mutex);

    // 3. 停止和关闭网络端口
    SOCKET_LOG(SOCKET_LOG_DEBUG, "Stopping network port...");
    rte_eth_dev_stop(0);
    rte_eth_dev_close(0);

    // 4. 清理ring资源
    SOCKET_LOG(SOCKET_LOG_DEBUG, "Cleaning up ring resources...");
    if (g_ring != NULL) {
        if (g_ring->in != NULL) {
            // 清空并释放入口ring
            void *msg;
            while (rte_ring_dequeue(g_ring->in, &msg) == 0) {
                rte_pktmbuf_free((struct rte_mbuf *)msg);
            }
            rte_ring_free(g_ring->in);
        }
        
        if (g_ring->out != NULL) {
            // 清空并释放出口ring
            void *msg;
            while (rte_ring_dequeue(g_ring->out, &msg) == 0) {
                rte_pktmbuf_free((struct rte_mbuf *)msg);
            }
            rte_ring_free(g_ring->out);
        }
        
        rte_free(g_ring);
        g_ring = NULL;
    }

    // 5. 释放内存池
    SOCKET_LOG(SOCKET_LOG_DEBUG, "Freeing memory pool...");
    if (g_mbuf_pool != NULL) {
        rte_mempool_free(g_mbuf_pool);
        g_mbuf_pool = NULL;
    }

    // 6. 清理基础设施
    SOCKET_LOG(SOCKET_LOG_DEBUG, "Cleaning up basic infrastructure...");
    pthread_mutex_destroy(&g_config_mutex);
    
    // 7. 最后清理DPDK环境
    SOCKET_LOG(SOCKET_LOG_DEBUG, "Cleaning up DPDK environment...");
    rte_eal_cleanup();

    // 8. 关闭日志系统
    SOCKET_LOG(SOCKET_LOG_INFO, "Socket module cleanup completed");
    closelog();
}

//----------------------------- API包装函数实现 ---------------------------------//
int edrp_socket(int domain, int type, int protocol) {
    return socket(domain, type, protocol);
}

int edrp_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    return bind(sockfd, addr, addrlen);
}

int edrp_listen(int sockfd, int backlog) {
    return listen(sockfd, backlog);
}

int edrp_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    return accept(sockfd, addr, addrlen);
}

ssize_t edrp_send(int sockfd, const void *buf, size_t len, int flags) {
    return send(sockfd, buf, len, flags);
}

ssize_t edrp_recv(int sockfd, void *buf, size_t len, int flags) {
    return recv(sockfd, buf, len, flags);
}

int edrp_close(int sockfd) {
    return close(sockfd);
}

int edrp_init(void) {
    return socket_init();
}

void edrp_cleanup(void) {
    socket_cleanup();
}

int edrp_set_config(const struct edrp_config *config) {
    struct socket_config sock_config;
    sock_config.max_fds = config->max_fds;
    sock_config.ring_size = config->ring_size;
    sock_config.timeout_sec = config->timeout_sec;
    sock_config.log_level = config->log_level;
    return socket_set_config(&sock_config);
}

int edrp_get_config(struct edrp_config *config) {
    struct socket_config sock_config;
    int ret = socket_get_config(&sock_config);
    if (ret == 0) {
        config->max_fds = sock_config.max_fds;
        config->ring_size = sock_config.ring_size;
        config->timeout_sec = sock_config.timeout_sec;
        config->log_level = sock_config.log_level;
    }
    return ret;
}

void edrp_get_stats(struct edrp_stats *stats) {
    struct socket_statistics sock_stats;
    socket_stats(&sock_stats);
    stats->total_fds = sock_stats.total_fds;
    stats->used_fds = sock_stats.used_fds;
    stats->udp_sockets = sock_stats.udp_sockets;
    stats->tcp_sockets = sock_stats.tcp_sockets;
    stats->bytes_sent = sock_stats.bytes_sent;
    stats->bytes_received = sock_stats.bytes_received;
}

void edrp_set_log_level(int level) {
    socket_set_log_level(level);
}

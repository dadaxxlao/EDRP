#ifndef __NG_SOCKET_H__
#define __NG_SOCKET_H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <errno.h>
#include <syslog.h>
#include <rte_ether.h>
#include <rte_ring.h>
#include <rte_mempool.h>

// 添加IP地址转换宏
#define MAKE_IPV4_ADDR(a, b, c, d) \
    (((uint32_t)a) | (((uint32_t)b) << 8) | \
    (((uint32_t)c) << 16) | (((uint32_t)d) << 24))

#define SOCKET_LOG_ERROR    0
#define SOCKET_LOG_WARNING  1
#define SOCKET_LOG_INFO     2
#define SOCKET_LOG_DEBUG    3

// 套接字类型定义
#define SOCKET_TYPE_UDP 0
#define SOCKET_TYPE_TCP 1

// 错误码定义
#define SOCKET_SUCCESS           0   // 成功
#define SOCKET_ERROR_NOMEM      -1   // 内存不足
#define SOCKET_ERROR_INVALID    -2   // 无效参数
#define SOCKET_ERROR_INUSE      -3   // 资源已被使用
#define SOCKET_ERROR_TIMEOUT    -4   // 超时
#define SOCKET_ERROR_BIND       -5   // 绑定失败
#define SOCKET_ERROR_SEND       -6   // 发送失败

// 添加配置参数
#define SOCKET_MAX_FD        1024
#define SOCKET_RING_SIZE     1024
#define SOCKET_TIMEOUT_SEC   30

// 在header文件中添加颜色定义
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_RESET   "\x1b[0m"

// 重新定义SOCKET_LOG宏
#define SOCKET_LOG(level, fmt, ...) do { \
    switch(level) { \
        case SOCKET_LOG_ERROR: \
            syslog(LOG_ERR, ANSI_COLOR_RED "[SOCKET][ERROR][%s:%d] " fmt ANSI_COLOR_RESET, \
                   __FILE__, __LINE__, ##__VA_ARGS__); \
            break; \
        case SOCKET_LOG_WARNING: \
            syslog(LOG_WARNING, ANSI_COLOR_YELLOW "[SOCKET][WARN][%s:%d] " fmt ANSI_COLOR_RESET, \
                   __FILE__, __LINE__, ##__VA_ARGS__); \
            break; \
        case SOCKET_LOG_INFO: \
            syslog(LOG_INFO, "[SOCKET][INFO][%s:%d] " fmt, \
                   __FILE__, __LINE__, ##__VA_ARGS__); \
            break; \
        case SOCKET_LOG_DEBUG: \
            syslog(LOG_DEBUG, ANSI_COLOR_BLUE "[SOCKET][DEBUG][%s:%d] " fmt ANSI_COLOR_RESET, \
                   __FILE__, __LINE__, ##__VA_ARGS__); \
            break; \
    } \
} while(0)


// DPDK Initialization 环形结构区
struct inout_ring {
    struct rte_ring *in;
    struct rte_ring *out;
};
extern struct inout_ring *g_ring;

// DPDK Initialization 源MAC地址和IP地址
extern uint8_t g_src_mac[RTE_ETHER_ADDR_LEN];
extern uint32_t g_local_ip;

// DPDK Initialization 内存池
extern struct rte_mempool *g_mbuf_pool;

// Socket配置
struct socket_config {
    int max_fds;
    int ring_size;
    int timeout_sec;
    int log_level;
};
extern struct socket_config g_config;

// 添加初始化状态标志
extern int g_socket_initialized;

/**
 * @brief 创建套接字
 * @param type 类型（SOCK_DGRAM或SOCK_STREAM）
 * @return 成功返回文件描述符，失败返回-1
 */
int socket(int domain, int type, int protocol);

/**
 * @brief 绑定套接字到本地地址
 */
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

/**
 * @brief 监听TCP连接请求
 */
int listen(int sockfd, int backlog);

/**
 * @brief 接受TCP连接请求
 */
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

/**
 * @brief 发送数据
 */
ssize_t send(int sockfd, const void *buf, size_t len, int flags);

/**
 * @brief 接收数据
 */
ssize_t recv(int sockfd, void *buf, size_t len, int flags);

/**
 * @brief 关闭套接字
 */
int close(int sockfd);

struct socket_statistics {
    int total_fds;
    int used_fds;
    int udp_sockets;
    int tcp_sockets;
    int64_t bytes_sent;
    int64_t bytes_received;
};



// 统计接口
void socket_stats(struct socket_statistics *stats);

/**
 * @brief 检查端口是否已被使用
 * @param port 要检查的端口号（网络字节序）
 * @return 如果端口已被使用返回1，否则返回0
 */
int check_port_in_use(uint16_t port);

// 初始化和清理接口
int socket_init(void);
int init_dpdk(void);
void socket_cleanup(void);

// 配置接口
int socket_set_config(const struct socket_config *config);
int socket_get_config(struct socket_config *config);
// 调试接口
void socket_set_log_level(int level);

#endif

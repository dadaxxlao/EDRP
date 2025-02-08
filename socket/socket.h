#ifndef __NG_SOCKET_H__
#define __NG_SOCKET_H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <errno.h>
#include <syslog.h>

// 套接字类型定义
#define SOCKET_TYPE_UDP 0
#define SOCKET_TYPE_TCP 1



// 添加日志级别定义
#define SOCKET_LOG_ERROR    0
#define SOCKET_LOG_WARNING  1
#define SOCKET_LOG_INFO     2
#define SOCKET_LOG_DEBUG    3

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

// 添加日志宏
#define SOCKET_LOG(level, fmt, ...) \
    syslog(level, "[SOCKET][%s:%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

// 确保SOCK_NONBLOCK有定义
#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 04000
#endif


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
void socket_cleanup(void);

// 配置接口
int socket_set_config(const struct socket_config *config);
int socket_get_config(struct socket_config *config);
// 调试接口
void socket_set_log_level(int level);

#endif

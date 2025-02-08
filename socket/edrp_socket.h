#ifndef __EDRP_SOCKET_H__
#define __EDRP_SOCKET_H__

#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

// Socket API
int edrp_socket(int domain, int type, int protocol);
int edrp_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int edrp_listen(int sockfd, int backlog);
int edrp_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t edrp_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t edrp_recv(int sockfd, void *buf, size_t len, int flags);
int edrp_close(int sockfd);

// 初始化和清理
int edrp_init(void);
void edrp_cleanup(void);

// 配置接口
struct edrp_config {
    int max_fds;        // 最大文件描述符数
    int ring_size;      // 环形缓冲区大小
    int timeout_sec;    // 超时时间(秒)
    int log_level;      // 日志级别
};

int edrp_set_config(const struct edrp_config *config);
int edrp_get_config(struct edrp_config *config);

// 统计信息
struct edrp_stats {
    int total_fds;          // 总文件描述符数
    int used_fds;          // 已使用的文件描述符数
    int udp_sockets;       // UDP套接字数
    int tcp_sockets;       // TCP套接字数
    int64_t bytes_sent;    // 发送字节数
    int64_t bytes_received;// 接收字节数
};

void edrp_get_stats(struct edrp_stats *stats);

// 日志级别
#define EDRP_LOG_ERROR    0
#define EDRP_LOG_WARNING  1
#define EDRP_LOG_INFO     2
#define EDRP_LOG_DEBUG    3

void edrp_set_log_level(int level);

#ifdef __cplusplus
}
#endif

#endif // __EDRP_SOCKET_H__ 
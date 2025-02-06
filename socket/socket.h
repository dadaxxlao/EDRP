#ifndef __NG_SOCKET_H__
#define __NG_SOCKET_H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

// 套接字类型定义
#define SOCKET_TYPE_UDP 0
#define SOCKET_TYPE_TCP 1

// 错误码定义
#define SOCKET_ERR_INVALID_FD    -1
#define SOCKET_ERR_BIND_FAILED   -2
#define SOCKET_ERR_SEND_FAILED   -3

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

#endif

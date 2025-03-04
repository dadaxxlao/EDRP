#ifndef MYLIB_CORE_H
#define MYLIB_CORE_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "ex_logging.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 不透明指针类型定义 */
typedef struct mylib_socket* socket_handle_t;
typedef struct mylib_config* config_handle_t;

/* 错误码定义 */
typedef enum {
    MYLIB_SUCCESS = 0,
    MYLIB_ERROR_NOMEM = -1,
    MYLIB_ERROR_INVALID = -2,
    MYLIB_ERROR_INUSE = -3,
    MYLIB_ERROR_TIMEOUT = -4,
    MYLIB_ERROR_BIND = -5,
    MYLIB_ERROR_SEND = -6,
    MYLIB_ERROR_IO = -7
} mylib_error_t;

/* 配置选项 */
typedef struct {
    int max_fds;
    int ring_size;
    int timeout_sec;
    int log_level;
    struct {                    //TODO: 先只考虑单端口
        uint32_t ip_addr;      // 本机IP地址
        uint16_t port_range_start;  // 端口范围起始
        uint16_t port_range_end;    // 端口范围结束
        uint32_t netmask;      // 子网掩码
        uint32_t gateway;      // 网关地址
    } network_config;
} mylib_config_t;


/* 统计信息 */
typedef struct {
    int total_fds;
    int used_fds;
    int64_t bytes_sent;
    int64_t bytes_received;
} mylib_stats_t;

/* 初始化函数 */
mylib_error_t mylib_init(const mylib_config_t* config);

/* 清理函数 */
void mylib_cleanup(void);

/* Socket API */
socket_handle_t mylib_socket(int domain, int type, int protocol);
mylib_error_t mylib_bind(socket_handle_t sock, const struct sockaddr* addr, socklen_t addrlen);
mylib_error_t mylib_listen(socket_handle_t sock, int backlog);
mylib_error_t mylib_connect(socket_handle_t handle, const struct sockaddr* addr, socklen_t addrlen);
socket_handle_t mylib_accept(socket_handle_t sock, struct sockaddr* addr, socklen_t* addrlen);
ssize_t mylib_send(socket_handle_t sock, const void* buf, size_t len, int flags);
ssize_t mylib_recv(socket_handle_t sock, void* buf, size_t len, int flags);
ssize_t mylib_sendto(socket_handle_t sock, const void* buf, size_t len, int flags,
                     const struct sockaddr* dest_addr, socklen_t addrlen);
ssize_t mylib_recvfrom(socket_handle_t sock, void* buf, size_t len, int flags,
                       struct sockaddr* src_addr, socklen_t* addrlen);
mylib_error_t mylib_close(socket_handle_t sock);

/* 配置管理 */
config_handle_t mylib_config_create(void);
mylib_error_t mylib_config_set(config_handle_t cfg, const mylib_config_t* config);
mylib_error_t mylib_config_get(config_handle_t cfg, mylib_config_t* config);
void mylib_config_destroy(config_handle_t cfg);

/* 统计信息 */
mylib_error_t mylib_get_stats(mylib_stats_t* stats);

/* 日志级别设置 */
void mylib_set_log_level(int level);

#ifdef __cplusplus
}
#endif

#endif /* MYLIB_CORE_H */ 
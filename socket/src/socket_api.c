#include <rte_malloc.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "internal/common.h"
#include "internal/logging.h"
#include "internal/tcp_impl.h"
#include "internal/udp_impl.h"

/* 全局变量声明 */
extern struct udp_control_block *g_ucb_list;
extern struct tcp_control_block *g_tcb_list;
extern pthread_mutex_t g_udp_mutex;
extern pthread_mutex_t g_tcp_mutex;

int check_port_in_use(uint16_t port) {
    int in_use = 0;
    
    /* 检查UDP端口 */
    pthread_mutex_lock(&g_udp_mutex);
    struct udp_control_block *ucb;
    for (ucb = g_ucb_list; ucb != NULL; ucb = ucb->next) {
        if (ucb->sock->local_port == port) {
            in_use = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_udp_mutex);
    
    if (in_use) return 1;
    
    /* 检查TCP端口 */
    pthread_mutex_lock(&g_tcp_mutex);
    struct tcp_control_block *tcb;
    for (tcb = g_tcb_list; tcb != NULL; tcb = tcb->next) {
        if (tcb->sock->local_port == port) {
            in_use = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_tcp_mutex);
    
    return in_use;
}

mylib_error_t mylib_bind(socket_handle_t handle, const struct sockaddr* addr, socklen_t addrlen) {
    struct mylib_socket *sock = (struct mylib_socket *)handle;
    
    if (!sock || !addr || addrlen < sizeof(struct sockaddr_in)) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Invalid parameters in bind");
        return MYLIB_ERROR_INVALID;
    }

    const struct sockaddr_in *saddr = (const struct sockaddr_in*)addr;
    
    /* 检查地址族 */
    if (saddr->sin_family != AF_INET) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Unsupported address family");
        return MYLIB_ERROR_INVALID;
    }

    /* 检查端口是否已被使用 */
    if (check_port_in_use(saddr->sin_port)) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Port %d already in use", ntohs(saddr->sin_port));
        return MYLIB_ERROR_INUSE;
    }

    /* 设置socket地址信息 */
    sock->local_ip = saddr->sin_addr.s_addr;
    sock->local_port = saddr->sin_port;

    /* 根据协议类型创建相应的控制块 */
    if (sock->protocol == IPPROTO_UDP) {
        struct udp_control_block *ucb = udp_create_ucb(sock);
        if (!ucb) {
            MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to create UDP control block");
            return MYLIB_ERROR_NOMEM;
        }
    } else if (sock->protocol == IPPROTO_TCP) {
        struct tcp_control_block *tcb = tcp_create_tcb(sock);
        if (!tcb) {
            MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to create TCP control block");
            return MYLIB_ERROR_NOMEM;
        }
    }

    MYLIB_LOG(LOG_LEVEL_INFO, "Socket bound to %s:%d", 
              inet_ntoa(saddr->sin_addr), ntohs(saddr->sin_port));
    return MYLIB_SUCCESS;
}

ssize_t mylib_sendto(socket_handle_t handle, const void* buf, size_t len, int flags,
                     const struct sockaddr* dest_addr, socklen_t addrlen) {
    struct mylib_socket *sock = (struct mylib_socket *)handle;
    
    if (!sock || !buf || !dest_addr || addrlen < sizeof(struct sockaddr_in)) {
        errno = EINVAL;
        return -1;
    }

    const struct sockaddr_in *daddr = (const struct sockaddr_in*)dest_addr;
    
    /* 检查地址族 */
    if (daddr->sin_family != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    /* 只支持UDP */
    if (sock->protocol != IPPROTO_UDP) {
        errno = EPROTOTYPE;
        return -1;
    }

    /* 获取UDP控制块 */
    struct udp_control_block *ucb = udp_find_ucb(sock->local_ip, sock->local_port);
    if (!ucb) {
        errno = ENOTCONN;
        return -1;
    }

    /* 设置目标地址 */
    ucb->remote_ip = daddr->sin_addr.s_addr;
    ucb->remote_port = daddr->sin_port;

    /* 将数据放入发送缓冲区 */
    void *data = rte_malloc("udp_data", len, 0);
    if (!data) {
        errno = ENOMEM;
        return -1;
    }
    rte_memcpy(data, buf, len);

    if (rte_ring_mp_enqueue(sock->send_buf, data) < 0) {
        rte_free(data);
        errno = EAGAIN;
        return -1;
    }

    /* 触发发送 */
    mylib_error_t ret = udp_output(ucb);
    if (ret != MYLIB_SUCCESS) {
        errno = EAGAIN;
        return -1;
    }

    return len;
}

ssize_t mylib_recvfrom(socket_handle_t handle, void* buf, size_t len, int flags,
                       struct sockaddr* src_addr, socklen_t* addrlen) {
    struct mylib_socket *sock = (struct mylib_socket *)handle;
    
    if (!sock || !buf) {
        errno = EINVAL;
        return -1;
    }

    /* 只支持UDP */
    if (sock->protocol != IPPROTO_UDP) {
        errno = EPROTOTYPE;
        return -1;
    }

    /* 获取UDP控制块 */
    struct udp_control_block *ucb = udp_find_ucb(sock->local_ip, sock->local_port);
    if (!ucb) {
        errno = ENOTCONN;
        return -1;
    }

    /* 从接收缓冲区获取数据 */
    void *data;
    if (rte_ring_mc_dequeue(sock->recv_buf, &data) < 0) {
        if (flags & MSG_DONTWAIT) {
            errno = EAGAIN;
            return -1;
        }

        /* 阻塞等待数据 */
        pthread_mutex_lock(&sock->mutex);
        while (rte_ring_mc_dequeue(sock->recv_buf, &data) < 0) {
            pthread_cond_wait(&sock->cond, &sock->mutex);
        }
        pthread_mutex_unlock(&sock->mutex);
    }

    /* 复制数据到用户缓冲区 */
    size_t data_len = strlen(data);  // TODO: 需要正确处理数据长度
    size_t copy_len = (data_len < len) ? data_len : len;
    rte_memcpy(buf, data, copy_len);

    /* 如果提供了源地址参数，填充源地址信息 */
    if (src_addr && addrlen && *addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in *saddr = (struct sockaddr_in*)src_addr;
        saddr->sin_family = AF_INET;
        saddr->sin_addr.s_addr = ucb->remote_ip;
        //saddr->sin_addr.s_addr = htonl(ucb->remote_ip);  // 添加htonl()转换
        saddr->sin_port = ucb->remote_port;
        *addrlen = sizeof(struct sockaddr_in);
    }

    rte_free(data);
    return copy_len;
}

mylib_error_t mylib_listen(socket_handle_t handle, int backlog) {
    struct mylib_socket *sock = (struct mylib_socket *)handle;
    
    if (!sock) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Invalid socket handle");
        return MYLIB_ERROR_INVALID;
    }

    /* 只支持TCP */
    if (sock->protocol != IPPROTO_TCP) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Protocol not supported for listen");
        return MYLIB_ERROR_INVALID;
    }

    /* 获取TCP控制块 */
    struct tcp_control_block *tcb = tcp_find_tcb(sock->local_ip, sock->local_port);
    if (!tcb) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "TCP control block not found");
        return MYLIB_ERROR_INVALID;
    }

    /* 设置TCP状态为监听 */
    tcb->state = TCP_STATE_LISTEN;
    
    MYLIB_LOG(LOG_LEVEL_INFO, "Socket listening on port %d", ntohs(sock->local_port));
    return MYLIB_SUCCESS;
}

socket_handle_t mylib_accept(socket_handle_t handle, struct sockaddr* addr, socklen_t* addrlen) {
    struct mylib_socket *sock = (struct mylib_socket *)handle;
    
    if (!sock || !addr || !addrlen || *addrlen < sizeof(struct sockaddr_in)) {
        errno = EINVAL;
        return NULL;
    }

    /* 只支持TCP */
    if (sock->protocol != IPPROTO_TCP) {
        errno = EPROTOTYPE;
        return NULL;
    }

    /* 获取TCP控制块 */
    struct tcp_control_block *listen_tcb = tcp_find_tcb(sock->local_ip, sock->local_port);
    if (!listen_tcb || listen_tcb->state != TCP_STATE_LISTEN) {
        errno = EINVAL;
        return NULL;
    }

    /* 等待新的连接 */
    struct tcp_control_block *new_tcb;
    pthread_mutex_lock(&sock->mutex);
    while (1) {
        new_tcb = tcp_get_accept_tcb(sock->local_port);
        if (new_tcb && new_tcb->state == TCP_STATE_ESTABLISHED) {
            break;
        }
        pthread_cond_wait(&sock->cond, &sock->mutex);
    }
    pthread_mutex_unlock(&sock->mutex);

    /* 创建新的socket */
    struct mylib_socket *new_sock = rte_malloc("mylib_socket", sizeof(struct mylib_socket), 0);
    if (!new_sock) {
        errno = ENOMEM;
        return NULL;
    }

    /* 初始化新socket */
    memset(new_sock, 0, sizeof(struct mylib_socket));
    new_sock->protocol = IPPROTO_TCP;
    new_sock->local_ip = sock->local_ip;
    new_sock->local_port = new_tcb->remote_port;
    
    /* 分配文件描述符 */
    new_sock->fd = allocate_fd();
    if (new_sock->fd < 0) {
        rte_free(new_sock);
        errno = EMFILE;
        return NULL;
    }

    /* 创建缓冲区 */
    new_sock->send_buf = rte_ring_create("send_buf", 1024,
                                        rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    new_sock->recv_buf = rte_ring_create("recv_buf", 1024,
                                        rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    
    if (!new_sock->send_buf || !new_sock->recv_buf) {
        if (new_sock->send_buf) rte_ring_free(new_sock->send_buf);
        if (new_sock->recv_buf) rte_ring_free(new_sock->recv_buf);
        release_fd(new_sock->fd);
        rte_free(new_sock);
        errno = ENOMEM;
        return NULL;
    }

    /* 初始化同步原语 */
    pthread_mutex_init(&new_sock->mutex, NULL);
    pthread_cond_init(&new_sock->cond, NULL);

    /* 关联TCP控制块 */
    new_tcb->sock = new_sock;

    /* 填充客户端地址信息 */
    struct sockaddr_in *client_addr = (struct sockaddr_in *)addr;
    client_addr->sin_family = AF_INET;
    client_addr->sin_addr.s_addr = new_tcb->remote_ip;
    client_addr->sin_port = new_tcb->remote_port;
    *addrlen = sizeof(struct sockaddr_in);

    MYLIB_LOG(LOG_LEVEL_INFO, "Accepted new connection from %s:%d",
              inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
    
    return (socket_handle_t)new_sock;
}

ssize_t mylib_send(socket_handle_t handle, const void* buf, size_t len, int flags) {
    struct mylib_socket *sock = (struct mylib_socket *)handle;
    
    if (!sock || !buf) {
        errno = EINVAL;
        return -1;
    }

    /* 只支持TCP */
    if (sock->protocol != IPPROTO_TCP) {
        errno = EPROTOTYPE;
        return -1;
    }

    /* 获取TCP控制块 */
    struct tcp_control_block *tcb = tcp_find_tcb(sock->local_ip, sock->local_port);
    if (!tcb || tcb->state != TCP_STATE_ESTABLISHED) {
        errno = ENOTCONN;
        return -1;
    }

    /* 将数据放入发送缓冲区 */
    void *data = rte_malloc("tcp_data", len, 0);
    if (!data) {
        errno = ENOMEM;
        return -1;
    }
    rte_memcpy(data, buf, len);

    if (rte_ring_mp_enqueue(sock->send_buf, data) < 0) {
        rte_free(data);
        errno = EAGAIN;
        return -1;
    }

    /* 触发发送 */
    mylib_error_t ret = tcp_output(tcb);
    if (ret != MYLIB_SUCCESS) {
        errno = EAGAIN;
        return -1;
    }

    return len;
}

ssize_t mylib_recv(socket_handle_t handle, void* buf, size_t len, int flags) {
    struct mylib_socket *sock = (struct mylib_socket *)handle;
    
    if (!sock || !buf) {
        errno = EINVAL;
        return -1;
    }

    /* 只支持TCP */
    if (sock->protocol != IPPROTO_TCP) {
        errno = EPROTOTYPE;
        return -1;
    }

    /* 获取TCP控制块 */
    struct tcp_control_block *tcb = tcp_find_tcb(sock->local_ip, sock->local_port);
    if (!tcb || tcb->state != TCP_STATE_ESTABLISHED) {
        errno = ENOTCONN;
        return -1;
    }

    /* 从接收缓冲区获取数据 */
    void *data;
    if (rte_ring_mc_dequeue(sock->recv_buf, &data) < 0) {
        if (flags & MSG_DONTWAIT) {
            errno = EAGAIN;
            return -1;
        }

        /* 阻塞等待数据 */
        pthread_mutex_lock(&sock->mutex);
        while (rte_ring_mc_dequeue(sock->recv_buf, &data) < 0) {
            pthread_cond_wait(&sock->cond, &sock->mutex);
        }
        pthread_mutex_unlock(&sock->mutex);
    }

    /* 复制数据到用户缓冲区 */
    size_t data_len = strlen(data);  // TODO: 需要正确处理数据长度
    size_t copy_len = (data_len < len) ? data_len : len;
    rte_memcpy(buf, data, copy_len);

    rte_free(data);
    return copy_len;
} 
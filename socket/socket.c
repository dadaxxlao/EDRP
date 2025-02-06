#include "socket.h"
#include "udp.h"
#include "tcp.h"
#include "arp.h"
#include <rte_malloc.h>
#include <errno.h>

// 全局套接字位图（用于分配唯一的文件描述符）
static unsigned char fd_bitmap[1024] = {0};

/**
 * @brief 从位图中分配一个未使用的文件描述符
 */
static int allocate_fd() {
    for (int fd = 3; fd < 1024; fd++) { // 0-2保留给标准输入输出
        int byte = fd / 8;
        int bit = fd % 8;
        if ((fd_bitmap[byte] & (1 << bit)) == 0) {
            fd_bitmap[byte] |= (1 << bit);
            return fd;
        }
    }
    return -1; // 无可用fd
}

/**
 * @brief 释放文件描述符
 */
static void release_fd(int fd) {
    if (fd >= 0 && fd < 1024) {
        int byte = fd / 8;
        int bit = fd % 8;
        fd_bitmap[byte] &= ~(1 << bit);
    }
}

/**
 * @brief 根据文件描述符获取TCP流或UDP上下文
 */
static void* get_context(int sockfd) {
    // UDP上下文查找
    struct localhost *udp_ctx = udp_get_host_by_fd(sockfd);
    if (udp_ctx != NULL) return udp_ctx;

    // TCP流查找
    struct ng_tcp_stream *tcp_stream = tcp_find_stream_by_fd(sockfd);
    if (tcp_stream != NULL) return tcp_stream;

    return NULL;
}

//--------------------------------- 接口实现 ---------------------------------//

int socket(int domain, int type, int protocol) {
    int fd = allocate_fd();
    if (fd == -1) {
        errno = EMFILE; // 文件描述符耗尽
        return -1;
    }

    if (type == SOCK_DGRAM) {
        // 创建UDP套接字
        struct localhost *ctx = rte_malloc("udp_ctx", sizeof(struct localhost), 0);
        if (!ctx) {
            release_fd(fd);
            errno = ENOMEM;
            return -1;
        }
        memset(ctx, 0, sizeof(struct localhost));
        ctx->fd = fd;
        ctx->protocol = IPPROTO_UDP;
        ctx->sndbuf = rte_ring_create("udp_snd", 1024, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        ctx->rcvbuf = rte_ring_create("udp_rcv", 1024, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        LL_ADD(ctx, lhost);
    } else if (type == SOCK_STREAM) {
        // 创建TCP套接字
        struct ng_tcp_stream *stream = rte_malloc("tcp_stream", sizeof(struct ng_tcp_stream), 0);
        if (!stream) {
            release_fd(fd);
            errno = ENOMEM;
            return -1;
        }
        memset(stream, 0, sizeof(struct ng_tcp_stream));
        stream->fd = fd;
        stream->protocol = IPPROTO_TCP;
        stream->sndbuf = rte_ring_create("tcp_snd", 1024, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        stream->rcvbuf = rte_ring_create("tcp_rcv", 1024, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        struct ng_tcp_table *table = tcp_table_instance();
        LL_ADD(stream, table->tcb_set);
    } else {
        release_fd(fd);
        errno = EPROTONOSUPPORT;
        return -1;
    }
    return fd;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    void *ctx = get_context(sockfd);
    if (!ctx) {
        errno = EBADF;
        return -1;
    }

    const struct sockaddr_in *saddr = (const struct sockaddr_in*)addr;
    if (saddr->sin_family != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    if (((struct localhost*)ctx)->protocol == IPPROTO_UDP) {
        struct localhost *udp_ctx = (struct localhost*)ctx;
        udp_ctx->localip = saddr->sin_addr.s_addr;
        udp_ctx->localport = saddr->sin_port;
    } else if (((struct ng_tcp_stream*)ctx)->protocol == IPPROTO_TCP) {
        struct ng_tcp_stream *tcp_stream = (struct ng_tcp_stream*)ctx;
        tcp_stream->dip = saddr->sin_addr.s_addr;
        tcp_stream->dport = saddr->sin_port;
    }
    return 0;
}

int listen(int sockfd, int backlog) {
    struct ng_tcp_stream *stream = tcp_find_stream_by_fd(sockfd);
    if (!stream || stream->protocol != IPPROTO_TCP) {
        errno = EOPNOTSUPP;
        return -1;
    }
    stream->status = NG_TCP_STATUS_LISTEN;
    return 0;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    struct ng_tcp_stream *listener = tcp_find_stream_by_fd(sockfd);
    if (!listener || listener->status != NG_TCP_STATUS_LISTEN) {
        errno = EINVAL;
        return -1;
    }

    // 阻塞直到有新连接
    struct ng_tcp_stream *new_stream = NULL;
    pthread_mutex_lock(&listener->mutex);
    while ((new_stream = tcp_get_pending_connection(listener)) == NULL) {
        pthread_cond_wait(&listener->cond, &listener->mutex);
    }
    pthread_mutex_unlock(&listener->mutex);

    // 分配新fd
    int new_fd = allocate_fd();
    new_stream->fd = new_fd;

    // 填充客户端地址
    struct sockaddr_in *saddr = (struct sockaddr_in*)addr;
    saddr->sin_addr.s_addr = new_stream->sip;
    saddr->sin_port = new_stream->sport;
    return new_fd;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    void *ctx = get_context(sockfd);
    if (!ctx) {
        errno = EBADF;
        return -1;
    }

    if (((struct localhost*)ctx)->protocol == IPPROTO_UDP) {
        struct localhost *udp_ctx = (struct localhost*)ctx;
        struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
        ol->data = rte_malloc("payload", len, 0);
        rte_memcpy(ol->data, buf, len);
        rte_ring_mp_enqueue(udp_ctx->sndbuf, ol);
        return len;
    } else if (((struct ng_tcp_stream*)ctx)->protocol == IPPROTO_TCP) {
        struct ng_tcp_stream *stream = (struct ng_tcp_stream*)ctx;
        struct ng_tcp_fragment *frag = rte_malloc("tcp_frag", sizeof(struct ng_tcp_fragment), 0);
        frag->data = rte_malloc("payload", len, 0);
        rte_memcpy(frag->data, buf, len);
        rte_ring_mp_enqueue(stream->sndbuf, frag);
        return len;
    }
    return -1;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    void *ctx = get_context(sockfd);
    if (!ctx) {
        errno = EBADF;
        return -1;
    }

    if (((struct localhost*)ctx)->protocol == IPPROTO_UDP) {
        struct localhost *udp_ctx = (struct localhost*)ctx;
        struct offload *ol;
        if (rte_ring_mc_dequeue(udp_ctx->rcvbuf, (void**)&ol) < 0) {
            errno = EAGAIN;
            return -1;
        }
        size_t copy_len = (ol->length > len) ? len : ol->length;
        rte_memcpy(buf, ol->data, copy_len);
        rte_free(ol->data);
        rte_free(ol);
        return copy_len;
    } else if (((struct ng_tcp_stream*)ctx)->protocol == IPPROTO_TCP) {
        struct ng_tcp_stream *stream = (struct ng_tcp_stream*)ctx;
        struct ng_tcp_fragment *frag;
        if (rte_ring_mc_dequeue(stream->rcvbuf, (void**)&frag) < 0) {
            errno = EAGAIN;
            return -1;
        }
        size_t copy_len = (frag->length > len) ? len : frag->length;
        rte_memcpy(buf, frag->data, copy_len);
        rte_free(frag->data);
        rte_free(frag);
        return copy_len;
    }
    return -1;
}

int close(int sockfd) {
    void *ctx = get_context(sockfd);
    if (!ctx) {
        errno = EBADF;
        return -1;
    }

    if (((struct localhost*)ctx)->protocol == IPPROTO_UDP) {
        struct localhost *udp_ctx = (struct localhost*)ctx;
        LL_REMOVE(udp_ctx, lhost);
        rte_ring_free(udp_ctx->sndbuf);
        rte_ring_free(udp_ctx->rcvbuf);
        rte_free(udp_ctx);
    } else if (((struct ng_tcp_stream*)ctx)->protocol == IPPROTO_TCP) {
        struct ng_tcp_stream *stream = (struct ng_tcp_stream*)ctx;
        struct ng_tcp_table *table = tcp_table_instance();
        LL_REMOVE(stream, table->tcb_set);
        rte_ring_free(stream->sndbuf);
        rte_ring_free(stream->rcvbuf);
        rte_free(stream);
    }
    release_fd(sockfd);
    return 0;
}

/**
 * @file rings.c
 * @brief 环形缓冲区实现
 *
 * 实现环形缓冲区的创建和管理。
 * 基于DPDK实现高性能网络通信。
 *
 * @author 冯昊阳
 * @date 2025年2月18日
 */
#include <rte_ring.h>
#include <rte_malloc.h>
#include "internal/common.h"
#include "internal/logging.h"

mylib_error_t init_rings(void) {
    /* 创建接收环形缓冲区 */
    g_in_ring = rte_ring_create("in_ring", 1024,
                               rte_socket_id(),
                               RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (g_in_ring == NULL) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to create in ring");
        return MYLIB_ERROR_NOMEM;
    }

    /* 创建发送环形缓冲区 */
    g_out_ring = rte_ring_create("out_ring", 1024,
                                rte_socket_id(),
                                RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (g_out_ring == NULL) {
        rte_ring_free(g_in_ring);
        g_in_ring = NULL;
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to create out ring");
        return MYLIB_ERROR_NOMEM;
    }

    MYLIB_LOG(LOG_LEVEL_INFO, "Rings initialized successfully");
    return MYLIB_SUCCESS;
}

void cleanup_rings(void) {
    if (g_in_ring) {
        rte_ring_free(g_in_ring);
        g_in_ring = NULL;
    }
    
    if (g_out_ring) {
        rte_ring_free(g_out_ring);
        g_out_ring = NULL;
    }
    
    MYLIB_LOG(LOG_LEVEL_INFO, "Rings cleaned up successfully");
} 
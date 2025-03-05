/**
 * @file fd_manager.c
 * @brief 文件描述符管理
 *
 * 实现文件描述符的分配和释放。
 * 基于DPDK实现高性能网络通信。
 *
 * @author 冯昊阳
 * @date 2025年2月18日
 */
#include <rte_malloc.h>
#include <pthread.h>
#include "internal/common.h"
#include "internal/logging.h"

/* 文件描述符管理 */
#define MAX_FDS 1024
static uint32_t g_fd_bitmap[MAX_FDS / 32];  // 使用无符号整型
static pthread_mutex_t g_fd_mutex = PTHREAD_MUTEX_INITIALIZER;

int allocate_fd(void) {
    pthread_mutex_lock(&g_fd_mutex);
    
    /* 查找第一个可用的文件描述符 */
    for (uint32_t i = 0; i < MAX_FDS / 32; i++) {
        if (g_fd_bitmap[i] != 0xFFFFFFFFU) {
            /* 找到有空闲位的整数 */
            for (uint32_t j = 0; j < 32; j++) {
                if (!(g_fd_bitmap[i] & (1 << j))) {
                    /* 找到空闲位 */
                    g_fd_bitmap[i] |= (1 << j);
                    int fd = i * 32 + j;
                    pthread_mutex_unlock(&g_fd_mutex);
                    MYLIB_LOG(LOG_LEVEL_DEBUG, "Allocated fd %d", fd);
                    return fd;
                }
            }
        }
    }
    
    pthread_mutex_unlock(&g_fd_mutex);
    MYLIB_LOG(LOG_LEVEL_ERROR, "No available file descriptors");
    return -1;
}

void release_fd(int fd) {
    if (fd < 0 || fd >= MAX_FDS) {
        MYLIB_LOG(LOG_LEVEL_WARNING, "Invalid fd %d", fd);
        return;
    }

    pthread_mutex_lock(&g_fd_mutex);
    
    int index = fd / 32;
    int bit = fd % 32;
    
    /* 清除对应的位 */
    g_fd_bitmap[index] &= ~(1 << bit);
    
    pthread_mutex_unlock(&g_fd_mutex);
    
    MYLIB_LOG(LOG_LEVEL_DEBUG, "Released fd %d", fd);
} 
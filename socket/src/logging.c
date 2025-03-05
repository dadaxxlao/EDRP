/**
 * @file logging.c
 * @brief 日志实现
 *
 * 实现日志功能，包括初始化、清理、设置日志级别等。
 * 基于DPDK实现高性能网络通信。
 *
 * @author 冯昊阳
 * @date 2025年2月18日
 */
#include <syslog.h>
#include <pthread.h>
#include "internal/logging.h"

/* 全局变量 */
static int g_log_level = LOG_LEVEL_INFO;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

void logging_init(void) {
    pthread_mutex_lock(&g_log_mutex);
    
    /* 打开系统日志 */
    openlog("MYLIB", LOG_PID | LOG_CONS | LOG_PERROR, LOG_USER);
    setlogmask(LOG_UPTO(LOG_DEBUG));
    
    pthread_mutex_unlock(&g_log_mutex);
}

void logging_cleanup(void) {
    pthread_mutex_lock(&g_log_mutex);
    
    /* 关闭系统日志 */
    closelog();
    
    pthread_mutex_unlock(&g_log_mutex);
}

void logging_set_level(int level) {
    pthread_mutex_lock(&g_log_mutex);
    
    if (level >= LOG_LEVEL_ERROR && level <= LOG_LEVEL_DEBUG) {
        g_log_level = level;
        
        /* 更新系统日志掩码 */
        switch (level) {
            case LOG_LEVEL_ERROR:
                setlogmask(LOG_UPTO(LOG_ERR));
                break;
            case LOG_LEVEL_WARNING:
                setlogmask(LOG_UPTO(LOG_WARNING));
                break;
            case LOG_LEVEL_INFO:
                setlogmask(LOG_UPTO(LOG_INFO));
                break;
            case LOG_LEVEL_DEBUG:
                setlogmask(LOG_UPTO(LOG_DEBUG));
                break;
        }
    }
    
    pthread_mutex_unlock(&g_log_mutex);
} 
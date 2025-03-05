/**
 * @file logging.h
 * @brief 日志实现
 *
 * 实现日志功能，包括初始化、清理、设置日志级别等。
 * 基于DPDK实现高性能网络通信。
 *
 * @author 冯昊阳
 * @date 2025年2月18日
 */
#ifndef MYLIB_INTERNAL_LOGGING_H
#define MYLIB_INTERNAL_LOGGING_H

#include <syslog.h>
#include "../../include/mylib/ex_logging.h"

/* 颜色定义 */
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_RESET   "\x1b[0m"

/* 日志宏 */
#define MYLIB_LOG(level, fmt, ...) do { \
    switch(level) { \
        case LOG_LEVEL_ERROR: \
            syslog(LOG_ERR, ANSI_COLOR_RED "[MYLIB][ERROR][%s:%d] " fmt ANSI_COLOR_RESET, \
                   __FILE__, __LINE__, ##__VA_ARGS__); \
            break; \
        case LOG_LEVEL_WARNING: \
            syslog(LOG_WARNING, ANSI_COLOR_YELLOW "[MYLIB][WARN][%s:%d] " fmt ANSI_COLOR_RESET, \
                   __FILE__, __LINE__, ##__VA_ARGS__); \
            break; \
        case LOG_LEVEL_INFO: \
            syslog(LOG_INFO, "[MYLIB][INFO][%s:%d] " fmt, \
                   __FILE__, __LINE__, ##__VA_ARGS__); \
            break; \
        case LOG_LEVEL_DEBUG: \
            syslog(LOG_DEBUG, ANSI_COLOR_BLUE "[MYLIB][DEBUG][%s:%d] " fmt ANSI_COLOR_RESET, \
                   __FILE__, __LINE__, ##__VA_ARGS__); \
            break; \
    } \
} while(0)

/* 内部函数声明 */
void logging_init(void);
void logging_cleanup(void);
void logging_set_level(int level);

#endif /* MYLIB_INTERNAL_LOGGING_H */ 
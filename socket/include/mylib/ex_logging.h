#ifndef EX_LOGGING_H
#define EX_LOGGING_H

#ifdef __cplusplus
extern "C" {
#endif

/* 日志级别定义 */
#define LOG_LEVEL_ERROR    0
#define LOG_LEVEL_WARNING  1
#define LOG_LEVEL_INFO     2
#define LOG_LEVEL_DEBUG    3

/* 日志级别设置函数 */
void mylib_set_log_level(int level);

#ifdef __cplusplus
}
#endif

#endif /* MYLIB_LOGGING_H */ 
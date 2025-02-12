#ifndef __TEST_COMMON_H__
#define __TEST_COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../edrp_socket.h"

// 测试结果状态
#define TEST_SUCCESS 0
#define TEST_FAILURE 1

// 测试辅助宏
#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("测试失败: %s\n", message); \
            printf("位置: %s:%d\n", __FILE__, __LINE__); \
            return TEST_FAILURE; \
        } \
    } while (0)

// 测试用例函数类型
typedef int (*test_func_t)(void);

// 测试用例结构
struct test_case {
    const char *name;
    test_func_t func;
};

#endif // __TEST_COMMON_H__ 
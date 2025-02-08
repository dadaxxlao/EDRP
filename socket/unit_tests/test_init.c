#include "unity.h"
#include "socket.h"
#include "edrp_socket.h"
#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

// 测试前的设置
void setUp(void) {
    // 在每个测试前运行
}

// 测试后的清理
void tearDown(void) {
    // 在每个测试后运行
}

// 测试日志系统初始化
void test_log_system(void) {
    // 测试不同日志级别
    socket_set_log_level(SOCKET_LOG_ERROR);
    TEST_ASSERT_EQUAL(0, (LOG_MASK(LOG_ERR) & setlogmask(0)));
    
    socket_set_log_level(SOCKET_LOG_WARNING);
    TEST_ASSERT_EQUAL(0, (LOG_MASK(LOG_WARNING) & setlogmask(0)));
    
    socket_set_log_level(SOCKET_LOG_INFO);
    TEST_ASSERT_EQUAL(0, (LOG_MASK(LOG_INFO) & setlogmask(0)));
    
    socket_set_log_level(SOCKET_LOG_DEBUG);
    TEST_ASSERT_EQUAL(0, (LOG_MASK(LOG_DEBUG) & setlogmask(0)));
    
    // 测试无效日志级别
    socket_set_log_level(-1);
    TEST_ASSERT_EQUAL(0, (LOG_MASK(LOG_INFO) & setlogmask(0))); // 应该默认为INFO级别
}

// 测试DPDK初始化
void test_dpdk_init(void) {
    int ret = socket_init();
    TEST_ASSERT_EQUAL(SOCKET_SUCCESS, ret);
    
    // 验证DPDK环境是否正确初始化
    TEST_ASSERT_NOT_NULL(rte_eal_get_configuration());
    
    // 验证内存池是否创建成功
    struct rte_mempool *mp = rte_mempool_lookup("mbuf_pool");
    TEST_ASSERT_NOT_NULL(mp);
    
    // 验证端口是否正确初始化
    TEST_ASSERT_GREATER_THAN(0, rte_eth_dev_count_avail());
    
    // 清理
    socket_cleanup();
}

// 测试配置系统
void test_socket_config(void) {
    struct socket_config config = {
        .max_fds = 2048,
        .ring_size = 2048,
        .timeout_sec = 60,
        .log_level = SOCKET_LOG_INFO
    };
    
    // 测试设置配置
    int ret = socket_set_config(&config);
    TEST_ASSERT_EQUAL(SOCKET_SUCCESS, ret);
    
    // 测试获取配置
    struct socket_config get_config;
    ret = socket_get_config(&get_config);
    TEST_ASSERT_EQUAL(SOCKET_SUCCESS, ret);
    
    // 验证配置值
    TEST_ASSERT_EQUAL(config.max_fds, get_config.max_fds);
    TEST_ASSERT_EQUAL(config.ring_size, get_config.ring_size);
    TEST_ASSERT_EQUAL(config.timeout_sec, get_config.timeout_sec);
    TEST_ASSERT_EQUAL(config.log_level, get_config.log_level);
    
    // 测试无效配置
    config.max_fds = -1;
    ret = socket_set_config(&config);
    TEST_ASSERT_EQUAL(SOCKET_ERROR_INVALID, ret);
}

// 主函数
int main(void) {
    UNITY_BEGIN();
    
    // 运行测试
    RUN_TEST(test_log_system);
    RUN_TEST(test_dpdk_init);
    RUN_TEST(test_socket_config);
    
    return UNITY_END();
} 
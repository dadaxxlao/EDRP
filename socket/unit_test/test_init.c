#include "test_common.h"
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_version.h>

// 测试DPDK初始化
static int test_dpdk_init(void)
{
    int ret;
    
    // 准备EAL参数
    char *dpdk_argv[] = {
        "socket_test",              // 程序名
        "-l", "0-3",               // 使用CPU核心0-3
        "-n", "4",                 // 设置内存通道数
        "--proc-type=primary",     // 设置为主进程
        "--file-prefix=test_init", // 使用不同的文件前缀
        "--socket-mem=512",        // 每个socket分配512MB内存
        NULL
    };
    int dpdk_argc = sizeof(dpdk_argv) / sizeof(dpdk_argv[0]) - 1;

    // 初始化EAL
    ret = rte_eal_init(dpdk_argc, dpdk_argv);
    if (ret < 0) {
        printf("EAL初始化失败: %s\n", rte_strerror(rte_errno));
        return TEST_FAILURE;
    }
    
    // 测试DPDK初始化函数
    ret = edrp_init_dpdk();
    TEST_ASSERT(ret == 0, "DPDK初始化失败");
    
    // 验证DPDK是否正确初始化
    #if RTE_VERSION >= RTE_VERSION_NUM(17,11,0,0)
    TEST_ASSERT(rte_eal_has_hugepages(), "DPDK大页内存未初始化");
    #endif
    
    // 检查是否至少有一个可用的网络端口
    uint16_t port_count = rte_eth_dev_count_avail();
    TEST_ASSERT(port_count > 0, "没有可用的网络端口");
    
    printf("DPDK初始化测试通过:\n");
    printf("- EAL初始化成功\n");
    printf("- 可用端口数量: %d\n", port_count);
    
    // 清理资源
    rte_eal_cleanup();
    
    return TEST_SUCCESS;
}

// 主测试函数
int main(int argc, char *argv[])
{
    struct test_case tests[] = {
        {"DPDK初始化测试", test_dpdk_init},
        {NULL, NULL}  // 结束标记
    };
    
    int failed = 0;
    for (struct test_case *test = tests; test->name != NULL; test++) {
        printf("\n运行测试: %s\n", test->name);
        if (test->func() != TEST_SUCCESS) {
            failed++;
        }
    }
    
    printf("\n测试完成: %d 个测试失败\n", failed);
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
} 
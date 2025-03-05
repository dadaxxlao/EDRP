/**
 * @file dpdk_init.c
 * @brief DPDK初始化
 *
 * 实现DPDK的初始化功能，包括EAL初始化、内存池创建、端口配置等。
 * 基于DPDK实现高性能网络通信。
 *
 * @author 冯昊阳
 * @date 2025年2月18日
 */
#include <rte_bus_pci.h>
#include <rte_ethdev.h>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <string.h>

#include "internal/dpdk_init.h"
#include "internal/logging.h"
#include "internal/common.h"

/* 静态函数声明 */
static int check_port_link_status(uint16_t port_id);

mylib_error_t init_dpdk(void) {
    /* 初始化EAL */
    char *argv[] = {
        "mylib",
        "-l", "0-3",        /* 使用逻辑核心0和1 */
        "-n", "4",          /* 使用4个内存通道 */
        "--proc-type=auto", /* 自动检测进程类型 */
        NULL
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to initialize EAL");
        return MYLIB_ERROR_INVALID;
    }

    /* 初始化内存池 */
    if (init_mempool() != MYLIB_SUCCESS) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to initialize mempool");
        return MYLIB_ERROR_NOMEM;
    }

    /* 获取可用端口数量 */
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "No Ethernet ports available");
        return MYLIB_ERROR_INVALID;
    }

    //TODO: 先只考虑单端口
    /* 初始化第一个可用端口 */
    if (init_port(0) != MYLIB_SUCCESS) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to initialize port 0");
        return MYLIB_ERROR_INVALID;
    }

    /* 等待端口链路状态就绪 */
    if (check_port_link_status(0) < 0) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Link is down on port 0");
        return MYLIB_ERROR_INVALID;
    }

    /* 获取MAC地址 */
    struct rte_ether_addr addr;
    rte_eth_macaddr_get(0, &addr);
    rte_memcpy(g_local_mac, addr.addr_bytes, RTE_ETHER_ADDR_LEN);
    
    // Print MAC address using DPDK function
    char mac_buf[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(mac_buf, RTE_ETHER_ADDR_FMT_SIZE, (struct rte_ether_addr *)g_local_mac);
    MYLIB_LOG(LOG_LEVEL_INFO, "Local MAC: %s", mac_buf);

    /* 创建收发环形缓冲区 */
    if (init_rings() != MYLIB_SUCCESS) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to initialize rings");
        return MYLIB_ERROR_NOMEM;
    }

    MYLIB_LOG(LOG_LEVEL_INFO, "DPDK initialized successfully");
    return MYLIB_SUCCESS;
}

mylib_error_t init_mempool(void) {
    /* 创建mbuf内存池 */
    g_mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
                                         NUM_MBUFS,
                                         MEMPOOL_CACHE_SIZE,
                                         0,
                                         MBUF_SIZE,
                                         rte_socket_id());
    if (g_mbuf_pool == NULL) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to create mbuf pool: %s",
                  rte_strerror(rte_errno));
        return MYLIB_ERROR_NOMEM;
    }

    return MYLIB_SUCCESS;
}

mylib_error_t init_port(uint16_t port_id) {
    /* 配置以太网设备 */
    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    /* 配置接收队列 */
    int ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (ret < 0) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to configure port %u", port_id);
        return MYLIB_ERROR_INVALID;
    }

    /* 设置接收队列 */
    ret = rte_eth_rx_queue_setup(port_id, 0, RX_RING_SIZE,
                                rte_eth_dev_socket_id(port_id),
                                NULL, g_mbuf_pool);
    if (ret < 0) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to setup RX queue");
        return MYLIB_ERROR_INVALID;
    }

    /* 设置发送队列 */
    ret = rte_eth_tx_queue_setup(port_id, 0, TX_RING_SIZE,
                                rte_eth_dev_socket_id(port_id),
                                NULL);
    if (ret < 0) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to setup TX queue");
        return MYLIB_ERROR_INVALID;
    }

    /* 启动设备 */
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to start port %u", port_id);
        return MYLIB_ERROR_INVALID;
    }

    /* 启用混杂模式 */
    rte_eth_promiscuous_enable(port_id);

    return MYLIB_SUCCESS;
}

static int check_port_link_status(uint16_t port_id) {
    const int max_check_time = 90; /* 90 * 100ms = 9s */
    int check_interval = 100; /* 100ms */
    int count = 0;

    struct rte_eth_link link;
    memset(&link, 0, sizeof(link));

    while (count++ <= max_check_time) {
        /* 检查链路状态 */
        int ret = rte_eth_link_get_nowait(port_id, &link);
        if (ret < 0) {
            MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to get link status");
            return -1;
        }
        if (link.link_status) {
            return 0; /* 链路已就绪 */
        }
        
        rte_delay_ms(check_interval);
    }

    return -1; /* 链路未就绪 */
}

void cleanup_dpdk(void) {
    /* 停止并关闭端口 */
    rte_eth_dev_stop(0);
    rte_eth_dev_close(0);

    /* 释放内存池 */
    if (g_mbuf_pool) {
        rte_mempool_free(g_mbuf_pool);
        g_mbuf_pool = NULL;
    }

    /* 清理EAL */
    rte_eal_cleanup();

    MYLIB_LOG(LOG_LEVEL_INFO, "DPDK cleaned up successfully");
} 
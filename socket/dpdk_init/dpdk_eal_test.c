#include "dpdk_init.h"
#include <string.h>

// 全局变量定义
struct rte_mempool *g_mbuf_pool = NULL;
uint8_t g_src_mac[6];
struct ring_pair *g_ring = NULL;

// 初始化环形缓冲区
static int init_rings(void) {
    // 分配ring结构内存
    g_ring = rte_malloc("inout_ring", sizeof(struct ring_pair), 0);
    if (!g_ring) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to allocate memory for ring structure: %s", 
                  rte_strerror(rte_errno));
        return SOCKET_ERROR_NOMEM;
    }

    // 初始化为NULL,防止清理时出错
    g_ring->in = NULL;
    g_ring->out = NULL;

    // 创建入口ring
    g_ring->in = rte_ring_create("in_ring", 
                                1024,
                                rte_socket_id(),
                                RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!g_ring->in) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to create input ring: %s", 
                  rte_strerror(rte_errno));
        rte_free(g_ring);
        g_ring = NULL;
        return SOCKET_ERROR_NOMEM;
    }

    // 创建出口ring
    g_ring->out = rte_ring_create("out_ring",
                                 1024,
                                 rte_socket_id(),
                                 RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!g_ring->out) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to create output ring: %s", 
                  rte_strerror(rte_errno));
        rte_ring_free(g_ring->in);
        rte_free(g_ring);
        g_ring = NULL;
        return SOCKET_ERROR_NOMEM;
    }

    SOCKET_LOG(SOCKET_LOG_INFO, "Ring buffers initialized successfully");
    return SOCKET_SUCCESS;
}

int init_dpdk(void) {
    SOCKET_LOG(SOCKET_LOG_INFO, "Initializing DPDK...");

    // 准备EAL参数
    char *dpdk_argv[] = {
        "dpdk_init_test",              // 程序名
        "-l", "0-3",               // 使用CPU核心0-3
        "-n", "4",                 // 设置内存通道数
        NULL
    };
    int dpdk_argc = sizeof(dpdk_argv) / sizeof(dpdk_argv[0]) - 1;

    // 初始化EAL
    int ret = rte_eal_init(dpdk_argc, dpdk_argv);
    if (ret < 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Error with EAL init: %s", rte_strerror(rte_errno));
        return SOCKET_ERROR_INVALID;
    }
    SOCKET_LOG(SOCKET_LOG_INFO, "EAL initialization successful");

    // 检查是否有足够的内存
    if (rte_eal_has_hugepages() == 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "No hugepages available");
        rte_eal_cleanup();
        return SOCKET_ERROR_INVALID;
    }
    SOCKET_LOG(SOCKET_LOG_INFO, "Hugepages check passed");

    // 创建内存池
    unsigned cache_size = 256;
    g_mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", 
                                         NUM_MBUFS,
                                         cache_size,
                                         0,  // private data size
                                         RTE_MBUF_DEFAULT_BUF_SIZE,
                                         rte_socket_id());
    if (!g_mbuf_pool) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Could not create mbuf pool: %s", rte_strerror(rte_errno));
        rte_eal_cleanup();
        return SOCKET_ERROR_NOMEM;
    }
    SOCKET_LOG(SOCKET_LOG_INFO, "Memory pool created successfully");

    // 初始化环形缓冲区
    ret = init_rings();
    if (ret != 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to initialize rings");
        rte_mempool_free(g_mbuf_pool);
        rte_eal_cleanup();
        return SOCKET_ERROR_NOMEM;
    }
    SOCKET_LOG(SOCKET_LOG_INFO, "Ring buffers initialized successfully");

    // 检查可用端口
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "No supported ports found");
        rte_mempool_free(g_mbuf_pool);
        rte_ring_free(g_ring->in);
        rte_ring_free(g_ring->out);
        rte_free(g_ring);
        rte_eal_cleanup();
        return SOCKET_ERROR_INVALID;
    }
    SOCKET_LOG(SOCKET_LOG_INFO, "Found %d available ports", nb_ports);

    // 配置第一个可用端口
    uint16_t port_id = 0;  // 使用第一个端口
    if (port_id >= nb_ports) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Port index %u is out of range", port_id);
        rte_mempool_free(g_mbuf_pool);
        rte_ring_free(g_ring->in);
        rte_ring_free(g_ring->out);
        rte_free(g_ring);
        rte_eal_cleanup();
        return SOCKET_ERROR_INVALID;
    }
    
    // 获取MAC地址
    struct rte_ether_addr mac_addr;
    ret = rte_eth_macaddr_get(port_id, &mac_addr);
    if (ret < 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Failed to get MAC address: %s", rte_strerror(-ret));
        rte_mempool_free(g_mbuf_pool);
        rte_ring_free(g_ring->in);
        rte_ring_free(g_ring->out);
        rte_free(g_ring);
        rte_eal_cleanup();
        return SOCKET_ERROR_INVALID;
    }
    memcpy(g_src_mac, mac_addr.addr_bytes, 6);
    SOCKET_LOG(SOCKET_LOG_INFO, "Got MAC address successfully");
    
    // 配置端口
    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    
    ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (ret < 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Port configuration failed: %s", rte_strerror(-ret));
        rte_mempool_free(g_mbuf_pool);
        rte_ring_free(g_ring->in);
        rte_ring_free(g_ring->out);
        rte_free(g_ring);
        rte_eal_cleanup();
        return SOCKET_ERROR_INVALID;
    }
    SOCKET_LOG(SOCKET_LOG_INFO, "Port configured successfully");

    // 设置接收队列
    ret = rte_eth_rx_queue_setup(port_id, 0, RX_RING_SIZE,
                                rte_eth_dev_socket_id(port_id),
                                NULL,
                                g_mbuf_pool);
    if (ret < 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "RX queue setup failed: %s", rte_strerror(-ret));
        rte_eth_dev_close(port_id);
        rte_mempool_free(g_mbuf_pool);
        rte_ring_free(g_ring->in);
        rte_ring_free(g_ring->out);
        rte_free(g_ring);
        rte_eal_cleanup();
        return SOCKET_ERROR_INVALID;
    }
    SOCKET_LOG(SOCKET_LOG_INFO, "RX queue setup successful");

    // 设置发送队列
    ret = rte_eth_tx_queue_setup(port_id, 0, TX_RING_SIZE,
                                rte_eth_dev_socket_id(port_id),
                                NULL);
    if (ret < 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "TX queue setup failed: %s", rte_strerror(-ret));
        rte_eth_dev_close(port_id);
        rte_mempool_free(g_mbuf_pool);
        rte_ring_free(g_ring->in);
        rte_ring_free(g_ring->out);
        rte_free(g_ring);
        rte_eal_cleanup();
        return SOCKET_ERROR_INVALID;
    }
    SOCKET_LOG(SOCKET_LOG_INFO, "TX queue setup successful");

    // 启动端口
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        SOCKET_LOG(SOCKET_LOG_ERROR, "Port start failed: %s", rte_strerror(-ret));
        rte_eth_dev_close(port_id);
        rte_mempool_free(g_mbuf_pool);
        rte_ring_free(g_ring->in);
        rte_ring_free(g_ring->out);
        rte_free(g_ring);
        rte_eal_cleanup();
        return SOCKET_ERROR_INVALID;
    }
    SOCKET_LOG(SOCKET_LOG_INFO, "Port started successfully");

    // 设置混杂模式
    rte_eth_promiscuous_enable(port_id);
    SOCKET_LOG(SOCKET_LOG_INFO, "Promiscuous mode enabled");

    SOCKET_LOG(SOCKET_LOG_INFO, "DPDK initialization completed successfully on port %u", port_id);
    return SOCKET_SUCCESS;
}
#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <stdlib.h>

#define NUM_MBUFS 8192
#define BURST_SIZE 32
#define RING_SIZE 1024

struct inout_ring {
    struct rte_ring *in;
    struct rte_ring *out;
};

static struct inout_ring *ring = NULL;
static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];  // Source MAC address

/**
 * @brief 初始化DPDK，mempool和ring
 */
static void init_dpdk(void) {
    // DPDK环境初始化
    int ret = rte_eal_init(0, NULL);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    }

    // 初始化内存池
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NUM_MBUFS, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) {
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
    }

    // 初始化ring缓冲区
    ring = rte_malloc("inout_ring", sizeof(struct inout_ring), 0);
    if (!ring) {
        rte_exit(EXIT_FAILURE, "Could not allocate memory for ring\n");
    }

    ring->in = rte_ring_create("in_ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    ring->out = rte_ring_create("out_ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!ring->in || !ring->out) {
        rte_exit(EXIT_FAILURE, "Could not create rings\n");
    }

    // 初始化网络端口
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) {
        rte_exit(EXIT_FAILURE, "No supported ports found\n");
    }

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(0, &dev_info);
    rte_eth_macaddr_get(0, (struct rte_ether_addr *)gSrcMac);
    printf("Source MAC address: ");
    for (int i = 0; i < RTE_ETHER_ADDR_LEN; i++) {
        printf("%02x", gSrcMac[i]);
        if (i != RTE_ETHER_ADDR_LEN - 1) {
            printf(":");
        }
    }
    printf("\n");

    // 配置端口并启动
    struct rte_eth_conf port_conf = {0};
    rte_eth_dev_configure(0, 1, 1, &port_conf);
    rte_eth_rx_queue_setup(0, 0, 1024, rte_eth_dev_socket_id(0), NULL, mbuf_pool);
    rte_eth_tx_queue_setup(0, 0, 1024, rte_eth_dev_socket_id(0), NULL);
    rte_eth_dev_start(0);
}

/**
 * @brief 数据包接收线程，负责将接收到的数据包放入ring->in
 */
static void rx_thread(void) {
    struct rte_mbuf *rx_bufs[BURST_SIZE];
    uint16_t nb_rx;

    while (1) {
        // 从网卡接收数据包
        nb_rx = rte_eth_rx_burst(0, 0, rx_bufs, BURST_SIZE);
        if (nb_rx > 0) {
            // 将接收到的数据包放入ring->in
            rte_ring_sp_enqueue_burst(ring->in, (void **)rx_bufs, nb_rx, NULL);
        }
    }
}

/**
 * @brief 数据包发送线程，负责将ring->out中的数据包发送出去
 */
static void tx_thread(void) {
    struct rte_mbuf *tx_bufs[BURST_SIZE];
    uint16_t nb_tx;

    while (1) {
        // 从ring->out取出数据包
        nb_tx = rte_ring_sc_dequeue_burst(ring->out, (void **)tx_bufs, BURST_SIZE, NULL);
        if (nb_tx > 0) {
            // 发送数据包
            rte_eth_tx_burst(0, 0, tx_bufs, nb_tx);

            // 释放发送的mbuf
            for (int i = 0; i < nb_tx; i++) {
                rte_pktmbuf_free(tx_bufs[i]);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    // 初始化DPDK环境
    init_dpdk();

    // 启动接收线程
    if (rte_lcore_id() == 0) {
        rx_thread();
    }

    // 启动发送线程
    if (rte_lcore_id() == 1) {
        tx_thread();
    }

    return 0;
}

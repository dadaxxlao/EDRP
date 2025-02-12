#include "dpdk_init.h"
#include <stdio.h>

int main(void) {
    printf("Starting DPDK initialization test...\n");
    
    int ret = init_dpdk();
    if (ret != 0) {
        printf("DPDK initialization failed with error code: %d\n", ret);
        return -1;
    }
    
    printf("DPDK initialization successful!\n");
    
    // 清理资源
    // 1. 首先停止并关闭网络端口
    uint16_t port_id = 0;
        rte_eth_dev_stop(port_id);
        rte_eth_dev_close(port_id);

    
    // 2. 释放ring缓冲区
    if (g_ring != NULL) {
        if (g_ring->in != NULL) {
            rte_ring_free(g_ring->in);
            g_ring->in = NULL;
        }
        if (g_ring->out != NULL) {
            rte_ring_free(g_ring->out);
            g_ring->out = NULL;
        }
        rte_free(g_ring);
        g_ring = NULL;
    }
    
    // 3. 释放内存池
    if (g_mbuf_pool != NULL) {
        rte_mempool_free(g_mbuf_pool);
        g_mbuf_pool = NULL;
    }
    
    // 4. 最后清理EAL
    rte_eal_cleanup();
    
    printf("Cleanup completed successfully\n");
    return 0;
} 
#include "dpdk_init.h"
#include <stdio.h>

int main(void) {
    printf("Starting DPDK initialization test...\n");
    
    int ret = init_dpdk();
    if (ret != SOCKET_SUCCESS) {
        printf("DPDK initialization failed with error code: %d\n", ret);
        return -1;
    }
    
    printf("DPDK initialization successful!\n");
    
    // 清理资源
    if (g_ring != NULL) {
        if (g_ring->in != NULL) rte_ring_free(g_ring->in);
        if (g_ring->out != NULL) rte_ring_free(g_ring->out);
        rte_free(g_ring);
    }
    if (g_mbuf_pool != NULL) {
        rte_mempool_free(g_mbuf_pool);
    }
    rte_eal_cleanup();
    
    return 0;
} 
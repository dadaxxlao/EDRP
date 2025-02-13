#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "../../socket/include/mylib/core.h"

/* 忽略未使用参数警告 */
#pragma GCC diagnostic ignored "-Wunused-parameter"

int main(int argc, char *argv[]) {
    /* 初始化配置 */
    mylib_config_t config = {
        .max_fds = 1024,
        .ring_size = 1024,
        .timeout_sec = 30,
        .log_level = LOG_LEVEL_DEBUG,
        .network_config = {
            .ip_addr = inet_addr("192.168.4.109"),
            .port_range_start = 1024,
            .port_range_end = 65535,
            .netmask = inet_addr("255.255.255.0"),
            .gateway = inet_addr("192.168.4.1")
        }
    };

    /* 初始化库 */
    mylib_error_t ret = mylib_init(&config);
    if (ret != MYLIB_SUCCESS) {
        printf("Failed to initialize library\n");
        return -1;
    }

    /* 创建UDP socket */
    socket_handle_t sock = mylib_socket(AF_INET, SOCK_DGRAM, 0);
    if (!sock) {
        printf("Failed to create socket\n");
        mylib_cleanup();
        return -1;
    }

    /* 绑定地址 */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);  // 使用端口12345
    addr.sin_addr.s_addr = config.network_config.ip_addr;

    ret = mylib_bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (ret != MYLIB_SUCCESS) {
        printf("Failed to bind socket\n");
        mylib_close(sock);
        mylib_cleanup();
        return -1;
    }

    printf("UDP socket bound to port 12345\n");

    /* 接收数据 */
    char buffer[1024];
    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len = sizeof(peer_addr);

    while (1) {
        ssize_t recv_len = mylib_recvfrom(sock, buffer, sizeof(buffer), 0,
                                         (struct sockaddr*)&peer_addr, &peer_addr_len);
        
        if (recv_len > 0) {
            buffer[recv_len] = '\0';
            printf("Received from %s:%d: %s\n",
                   inet_ntoa(peer_addr.sin_addr),
                   ntohs(peer_addr.sin_port),
                   buffer);

            /* 发送回显 */
            mylib_sendto(sock, buffer, recv_len, 0,
                        (struct sockaddr*)&peer_addr, peer_addr_len);
        }
    }

    /* 清理资源 */
    mylib_close(sock);
    mylib_cleanup();

    return 0;
} 
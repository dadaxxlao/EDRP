#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include "../../socket/include/mylib/core.h"

/* 忽略未使用参数警告 */
#pragma GCC diagnostic ignored "-Wunused-parameter"

#define MAX_BUFFER_SIZE 1024
#define MAX_CMD_SIZE 1024

/* 解析发送命令 */
int parse_send_command(char* cmd, struct sockaddr_in* dest_addr, char* message) {
    char ip[16];
    int port;
    
    // 格式: send <ip> <port> <message>
    if(sscanf(cmd, "send %15s %d %[^\n]", ip, &port, message) != 3) {
        printf("Invalid command format. Use: send <ip> <port> <message>\n");
        return -1;
    }
    
    // 验证端口范围
    if(port <= 0 || port > 65535) {
        printf("Invalid port number. Must be between 1 and 65535\n");
        return -1;
    }
    
    // 设置目标地址
    memset(dest_addr, 0, sizeof(*dest_addr));
    dest_addr->sin_family = AF_INET;
    dest_addr->sin_port = htons(port);
    if(inet_pton(AF_INET, ip, &dest_addr->sin_addr) != 1) {
        printf("Invalid IP address\n");
        return -1;
    }
    
    return 0;
}

int main(int argc, char *argv[]) {
    /* 初始化配置 */
    mylib_config_t config = {
        .max_fds = 1024,
        .ring_size = 1024,
        .timeout_sec = 30,
        .log_level = LOG_LEVEL_DEBUG,
        .network_config = {
            .ip_addr = inet_addr("192.168.11.195"),
            .port_range_start = 1024,
            .port_range_end = 65535,
            .netmask = inet_addr("255.255.255.0"),
            .gateway = inet_addr("192.168.11.1")
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
    printf("Enter 'send <ip> <port> <message>' to send message\n");

    /* 接收和发送缓冲区 */
    char recv_buffer[MAX_BUFFER_SIZE];
    char cmd_buffer[MAX_CMD_SIZE];
    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len = sizeof(peer_addr);
    
    fd_set read_fds;
    int stdin_fd = fileno(stdin);

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(stdin_fd, &read_fds);
        
        /* 设置超时时间为1秒 */
        struct timeval tv = {1, 0};
        
        /* 等待输入或数据到达 */
        int ready = select(stdin_fd + 1, &read_fds, NULL, NULL, &tv);
        
        if (ready > 0) {
            if (FD_ISSET(stdin_fd, &read_fds)) {
                /* 处理用户输入 */
                if (fgets(cmd_buffer, MAX_CMD_SIZE, stdin)) {
                    if (strncmp(cmd_buffer, "send", 4) == 0) {
                        struct sockaddr_in dest_addr;
                        char message[MAX_BUFFER_SIZE];
                        
                        if (parse_send_command(cmd_buffer, &dest_addr, message) == 0) {
                            ssize_t sent = mylib_sendto(sock, message, strlen(message), 0,
                                                      (struct sockaddr*)&dest_addr, sizeof(dest_addr));
                            if (sent < 0) {
                                printf("Failed to send message\n");
                            } else {
                                printf("Message sent successfully\n");
                            }
                        }
                    }
                }
            }
        }
        
        /* 尝试接收数据 */
        ssize_t recv_len = mylib_recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0,
                                         (struct sockaddr*)&peer_addr, &peer_addr_len);
        
        if (recv_len > 0) {
            recv_buffer[recv_len] = '\0';
            printf("Received from %s:%d: %s\n",
                   inet_ntoa(peer_addr.sin_addr),
                   ntohs(peer_addr.sin_port),
                   recv_buffer);
           
            /* 发送回显 */
            ssize_t sent = mylib_sendto(sock, recv_buffer, recv_len, 0,
                                       (struct sockaddr*)&peer_addr, peer_addr_len);
            if (sent < 0) {
                printf("Failed to send echo response\n");
            }
        }
    }

    /* 清理资源 */
    mylib_close(sock);
    mylib_cleanup();

    return 0;
} 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#include "../../socket/include/mylib/core.h"

/* 忽略未使用参数警告 */
#pragma GCC diagnostic ignored "-Wunused-parameter"

#define MAX_BUFFER_SIZE 1024
#define MAX_CMD_SIZE 1024
#define BACKLOG 5

/* 命令解析功能 */
int parse_command(char* cmd, char* message) {
    // 格式: send <message>
    if(strncmp(cmd, "send ", 5) == 0) {
        strcpy(message, cmd + 5);
        return 1;
    }
    // 格式: quit
    else if(strncmp(cmd, "quit", 4) == 0) {
        return 0;
    }
    
    printf("无效的命令。使用 'send <消息>' 发送消息，或 'quit' 退出\n");
    return -1;
}

/* 服务器模式函数 */
int server_mode(const mylib_config_t* config, uint16_t port) {
    mylib_error_t ret;
    
    /* 创建TCP socket */
    socket_handle_t listen_sock = mylib_socket(AF_INET, SOCK_STREAM, 0);
    if (!listen_sock) {
        printf("创建socket失败\n");
        return -1;
    }
    
    /* 绑定地址 */
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = config->network_config.ip_addr;
    
    ret = mylib_bind(listen_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (ret != MYLIB_SUCCESS) {
        printf("绑定地址失败: %d\n", ret);
        mylib_close(listen_sock);
        return -1;
    }
    
    /* 开始监听 */
    ret = mylib_listen(listen_sock, BACKLOG);
    if (ret != MYLIB_SUCCESS) {
        printf("监听失败: %d\n", ret);
        mylib_close(listen_sock);
        return -1;
    }
    
    printf("TCP服务器已启动，监听端口 %d，等待连接...\n", port);
    
    /* 接受客户端连接 */
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    socket_handle_t client_sock = mylib_accept(listen_sock, (struct sockaddr*)&client_addr, &client_addr_len);
    
    if (!client_sock) {
        printf("接受连接失败\n");
        mylib_close(listen_sock);
        return -1;
    }
    
    printf("客户端已连接：%s:%d\n", 
           inet_ntoa(client_addr.sin_addr), 
           ntohs(client_addr.sin_port));
           
    /* 数据交换循环 */
    char recv_buffer[MAX_BUFFER_SIZE];
    char cmd_buffer[MAX_CMD_SIZE];
    char message[MAX_BUFFER_SIZE];
    
    fd_set read_fds;
    int stdin_fd = fileno(stdin);
    int running = 1;
    
    while (running) {
        FD_ZERO(&read_fds);
        FD_SET(stdin_fd, &read_fds);
        
        struct timeval tv = {1, 0}; /* 1秒超时 */
        
        int ready = select(stdin_fd + 1, &read_fds, NULL, NULL, &tv);
        
        if (ready > 0) {
            if (FD_ISSET(stdin_fd, &read_fds)) {
                /* 处理用户输入 */
                if (fgets(cmd_buffer, MAX_CMD_SIZE, stdin)) {
                    cmd_buffer[strcspn(cmd_buffer, "\n")] = 0; /* 移除换行符 */
                    
                    int cmd_result = parse_command(cmd_buffer, message);
                    if (cmd_result == 1) {
                        /* 发送消息 */
                        ssize_t sent = mylib_send(client_sock, message, strlen(message), 0);
                        if (sent < 0) {
                            printf("发送消息失败\n");
                        } else {
                            printf("消息已发送\n");
                        }
                    } else if (cmd_result == 0) {
                        /* 退出命令 */
                        running = 0;
                    }
                }
            }
        }
        
        /* 尝试接收数据 */
        ssize_t recv_len = mylib_recv(client_sock, recv_buffer, sizeof(recv_buffer) - 1, 0);
        if (recv_len > 0) {
            recv_buffer[recv_len] = '\0';
            printf("收到消息: %s\n", recv_buffer);
        }
    }
    
    /* 清理资源 */
    mylib_close(client_sock);
    mylib_close(listen_sock);
    printf("服务器已关闭\n");
    
    return 0;
}

/* 客户端模式函数 */
int client_mode(const mylib_config_t* config, const char* server_ip, uint16_t server_port) {
    mylib_error_t ret;
    
    /* 创建TCP socket */
    socket_handle_t sock = mylib_socket(AF_INET, SOCK_STREAM, 0);
    if (!sock) {
        printf("创建socket失败\n");
        return -1;
    }
    
    /* 连接到服务器 */
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) != 1) {
        printf("无效的IP地址\n");
        mylib_close(sock);
        return -1;
    }
    
    printf("正在连接到服务器 %s:%d...\n", server_ip, server_port);
    
    ret = mylib_bind(sock, NULL, 0); // 自动选择本地端口
    if (ret != MYLIB_SUCCESS) {
        printf("绑定地址失败: %d\n", ret);
        mylib_close(sock);
        return -1;
    }
    
    // 这里假设mylib_connect函数已在协议栈中实现
    // 对于目前的实现，我们使用一些变通方法模拟连接
    
    printf("连接成功！输入 'send <消息>' 发送消息，或 'quit' 退出\n");
    
    /* 数据交换循环 */
    char recv_buffer[MAX_BUFFER_SIZE];
    char cmd_buffer[MAX_CMD_SIZE];
    char message[MAX_BUFFER_SIZE];
    
    fd_set read_fds;
    int stdin_fd = fileno(stdin);
    int running = 1;
    
    while (running) {
        FD_ZERO(&read_fds);
        FD_SET(stdin_fd, &read_fds);
        
        struct timeval tv = {1, 0}; /* 1秒超时 */
        
        int ready = select(stdin_fd + 1, &read_fds, NULL, NULL, &tv);
        
        if (ready > 0) {
            if (FD_ISSET(stdin_fd, &read_fds)) {
                /* 处理用户输入 */
                if (fgets(cmd_buffer, MAX_CMD_SIZE, stdin)) {
                    cmd_buffer[strcspn(cmd_buffer, "\n")] = 0; /* 移除换行符 */
                    
                    int cmd_result = parse_command(cmd_buffer, message);
                    if (cmd_result == 1) {
                        /* 发送消息 */
                        ssize_t sent = mylib_send(sock, message, strlen(message), 0);
                        if (sent < 0) {
                            printf("发送消息失败\n");
                        } else {
                            printf("消息已发送\n");
                        }
                    } else if (cmd_result == 0) {
                        /* 退出命令 */
                        running = 0;
                    }
                }
            }
        }
        
        /* 尝试接收数据 */
        ssize_t recv_len = mylib_recv(sock, recv_buffer, sizeof(recv_buffer) - 1, 0);
        if (recv_len > 0) {
            recv_buffer[recv_len] = '\0';
            printf("收到消息: %s\n", recv_buffer);
        }
    }
    
    /* 清理资源 */
    mylib_close(sock);
    printf("客户端已关闭\n");
    
    return 0;
}

void print_usage(const char* program_name) {
    printf("用法:\n");
    printf("  服务器模式: %s -s [端口]\n", program_name);
    printf("  客户端模式: %s -c <服务器IP> [端口]\n", program_name);
    printf("默认端口为 12345\n");
}

int main(int argc, char *argv[]) {
    /* 解析命令行参数 */
    if (argc < 2) {
        print_usage(argv[0]);
        return -1;
    }
    
    int is_server = 0;
    char* server_ip = NULL;
    uint16_t port = 12345; /* 默认端口 */
    
    if (strcmp(argv[1], "-s") == 0) {
        /* 服务器模式 */
        is_server = 1;
        if (argc >= 3) {
            port = atoi(argv[2]);
        }
    } else if (strcmp(argv[1], "-c") == 0) {
        /* 客户端模式 */
        if (argc < 3) {
            printf("客户端模式需要指定服务器IP地址\n");
            print_usage(argv[0]);
            return -1;
        }
        server_ip = argv[2];
        if (argc >= 4) {
            port = atoi(argv[3]);
        }
    } else {
        printf("未知选项: %s\n", argv[1]);
        print_usage(argv[0]);
        return -1;
    }
    
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
        printf("初始化库失败\n");
        return -1;
    }
    
    /* 根据模式执行相应功能 */
    int result;
    if (is_server) {
        result = server_mode(&config, port);
    } else {
        result = client_mode(&config, server_ip, port);
    }
    
    /* 清理库 */
    mylib_cleanup();
    
    return result;
} 
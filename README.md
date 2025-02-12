# DPDK 网络协议栈项目

这是一个基于DPDK（Data Plane Development Kit）实现的高性能网络协议栈项目，支持TCP/UDP协议，并实现了基本的网络功能。

## 功能特性

- 基于DPDK的高性能数据包处理
- TCP/UDP协议支持
- ARP协议实现
- 支持大页内存配置
- 网卡DPDK模式绑定

## 系统要求

- Linux操作系统（推荐Ubuntu 20.04或更高版本）
- DPDK 21.11或更高版本
- gcc编译器
- make工具
- 支持DPDK的网卡

## 安装步骤

### 1. 安装DPDK依赖

```bash
sudo apt update
sudo apt install -y build-essential python3 python3-pip ninja-build meson pkg-config libnuma-dev
```

### 2. 配置系统环境

项目提供了自动配置脚本 `setup_dpdk.sh`，使用方法如下：

```bash
# 赋予脚本执行权限
chmod +x setup_dpdk.sh

# 运行配置脚本（需要root权限）
sudo ./setup_dpdk.sh -n <网卡名称>:<PCI地址> -p <大页内存数量>

# 例如：
sudo ./setup_dpdk.sh -n ens32:0000:02:02.0 -p 1024
```

参数说明：
- `-n, --nic`: 指定网卡名称和PCI地址
- `-p, --pages`: 设置大页内存数量（默认：1024）
- `-h, --help`: 显示帮助信息

### 3. 编译项目

```bash
# 在项目根目录下执行
make
```

编译后的可执行文件将生成在 `build` 目录下。

## 项目结构

```
.
├── socket/             # 核心协议栈实现
│   ├── dpdk_init/     # DPDK初始化相关代码
│   ├── unit_test/     # 单元测试
│   ├── tcp.c          # TCP协议实现
│   ├── udp.c          # UDP协议实现
│   └── arp.c          # ARP协议实现
├── build/             # 编译输出目录
├── setup_dpdk.sh      # DPDK环境配置脚本
└── Makefile          # 项目编译配置
```

## 注意事项

1. 运行 `setup_dpdk.sh` 脚本后需要重启系统以使所有更改生效
2. 确保网卡支持DPDK并已正确配置
3. 运行程序需要root权限
4. 如需恢复网卡到正常模式，可使用以下命令：
   ```bash
   dpdk-devbind.py --bind=<原始驱动> <PCI地址>
   ```

## 故障排除

1. 检查大页内存配置：
   ```bash
   cat /proc/meminfo | grep Huge
   ```

2. 检查网卡绑定状态：
   ```bash
   dpdk-devbind.py --status
   ```

3. 如果遇到编译错误，请确保已安装所有必要的依赖项。

## 贡献指南

欢迎提交Issue和Pull Request来帮助改进项目。在提交代码前，请确保：

1. 代码符合项目的编码规范
2. 添加了适当的单元测试
3. 所有测试用例都能通过
4. 更新了相关文档


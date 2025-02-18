# DPDK 网络协议栈项目

这是一个基于DPDK（Data Plane Development Kit）实现的高性能弹性网络协议栈项目，支持EDRP/TCP/UDP协议，并实现了基本的网络功能。

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

## ARP表配置

项目支持静态ARP表项的持久化存储，配置文件位于 `socket/arp_table.txt`。您可以手动编辑此文件来添加静态ARP表项。

### 文件格式

```
#VERSION=1
<IP十进制>,<MAC地址>,<状态>,<时间戳>
```

各字段说明：
- IP地址：使用十进制格式（例如：167772417 表示 10.0.0.1）
- MAC地址：使用冒号分隔的十六进制格式（例如：00:50:56:c0:00:01）
- 状态：1 表示静态表项
- 时间戳：Unix时间戳（可使用 `date +%s` 命令获取）

### 示例配置

```
#VERSION=1
167772417,00:50:56:c0:00:01,1,1708272720  # 10.0.0.1
167772418,00:0c:29:a1:b2:c3,1,1708272720  # 10.0.0.2
167772419,00:1a:a0:11:22:33,1,1708272720  # 10.0.0.3
167772420,00:25:90:44:55:66,1,1708272720  # 10.0.0.4
```

### IP地址转换

要将点分十进制IP转换为十进制格式，可以使用以下Python脚本：

```python
ip = "10.0.0.1"
decimal_ip = sum(int(x) * (256 ** (3-i)) for i, x in enumerate(ip.split('.')))
print(decimal_ip)  # 输出：167772417
```

或使用以下bash命令：

```bash
ip="10.0.0.1"
printf '%d\n' $(echo $ip | awk -F. '{print ($1*256^3)+($2*256^2)+($3*256)+$4}')
```

### 注意事项

1. 文件权限应设置为644（所有者可读写，其他用户只读）
2. 每次修改后需要重启服务使更改生效
3. 时间戳可以使用当前时间，不影响静态表项的功能
4. MAC地址必须是有效的硬件地址格式

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


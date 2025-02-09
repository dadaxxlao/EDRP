#!/bin/bash

# 检查是否以root权限运行
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 配置参数
HUGEPAGE_SIZE=2048 # 2MB per page
HUGEPAGE_COUNT=1024 # 2GB total
NIC_PCI="0000:02:01.0" # 网卡PCI地址

echo -e "${YELLOW}Starting DPDK environment setup...${NC}"

# 函数：检查命令是否存在
check_command() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}Error: $1 command not found${NC}"
        exit 1
    fi
}

# 检查必要的命令
check_command "dpdk-devbind.py"
check_command "modprobe"

# 配置Hugepages
echo -e "${YELLOW}Configuring hugepages...${NC}"

# 创建挂载点
mkdir -p /mnt/huge

# 卸载已有的hugetlbfs挂载
if mount | grep "hugetlbfs" > /dev/null; then
    umount /mnt/huge
fi

# 设置hugepages数量
echo $HUGEPAGE_COUNT > /sys/kernel/mm/hugepages/hugepages-${HUGEPAGE_SIZE}kB/nr_hugepages

# 挂载hugepages
mount -t hugetlbfs nodev /mnt/huge

# 验证hugepages配置
MOUNTED_HUGE=$(mount | grep hugetlbfs | wc -l)
HUGE_PAGES=$(cat /sys/kernel/mm/hugepages/hugepages-${HUGEPAGE_SIZE}kB/nr_hugepages)

if [ $MOUNTED_HUGE -eq 0 ] || [ $HUGE_PAGES -eq 0 ]; then
    echo -e "${RED}Error: Hugepages configuration failed${NC}"
    exit 1
else
    echo -e "${GREEN}Hugepages configured successfully${NC}"
    echo -e "Total hugepages: $HUGE_PAGES"
fi

# 配置网卡
echo -e "\n${YELLOW}Configuring NIC...${NC}"

# 加载vfio-pci模块
modprobe vfio-pci

# 检查网卡是否存在
if ! dpdk-devbind.py --status | grep $NIC_PCI > /dev/null; then
    echo -e "${RED}Error: NIC with PCI address $NIC_PCI not found${NC}"
    exit 1
fi

# 绑定网卡到vfio-pci
echo -e "Binding NIC $NIC_PCI to vfio-pci driver..."
dpdk-devbind.py --bind=vfio-pci $NIC_PCI

# 验证绑定状态
if dpdk-devbind.py --status | grep "$NIC_PCI.*drv=vfio-pci" > /dev/null; then
    echo -e "${GREEN}NIC bound successfully to vfio-pci${NC}"
else
    echo -e "${RED}Error: Failed to bind NIC to vfio-pci${NC}"
    exit 1
fi

# 显示当前状态
echo -e "\n${YELLOW}Current system status:${NC}"
echo -e "\nHugepage Info:"
grep Huge /proc/meminfo
echo -e "\nNIC Binding Status:"
dpdk-devbind.py --status | grep -A 1 "Network devices using DPDK-compatible driver"

# 添加持久化配置（可选）
echo -e "\n${YELLOW}Adding persistent configuration...${NC}"
if ! grep "hugetlbfs" /etc/fstab > /dev/null; then
    echo "nodev /mnt/huge hugetlbfs defaults 0 0" >> /etc/fstab
    echo -e "${GREEN}Added hugepage mount to /etc/fstab${NC}"
fi

# 创建模块加载配置
echo "vfio-pci" > /etc/modules-load.d/vfio-pci.conf

echo -e "\n${GREEN}DPDK environment setup completed successfully!${NC}"
echo -e "${YELLOW}Note: Please reboot to ensure all changes take effect properly${NC}"

# 显示使用提示
echo -e "\n${YELLOW}Usage Instructions:${NC}"
echo "1. To verify hugepages: cat /proc/meminfo | grep Huge"
echo "2. To check NIC status: dpdk-devbind.py --status"
echo "3. To restore NIC to kernel driver: dpdk-devbind.py --bind=<original_driver> $NIC_PCI"

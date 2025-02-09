#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}开始EDRP Socket单元测试...${NC}"

# 检查是否以root权限运行
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}错误: 需要root权限来运行DPDK测试${NC}"
    exit 1
fi

# 创建构建目录
mkdir -p build
cd build

# 运行CMake构建
echo -e "${YELLOW}配置CMake...${NC}"
cmake ..

# 编译测试
echo -e "${YELLOW}编译测试...${NC}"
make

# 运行测试
echo -e "${YELLOW}运行测试...${NC}"
strace -f -o strace.log ./test_init

# 检查测试结果
if [ $? -eq 0 ]; then
    echo -e "${GREEN}所有测试通过！${NC}"
else
    echo -e "${RED}测试失败！${NC}"
    exit 1
fi 
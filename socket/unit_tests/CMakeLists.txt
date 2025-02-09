cmake_minimum_required(VERSION 3.10)
project(EDRP_Socket_Tests C)

# 设置C标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 添加SSSE3支持
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mssse3")

# 查找DPDK包
find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

# 设置DPDK链接选项
link_directories(${DPDK_LIBRARY_DIRS})
string(REPLACE ";" " " DPDK_LDFLAGS_STR "${DPDK_LDFLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${DPDK_LDFLAGS_STR}")

# 添加Unity测试框架
add_library(unity STATIC
    ../unity/unity.c
    ../unity/unity_internals.h
    ../unity/unity.h
)

# 设置包含目录
include_directories(
    ${CMAKE_SOURCE_DIR}/..
    ${DPDK_INCLUDE_DIRS}
    unity
)

# 添加测试可执行文件
add_executable(test_init
    test_init.c
    ../socket.c
    ../tcp.c
    ../arp.c
    ../udp.c
)

# 链接依赖库
target_link_libraries(test_init
    unity
    ${DPDK_LIBRARIES}
    pthread
)

# 添加测试
enable_testing()
add_test(NAME test_init COMMAND test_init) 
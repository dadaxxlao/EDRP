project('examples', 'c')

inc = include_directories('../../socket/include')

# 添加UDP示例程序
executable('udp_example',
    'udp_example.c',
    include_directories: [inc],
    dependencies: [dpdk_dep, mylib_dep],
    install: true)

# 添加TCP示例程序
executable('tcp_example',
    'tcp_example.c',
    include_directories: [inc],
    dependencies: [dpdk_dep, mylib_dep],
    install: true)
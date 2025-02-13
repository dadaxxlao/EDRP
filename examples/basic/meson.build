inc = include_directories('../../socket/include')

executable('udp_example',
    'udp_example.c',
    include_directories: [inc],
    dependencies: [dpdk_dep, mylib_dep],
    install: true) 
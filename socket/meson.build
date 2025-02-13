# 源文件列表
sources = [
  'src/core.c',
  'src/tcp.c',
  'src/udp.c',
  'src/arp.c',
  'src/logging.c',
  'src/rings.c',
  'src/dpdk_init.c',
  'src/fd_manager.c',
  'src/socket_api.c'
]

# 头文件目录
socket_inc = include_directories('include', 'src/internal')

# 创建共享库
mylib = shared_library('mylib',
  sources,
  include_directories : [inc, socket_inc],
  dependencies : dpdk_dep,
  install : true,
  install_dir : get_option('libdir')
)

# 安装头文件
install_headers('include/mylib/core.h',
  subdir : 'mylib'
)

# 为其他部分提供依赖对象
mylib_dep = declare_dependency(
  link_with : mylib,
  include_directories : [inc, socket_inc]
) 
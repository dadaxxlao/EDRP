project('mylib', 'c',
  version : '0.1.0',
  default_options : [
    'warning_level=3',
    'c_std=gnu11',
    'buildtype=release',
  ]
)

# 编译器配置
cc = meson.get_compiler('c')

# 检查DPDK依赖
dpdk_dep = dependency('libdpdk', required : true)

# 添加全局编译参数
add_project_arguments('-D_GNU_SOURCE', language : 'c')

# 添加全局包含路径
inc = include_directories('socket/include')

# 添加子目录
subdir('socket')

# 导出mylib依赖
mylib_dep = declare_dependency(
  include_directories: inc,
  link_with: mylib,
  dependencies: dpdk_dep
)

# 构建示例程序
subdir('examples/basic')


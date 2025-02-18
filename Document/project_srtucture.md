EDRP
├── builddir # 编译文件夹，不需要详细看
│   ├── meson-info
│   ├── meson-logs
│   ├── meson-private
│   └── socket
├── Document # 文档文件夹
│   ├── prd.md # 项目需求
│   └── project_srtucture.md # 项目结构
├── examples # Socket使用示例文件夹
│   └── basic
│       ├── meson.build # 编译文件
│       └── udp_example.c # udp示例代码
├── meson.build # 编译文件
├── meson_options.txt # 编译选项
├── ng-arp.h # 参考socket的头文件
├── ng-tcp.c # 参考socket的实现（已经实现socket代码，并跑通，主要进行参考）
├── README.md # 项目说明
├── setup_dpdk.sh # 设置DPDK环境变量，安装DPDK环境
└── socket
    ├── builddir # 编译文件夹
    │   ├── meson-info
    │   ├── meson-logs
    │   │   └── meson-log.txt
    │   └── meson-private
    │       └── meson.lock
    ├── include # 头文件夹
    │   └── mylib
    │       ├── core.h #核心头文件，用于向外提供接口
    │       └── ex_logging.h # 外部日志头文件，主要定义日志等级
    ├── meson.build # 编译文件
    ├── arp_table.txt # arp表文件
    ├── src # 源码文件夹
       ├── arp.c # arp实现
       ├── core.c # 核心实现，主要完成初始化和清理工作
       ├── dpdk_init.c # dpdk初始化实现
       ├── fd_manager.c # 文件描述符管理实现
       ├── logging.c #日志系统相关实现
       ├── rings.c # 环形缓冲区实现
       ├── socket_api.c # socket api实现
       ├── tcp.c # tcp实现
       ├── udp.c # udp实现
       ├── internal # 内部实现
          ├── arp_impl.h # arp实现头文件
          ├── common.h # 内部公共头文件
          ├── dpdk_init.h # dpdk初始化头文件
          ├── logging.h # 日志头文件
          ├── tcp_impl.h # tcp实现头文件
          └── udp_impl.h # udp实现头文件



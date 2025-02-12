project('edrp_socket_tests', 'c',
  version : '1.0.0',
  default_options : ['warning_level=3'])

# 添加DPDK依赖
dpdk_dep = dependency('libdpdk', required : true)
thread_dep = dependency('threads', required : true)

# 添加测试源文件
test_sources = [
  'test_init.c',
]

# 添加主项目源文件
socket_sources = [
  '../socket.c',
  '../tcp.c',
  '../udp.c',
  '../arp.c',
]

# 编译选项
test_c_args = [
  '-D_GNU_SOURCE',
  '-march=native',
  '-mrtm',
  '-include', 'rte_config.h',
  '-DALLOW_EXPERIMENTAL_API'
]

# 包含目录
include_dirs = include_directories('..',
                                 '/usr/local/include')

# 创建测试可执行文件
test_init = executable('test_init',
  sources: [test_sources, socket_sources],
  dependencies: [dpdk_dep, thread_dep],
  c_args: test_c_args,
  include_directories: include_dirs,
  link_args: [
    '-L/usr/local/lib/x86_64-linux-gnu',
    '-Wl,--as-needed',
    '-lrte_node', '-lrte_graph', '-lrte_pipeline', '-lrte_table', '-lrte_pdump',
    '-lrte_port', '-lrte_fib', '-lrte_pdcp', '-lrte_ipsec', '-lrte_vhost',
    '-lrte_stack', '-lrte_security', '-lrte_sched', '-lrte_reorder', '-lrte_rib',
    '-lrte_mldev', '-lrte_regexdev', '-lrte_rawdev', '-lrte_power', '-lrte_pcapng',
    '-lrte_member', '-lrte_lpm', '-lrte_latencystats', '-lrte_jobstats',
    '-lrte_ip_frag', '-lrte_gso', '-lrte_gro', '-lrte_gpudev', '-lrte_dispatcher',
    '-lrte_eventdev', '-lrte_efd', '-lrte_dmadev', '-lrte_distributor',
    '-lrte_cryptodev', '-lrte_compressdev', '-lrte_cfgfile', '-lrte_bpf',
    '-lrte_bitratestats', '-lrte_bbdev', '-lrte_acl', '-lrte_timer', '-lrte_hash',
    '-lrte_metrics', '-lrte_cmdline', '-lrte_pci', '-lrte_ethdev', '-lrte_meter',
    '-lrte_net', '-lrte_mbuf', '-lrte_mempool', '-lrte_rcu', '-lrte_ring',
    '-lrte_eal', '-lrte_telemetry', '-lrte_argparse', '-lrte_kvargs', '-lrte_log',
    '-lnuma', '-lpthread', '-ldl'
  ]
)

# 注册测试
test('DPDK初始化测试', test_init) 
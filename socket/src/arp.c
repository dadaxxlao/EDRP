/**
 * @file arp.c
 * @brief ARP协议实现
 *
 * 实现ARP协议的核心功能，包括ARP表管理、ARP请求处理、ARP应答处理等。
 * 基于DPDK实现高性能网络通信。
 *
 * @author 冯昊阳
 * @date 2025年2月18日
 */
#include <rte_arp.h>
#include <rte_malloc.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>     /* 为fsync函数 */
#include <sys/types.h>

#include "internal/arp_impl.h"
#include "internal/logging.h"
#include "internal/common.h"

/* 全局变量 */
struct arp_entry *g_arp_table = NULL;
struct arp_request *g_arp_requests = NULL;
pthread_mutex_t g_arp_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile int g_arp_table_dirty = 0;  /* 数据是否被修改的标志 */
volatile int g_static_entry_count = 0;  // 静态条目计数

/* MAC地址解析函数 */
static int parse_mac_address(const char *str, uint8_t mac[RTE_ETHER_ADDR_LEN]) {
    unsigned int values[6];
    int items = sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
                       &values[0], &values[1], &values[2],
                       &values[3], &values[4], &values[5]);
    
    if (items != 6) return -1;
    
    for (int i = 0; i < 6; i++) {
        if (values[i] > 0xFF) return -1;
        mac[i] = (uint8_t)values[i];
    }
    
    return 0;
}

/* 创建ARP表存储目录 */
static mylib_error_t create_arp_directory(void) {
    const char *dir = "/var/lib/mylib";
    struct stat st;
    
    /* 检查目录是否存在 */
    if (stat(dir, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            MYLIB_LOG(LOG_LEVEL_ERROR, "%s exists but is not a directory", dir);
            return MYLIB_ERROR_IO;
        }
        return MYLIB_SUCCESS;
    }
    
    /* 创建目录 */
    if (mkdir(dir, ARP_TABLE_DIR_MODE) != 0) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to create directory %s: %s", 
                 dir, strerror(errno));
        return MYLIB_ERROR_IO;
    }
    
    return MYLIB_SUCCESS;
}

mylib_error_t arp_init(void) {
    pthread_mutex_lock(&g_arp_mutex);
    g_arp_table = NULL;
    g_arp_requests = NULL;
    pthread_mutex_unlock(&g_arp_mutex);
    
    /* 加载ARP表 */
    mylib_error_t ret = arp_load_table();
    if (ret != MYLIB_SUCCESS) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to load ARP table");
        return ret;
    }
    
    MYLIB_LOG(LOG_LEVEL_INFO, "ARP module initialized");
    return MYLIB_SUCCESS;
}

void arp_cleanup(void) {
    /* 保存ARP表 */
    arp_save_table();
    
    pthread_mutex_lock(&g_arp_mutex);
    
    /* 清理ARP表 */
    struct arp_entry *entry = g_arp_table;
    while (entry) {
        struct arp_entry *next = entry->next;
        rte_free(entry);
        entry = next;
    }
    g_arp_table = NULL;
    
    /* 清理请求队列 */
    struct arp_request *req = g_arp_requests;
    while (req) {
        struct arp_request *next = req->next;
        if (req->pending_packet) {
            rte_pktmbuf_free(req->pending_packet);
        }
        rte_free(req);
        req = next;
    }
    g_arp_requests = NULL;
    
    pthread_mutex_unlock(&g_arp_mutex);
    
    MYLIB_LOG(LOG_LEVEL_INFO, "ARP module cleaned up");
}

struct arp_entry *arp_lookup(uint32_t ip) {
    pthread_mutex_lock(&g_arp_mutex);
    
    struct arp_entry *entry;
    for (entry = g_arp_table; entry != NULL; entry = entry->next) {
        if (entry->ip == ip) {
            break;
        }
    }
    
    pthread_mutex_unlock(&g_arp_mutex);
    return entry;
}

mylib_error_t arp_add_entry(uint32_t ip, const uint8_t *mac, 
                           uint8_t state, time_t timestamp) {
    struct arp_entry *entry = rte_malloc("arp_entry", sizeof(struct arp_entry), 0);
    if (!entry) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to allocate ARP entry");
        return MYLIB_ERROR_NOMEM;
    }

    /* 初始化表项 */
    entry->ip = ip;
    rte_memcpy(entry->mac, mac, RTE_ETHER_ADDR_LEN);
    entry->state = state;
    entry->timestamp = timestamp;
    
    /* 添加到ARP表 */
    pthread_mutex_lock(&g_arp_mutex);
    LL_ADD(entry, g_arp_table);
    if (state == ARP_ENTRY_STATE_STATIC) {
        g_static_entry_count++;
        g_arp_table_dirty = 1;
    }
    pthread_mutex_unlock(&g_arp_mutex);
    
    MYLIB_LOG(LOG_LEVEL_DEBUG, "Added ARP entry for IP %u.%u.%u.%u",
            (ip & 0xFF), (ip >> 8) & 0xFF,
            (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
    return MYLIB_SUCCESS;
}

void arp_remove_entry(struct arp_entry *entry) {
    if (!entry) return;

    pthread_mutex_lock(&g_arp_mutex);
    LL_REMOVE(entry, g_arp_table);
    if (entry->state == ARP_ENTRY_STATE_STATIC) {
        g_static_entry_count--;
        g_arp_table_dirty = 1;
    }
    rte_free(entry);
    pthread_mutex_unlock(&g_arp_mutex);
    
    MYLIB_LOG(LOG_LEVEL_DEBUG, "Removed ARP entry");
}

void arp_update_entry(struct arp_entry *entry, const uint8_t *mac) {
    if (!entry) return;

    pthread_mutex_lock(&g_arp_mutex);
    rte_memcpy(entry->mac, mac, RTE_ETHER_ADDR_LEN);
    entry->timestamp = time(NULL);
    if (entry->state == ARP_ENTRY_STATE_STATIC) {
        g_arp_table_dirty = 1;
    }
    pthread_mutex_unlock(&g_arp_mutex);
    
    MYLIB_LOG(LOG_LEVEL_DEBUG, "Updated ARP entry for IP %u.%u.%u.%u",
            (entry->ip & 0xFF), (entry->ip >> 8) & 0xFF,
            (entry->ip >> 16) & 0xFF, (entry->ip >> 24) & 0xFF);
}

mylib_error_t arp_queue_packet(uint32_t ip, struct rte_mbuf *mbuf) {
    struct arp_request *req = rte_malloc("arp_request", sizeof(struct arp_request), 0);
    if (!req) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to allocate ARP request");
        return MYLIB_ERROR_NOMEM;
    }

    /* 初始化请求 */
    req->ip = ip;
    req->pending_packet = mbuf;
    req->timestamp = time(NULL);
    req->retry_count = 0;
    
    /* 添加到请求队列 */
    pthread_mutex_lock(&g_arp_mutex);
    LL_ADD(req, g_arp_requests);
    pthread_mutex_unlock(&g_arp_mutex);
    
    //MYLIB_LOG(LOG_LEVEL_DEBUG, "Queued packet for IP 0x%x", ip);
    MYLIB_LOG(LOG_LEVEL_DEBUG, "Queued packet for IP %u.%u.%u.%u", 
            (ip & 0xFF),
            (ip >> 8) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 24) & 0xFF); 
    return MYLIB_SUCCESS;
}

void arp_process_pending_requests(void) {
    pthread_mutex_lock(&g_arp_mutex);
    
    time_t now = time(NULL);
    struct arp_request *req = g_arp_requests;
    
    while (req) {
        struct arp_request *next = req->next;
        
        /* 检查是否超时 */
        if (now - req->timestamp >= ARP_PENDING_TIMEOUT) {
            if (req->retry_count < 3) {
                /* 重新发送ARP请求 */
                struct rte_mbuf *arp_req = arp_create_request(req->ip);
                if (arp_req) {
                    rte_ring_mp_enqueue(g_out_ring, arp_req);
                    req->timestamp = now;
                    req->retry_count++;
                }
            } else {
                /* 超过重试次数，放弃该请求 */
                if (req->pending_packet) {
                    rte_pktmbuf_free(req->pending_packet);
                }
                LL_REMOVE(req, g_arp_requests);
                rte_free(req);
            }
        }
        
        req = next;
    }
    
    pthread_mutex_unlock(&g_arp_mutex);
}

void arp_cleanup_pending_requests(void) {
    pthread_mutex_lock(&g_arp_mutex);
    
    struct arp_request *req = g_arp_requests;
    while (req) {
        struct arp_request *next = req->next;
        if (req->pending_packet) {
            rte_pktmbuf_free(req->pending_packet);
        }
        rte_free(req);
        req = next;
    }
    g_arp_requests = NULL;
    
    pthread_mutex_unlock(&g_arp_mutex);
}

struct rte_mbuf *arp_create_request(uint32_t target_ip) {
    /* 分配mbuf */
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(g_mbuf_pool);
    if (!mbuf) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to allocate mbuf for ARP request");
        return NULL;
    }

    /* 计算总长度 */
    uint16_t total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    
    /* 初始化mbuf */
    mbuf->data_len = total_len;
    mbuf->pkt_len = total_len;
    
    /* 构建以太网头 */
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    rte_memcpy(eth_hdr->src_addr.addr_bytes, g_local_mac, RTE_ETHER_ADDR_LEN);
    memset(eth_hdr->dst_addr.addr_bytes, 0xFF, RTE_ETHER_ADDR_LEN);  // 广播
    eth_hdr->ether_type = htons(RTE_ETHER_TYPE_ARP);
    
    /* 构建ARP头 */
    struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);
    arp_hdr->arp_hardware = htons(RTE_ARP_HRD_ETHER);
    arp_hdr->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp_hdr->arp_plen = sizeof(uint32_t);
    arp_hdr->arp_opcode = htons(RTE_ARP_OP_REQUEST);
    
    rte_memcpy(arp_hdr->arp_data.arp_sha.addr_bytes, g_local_mac, RTE_ETHER_ADDR_LEN);
    arp_hdr->arp_data.arp_sip = g_local_ip;
    memset(arp_hdr->arp_data.arp_tha.addr_bytes, 0, RTE_ETHER_ADDR_LEN);
    arp_hdr->arp_data.arp_tip = target_ip;
    
    return mbuf;
}

struct rte_mbuf *arp_create_reply(uint32_t sender_ip, uint32_t target_ip,
                                const uint8_t *target_mac) {
    /* 分配mbuf */
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(g_mbuf_pool);
    if (!mbuf) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to allocate mbuf for ARP reply");
        return NULL;
    }

    /* 计算总长度 */
    uint16_t total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    
    /* 初始化mbuf */
    mbuf->data_len = total_len;
    mbuf->pkt_len = total_len;
    
    /* 构建以太网头 */
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    rte_memcpy(eth_hdr->src_addr.addr_bytes, g_local_mac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth_hdr->dst_addr.addr_bytes, target_mac, RTE_ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(RTE_ETHER_TYPE_ARP);
    
    /* 构建ARP头 */
    struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);
    arp_hdr->arp_hardware = htons(RTE_ARP_HRD_ETHER);
    arp_hdr->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp_hdr->arp_plen = sizeof(uint32_t);
    arp_hdr->arp_opcode = htons(RTE_ARP_OP_REPLY);
    
    rte_memcpy(arp_hdr->arp_data.arp_sha.addr_bytes, g_local_mac, RTE_ETHER_ADDR_LEN);
    arp_hdr->arp_data.arp_sip = sender_ip;
    rte_memcpy(arp_hdr->arp_data.arp_tha.addr_bytes, target_mac, RTE_ETHER_ADDR_LEN);
    arp_hdr->arp_data.arp_tip = target_ip;
    
    return mbuf;
}

mylib_error_t arp_process_packet(struct rte_mbuf *mbuf) {
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);
    
    /* 检查ARP包类型 */
    if (ntohs(arp_hdr->arp_hardware) != RTE_ARP_HRD_ETHER ||
        ntohs(arp_hdr->arp_protocol) != RTE_ETHER_TYPE_IPV4 ||
        arp_hdr->arp_hlen != RTE_ETHER_ADDR_LEN ||
        arp_hdr->arp_plen != sizeof(uint32_t)) {
        MYLIB_LOG(LOG_LEVEL_WARNING, "Invalid ARP packet format");
        return MYLIB_ERROR_INVALID;
    }

    uint16_t opcode = ntohs(arp_hdr->arp_opcode);
    switch (opcode) {
        case RTE_ARP_OP_REQUEST:
            /* 处理ARP请求 */
            if (arp_hdr->arp_data.arp_tip == g_local_ip) {
                /* 发送ARP应答 */
                struct rte_mbuf *reply = arp_create_reply(g_local_ip,
                                                        arp_hdr->arp_data.arp_sip,
                                                        arp_hdr->arp_data.arp_sha.addr_bytes);
                if (reply) {
                    rte_ring_mp_enqueue(g_out_ring, reply);
                }
            }
            break;
            
        case RTE_ARP_OP_REPLY:
            /* 处理ARP应答 */
            {
                struct arp_entry *entry = arp_lookup(arp_hdr->arp_data.arp_sip);
                if (entry) {
                    /* 更新已存在的表项 */
                    arp_update_entry(entry, arp_hdr->arp_data.arp_sha.addr_bytes);
                } else {
                    /* 添加新表项 */
                    arp_add_entry(arp_hdr->arp_data.arp_sip,
                                arp_hdr->arp_data.arp_sha.addr_bytes,
                                ARP_ENTRY_STATE_DYNAMIC,
                                time(NULL));
                }
                
                /* 处理等待该IP的数据包 */
                pthread_mutex_lock(&g_arp_mutex);
                struct arp_request *req = g_arp_requests;
                while (req) {
                    if (req->ip == arp_hdr->arp_data.arp_sip) {
                        if (req->pending_packet) {
                            /* 更新数据包的目标MAC地址并发送 */
                            struct rte_ether_hdr *pkt_eth = rte_pktmbuf_mtod(req->pending_packet,
                                                                           struct rte_ether_hdr *);
                            rte_memcpy(pkt_eth->dst_addr.addr_bytes,
                                     arp_hdr->arp_data.arp_sha.addr_bytes,
                                     RTE_ETHER_ADDR_LEN);
                            rte_ring_mp_enqueue(g_out_ring, req->pending_packet);
                            req->pending_packet = NULL;
                        }
                        struct arp_request *next = req->next;
                        LL_REMOVE(req, g_arp_requests);
                        rte_free(req);
                        req = next;
                    } else {
                        req = req->next;
                    }
                }
                pthread_mutex_unlock(&g_arp_mutex);
                /* 通知TCP模块ARP已解析 */
                tcp_handle_arp_resolution(arp_hdr->arp_data.arp_sip,
                                arp_hdr->arp_data.arp_sha.addr_bytes);
            }
            break;
            
        default:
            MYLIB_LOG(LOG_LEVEL_WARNING, "Unknown ARP opcode: %d", opcode);
            return MYLIB_ERROR_INVALID;
    }
    
    return MYLIB_SUCCESS;
}

void arp_timer_handler(void) {
    static time_t last_save = 0;
    time_t now = time(NULL);
    
    /* 定期保存ARP表 */
    if (now - last_save >= ARP_TABLE_SAVE_INTERVAL) {
        arp_save_table();
        last_save = now;
    }
    
    pthread_mutex_lock(&g_arp_mutex);
    
    time_t now_local = time(NULL);
    struct arp_entry *entry = g_arp_table;
    
    while (entry) {
        struct arp_entry *next = entry->next;
        
        /* 检查动态表项是否超时 */
        if (entry->state == ARP_ENTRY_STATE_DYNAMIC &&
            now_local - entry->timestamp >= ARP_ENTRY_TIMEOUT) {
            LL_REMOVE(entry, g_arp_table);
            rte_free(entry);
        }
        
        entry = next;
    }
    
    pthread_mutex_unlock(&g_arp_mutex);
    
    /* 处理等待中的ARP请求 */
    arp_process_pending_requests();
}

/* 保存ARP表到文件 */
mylib_error_t arp_save_table(void) {
    /* 如果没有静态条目或数据未修改，直接返回 */
    if (g_static_entry_count == 0 || !g_arp_table_dirty) {
        return MYLIB_SUCCESS;
    }

    char tmp_file[PATH_MAX];
    FILE *fp;
    struct arp_entry *entry;
    time_t start_time = time(NULL);
    
    snprintf(tmp_file, sizeof(tmp_file), "%s.tmp", ARP_TABLE_FILE);
    
    fp = fopen(tmp_file, "w");
    if (!fp) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to open %s: %s", 
                 tmp_file, strerror(errno));
        return MYLIB_ERROR_IO;
    }
    
    /* 设置文件权限 */
    fchmod(fileno(fp), ARP_TABLE_FILE_MODE);
    
    /* 写入版本信息 */
    if (fprintf(fp, "#VERSION=%d\n", ARP_TABLE_VERSION) < 0) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to write version: %s", strerror(errno));
        fclose(fp);
        remove(tmp_file);
        return MYLIB_ERROR_IO;
    }
    
    /* 写入ARP表项 */
    int saved = 0;
    pthread_mutex_lock(&g_arp_mutex);
    for (entry = g_arp_table; entry != NULL; entry = entry->next) {
        if (entry->state == ARP_ENTRY_STATE_STATIC) {
            if (fprintf(fp, "%u,%02x:%02x:%02x:%02x:%02x:%02x,%u,%ld\n",
                    entry->ip,
                    entry->mac[0], entry->mac[1], entry->mac[2],
                    entry->mac[3], entry->mac[4], entry->mac[5],
                    entry->state,
                    entry->timestamp) < 0) {
                pthread_mutex_unlock(&g_arp_mutex);
                MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to write entry: %s", 
                         strerror(errno));
                fclose(fp);
                remove(tmp_file);
                return MYLIB_ERROR_IO;
            }
            saved++;
        }
    }
    pthread_mutex_unlock(&g_arp_mutex);
    
    /* 确保数据写入磁盘 */
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to flush data: %s", strerror(errno));
        fclose(fp);
        remove(tmp_file);
        return MYLIB_ERROR_IO;
    }
    fclose(fp);
    
    /* 原子替换文件 */
    if (rename(tmp_file, ARP_TABLE_FILE) != 0) {
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to rename %s to %s: %s",
                 tmp_file, ARP_TABLE_FILE, strerror(errno));
        remove(tmp_file);
        return MYLIB_ERROR_IO;
    }
    
    g_arp_table_dirty = 0;
    
    MYLIB_LOG(LOG_LEVEL_INFO, 
             "Saved %d ARP entries (took %ld seconds)",
             saved, time(NULL) - start_time);
    return MYLIB_SUCCESS;
}

/* 从文件加载ARP表 */
mylib_error_t arp_load_table(void) {
    FILE *fp;
    char line[256];
    uint32_t ip;
    uint8_t mac[RTE_ETHER_ADDR_LEN];
    uint8_t state;
    time_t timestamp;
    int loaded = 0, line_num = 0;
    int version = 0;
    time_t start_time = time(NULL);
    
    mylib_error_t ret = create_arp_directory();
    if (ret != MYLIB_SUCCESS) {
        return ret;
    }
    
    fp = fopen(ARP_TABLE_FILE, "r");
    if (!fp) {
        if (errno == ENOENT) {
            MYLIB_LOG(LOG_LEVEL_INFO, "No ARP table file found");
            return MYLIB_SUCCESS;
        }
        MYLIB_LOG(LOG_LEVEL_ERROR, "Failed to open %s: %s",
                 ARP_TABLE_FILE, strerror(errno));
        return MYLIB_ERROR_IO;
    }
    
    /* 读取版本信息 */
    line_num++;
    if (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "#VERSION=%d", &version) != 1 || 
            version != ARP_TABLE_VERSION) {
            MYLIB_LOG(LOG_LEVEL_ERROR, 
                     "Invalid version at line %d: %s", line_num, line);
            fclose(fp);
            return MYLIB_ERROR_INVALID;
        }
    }
    
    /* 读取表项 */
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        char mac_str[18];
        if (sscanf(line, "%u,%17s,%hhu,%ld",
                   &ip, mac_str, &state, &timestamp) == 4) {
            
            /* 解析MAC地址 */
            if (parse_mac_address(mac_str, mac) != 0) {
                MYLIB_LOG(LOG_LEVEL_WARNING, 
                         "Invalid MAC at line %d: %s", line_num, mac_str);
                continue;
            }
            
            /* 添加表项 */
            if (arp_add_entry(ip, mac, state, timestamp) == MYLIB_SUCCESS) {
                loaded++;
            }
        } else {
            MYLIB_LOG(LOG_LEVEL_WARNING, 
                     "Invalid format at line %d: %s", line_num, line);
        }
    }
    
    fclose(fp);
    
    MYLIB_LOG(LOG_LEVEL_INFO, 
             "Loaded %d ARP entries (took %ld seconds)",
             loaded, time(NULL) - start_time);
    return MYLIB_SUCCESS;
} 
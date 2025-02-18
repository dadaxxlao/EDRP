#ifndef _ICMP_IMPL_H_
#define _ICMP_IMPL_H_

#include <rte_mbuf.h>
#include <rte_icmp.h>
#include "common.h"
#include "arp_impl.h" /*作为填充ICMP包头时，获取相应的MAC*/

/* ICMP处理函数声明 */
mylib_error_t icmp_init(void);
void icmp_cleanup(void);
mylib_error_t icmp_process_packet(struct rte_mbuf *mbuf);

/* ICMP校验和计算函数 */
uint16_t icmp_checksum(const void *buf, size_t len);

#endif /* _ICMP_IMPL_H_ */ 
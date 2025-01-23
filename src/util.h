/* util.h */

#ifndef _UTIL_H_
#define _UTIL_H_


#define min(a, b) (((a) > (b)) ? (b) : (a))
#define max(a, b) (((a) > (b)) ? (a) : (b))

#define array_size(a) (sizeof(a) / sizeof(a[0]))


# define likely(x)	__builtin_expect(!!(x), 1)
# define unlikely(x)	__builtin_expect(!!(x), 0)


/* check one sqe exists before get sqe */
struct io_uring_sqe *io_uring_get_sqe_always(struct io_uring *ring);


/* convert sockaddr to ADDR:PORT string onto buf */
void sockaddr_ntop(struct sockaddr_storage *ss, char *buf, socklen_t size);
char *sockaddr_ntoa(struct sockaddr_storage *ss);


/* tcp_info */
#include <linux/tcp.h>
#ifndef SOL_TCP
#define SOL_TCP	6	/* SOL_TCP does not exist on linux/tcp.h */
#endif

/* put key=value ... string of tcp_info onto buf */
int build_tcp_info_string(struct tcp_info *info, char *buf, size_t size);

#endif

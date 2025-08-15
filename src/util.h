/* util.h */
#ifndef _UTIL_H_
#define _UTIL_H_


#define min(a, b) (((a) > (b)) ? (b) : (a))
#define max(a, b) (((a) > (b)) ? (a) : (b))

#define array_size(a) (sizeof(a) / sizeof(a[0]))

#include <sys/socket.h>

/* convert sockaddr to ADDR:PORT string onto buf */
void sockaddr_ntop(struct sockaddr_storage *ss, char *buf, socklen_t size);
char *sockaddr_ntoa(struct sockaddr_storage *ss);


/* tcp_info */
#include <linux/tcp.h>
#ifndef SOL_TCP
#define SOL_TCP	6	/* SOL_TCP does not exist on linux/tcp.h */
#endif

/* put key=value ... string of tcp_info of the sock onto buf */
int build_tcp_info_string(int sock, char *buf, size_t size);

#define TCP_INFO_STRLEN	128


/* stop flag */
#include <stdbool.h>

void start_running(void);
void stop_running(void);
bool is_running(void);


/* wait (partial busy poll) until the specified time (unixtime) */
void wait_until(time_t);

/* stack of u64, for caching socket fds and pointers of send_buf */
typedef struct u64_stack_struct {
	__u64 *stack;
	size_t size;	/* size of this stack */
	size_t len;	/* current length (number of pusehd integers )*/
} u64_stack_t;

u64_stack_t *u64_stack_alloc(size_t size);
size_t u64_stack_len(u64_stack_t *stack);
void u64_stack_push(u64_stack_t *stack, __u64 v);
__u64 u64_stack_pop(u64_stack_t *stack);

#endif

/* util.h */

#ifndef _UTIL_H_
#define _UTIL_H_

#define min(a, b) (((a) > (b)) ? (b) : (a))
#define max(a, b) (((a) > (b)) ? (a) : (b))



# define likely(x)	__builtin_expect(!!(x), 1)
# define unlikely(x)	__builtin_expect(!!(x), 0)

#define make_sure_sq_is_available(ring)					\
	do {								\
		if (unlikely(io_uring_sq_space_left(ring) == 0))	\
			io_uring_submit_and_wait(ring, 2);		\
	} while (0)


/* convert sockaddr to ADDR:PORT string onto buf */
void sockaddr_ntop(struct sockaddr_storage *ss, char *buf, socklen_t size);
char *sockaddr_ntoa(struct sockaddr_storage *ss);

#endif

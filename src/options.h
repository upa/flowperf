
#ifndef _OPTIONS_H_
#define _OPTIONS_H_

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>

#include <print.h>

#define MODE_SERVER	1
#define MODE_CLIENT	2

/* default values */
#define DEFAULT_PORT		"9999"
#define DEFAULT_QUEUE_DEPTH	512
#define DEFAULT_HANDLE_BUF_SZ	(1 << 18)	/* 256KB */
#define DEFAULT_BATCH_SIZE	32

#define DEFAULT_LOCAL_ADDR	"::" /* in6-addr-any can handle both v6 and v4 */

/* flowperf command line options */
struct opts {
	/* common options for both server and client modes */
	int	mode;

	char	*port;
	int	queue_depth;
	int 	severity;
	int 	buf_sz;
	int 	batch_sz;

	/* server options */
	char	*local_addr;
};


#endif /* _OPTIONS_ */


#ifndef _OPTIONS_H_
#define _OPTIONS_H_

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netinet/in.h>

#include <prob.h>
#include <print.h>

#define MODE_SERVER	1
#define MODE_CLIENT	2

/* default values */
#define DEFAULT_PORT		"9999"
#define DEFAULT_QUEUE_DEPTH	512

#define DEFAULT_BUF_SZ		(1 << 18)	/* 256KB */
#define DEFAULT_NR_BUFS		1024		/* 256KB * 512 = 256MB */

#define DEFAULT_BATCH_SZ	32
#define MAX_BATCH_SZ		(DEFAULT_QUEUE_DEPTH >> 1)

#define DEFAULT_LOCAL_ADDR	"::" /* in6-addr-any can handle both v6 and v4 */


/* flowperf command line options */
struct opts {
	/* common options for both server and client modes */
	int	mode;

	char	*port;
	int	buf_sz;		/* a buffer size to be registered to io_uring */

	int	queue_depth;
	int 	batch_sz;

	int 	severity;


	/* server options */
	char	*local_addr;

	/* client options */
	int     nr_flows;
	int 	duration;
	int 	concurrency;
        int     tps_rate;
	bool	server_tcp_info;	/* get tcp_info from the server side */
	unsigned int     random_seed;
	int	nr_bufs;	/* number of buffers to be registered to io_uring */
	bool 	cache_sockets;
        time_t  start_time;     /* unixtime */
        double  sampling_rate;  /* rate between 0 and 1 */

	prob_list_t *addrs;
	prob_list_t *flows;
};


#endif /* _OPTIONS_ */

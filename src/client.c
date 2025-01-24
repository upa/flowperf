/* client.c: flowperf client process  */

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>
#include <linux/tcp.h>

#include <liburing.h>

#include <flowperf.h>
#include <client.h>
#include <util.h>

struct client {
	bool	run;
	struct opts *o;

	struct io_uring ring;
};

static struct client cli;
static struct io_uring *ring = &cli.ring;


typedef struct prob_addr_struct {
	/* o->addrs->probs[n].data */
	struct sockaddr_storage saddr;
} prob_addr_t;

typedef struct prob_flow_struct {
	/* o->flows->probs[n].data */
	size_t bytes;
} prob_flow_t;

typedef struct prob_interval_struct {
	/* o->intervals->probs[n].data */
	time_t interval;
} prob_interval_t;


static int prob_list_iter_addr(prob_t *prob)
{
	struct addrinfo hints, *res;
	prob_addr_t *pa;
	int ret;

	/* resolve prob->key as addr of hostname to sockaddr for
	 * connect(). */

	if ((pa = malloc(sizeof(*pa))) == NULL) {
		pr_err("malloc: %s", strerror(errno));
		return -1;
	}
	memset(pa, 0, sizeof(*pa));

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(prob->key, cli.o->port, &hints, &res);
	if (ret != 0) {
		pr_err("getaddrinfo for %s:%s: %s", prob->key, cli.o->port,
		       gai_strerror(ret));
		return -1;
	}

	memcpy(&pa->saddr, res->ai_addr, res->ai_addrlen);
	prob->data = pa;
	freeaddrinfo(res);
	return 0;
}

static int prob_list_iter_flow(prob_t *prob)
{
	prob_flow_t *pf;

	if ((pf = malloc(sizeof(*pf))) == NULL) {
		pr_err("malloc: %s", strerror(errno));
		return -1;
	}
	memset(pf, 0, sizeof(*pf));

	pf->bytes = atol(prob->key);
	if (pf->bytes <= 0) {
		pr_err("invalid flow size: %s", prob->key);
		return -1;
	}
	return 0;
}

static int prob_list_iter_interval(prob_t *prob)
{
	prob_interval_t *pi;

	if ((pi = malloc(sizeof(*pi))) == NULL) {
		pr_err("malloc: %s", strerror(errno));
		return -1;
	}
	memset(pi, 0, sizeof(*pi));

	pi->interval = atol(prob->key);
	if (pi->interval < 0) {
		pr_err("invalid interval: %s", prob->key);
		return -1;
	}
	return 0;
}



#define SEND_BUF_SZ	4096
#define ADDRSTRLEN	64

struct connection_handle {
	/* a handle for a connection to a server */
	int	sock;
	struct sockaddr_storage addr;	/* server address */
	socklen_t	addrlen;
	char		addrstr[ADDRSTRLEN];

	/* state and uring event type */
	int	state;
	int 	event;

	/* fileds for an RPC transaction */
	char	sendbuf[SEND_BUF_SZ];

	void	*buf;
	size_t	buf_sz;
	ssize_t	remain_bytes;	/* remain bytes to be received */

	struct timespec start, end;
};

static int init_client_io_uring(void)
{
	int ret;

	ret = io_uring_queue_init(cli.o->queue_depth, ring, 0);
	if (ret < 0) {
		pr_err("io_uring_queue_init: %s", strerror(-ret));
		return -1;
	}
	return 0;
}


static int client_loop(void)
{
	return 0;
}


static void sigint_handler(int signo) {
    pr_notice("^C pressed. Shutting down.");
    cli.run = false;
    io_uring_queue_exit(ring);
}


int start_client(struct opts *o)
{
	memset(&cli, 0, sizeof(cli));
	cli.o = o;

	if (prob_list_iterate(o->addrs, prob_list_iter_addr) < 0)
		return -1;

	if (prob_list_iterate(o->flows, prob_list_iter_flow) < 0)
		return -1;

	if (prob_list_iterate(o->intervals, prob_list_iter_interval) < 0)
		return -1;

	prob_list_convert_to_cdf(o->addrs);
	prob_list_convert_to_cdf(o->flows);
	prob_list_convert_to_cdf(o->intervals);

	pr_debug("destination addresses and its probability:");
	prob_list_dump_debug(o->addrs);
	if (prob_list_is_empty(o->addrs)) {
		pr_err("no destination address provided");
		return -1;
	}

	pr_debug("flow sizes and its probability:");
	prob_list_dump_debug(o->flows);
	if (prob_list_is_empty(o->flows)) {
		pr_err("no flow size provided");
		return -1;
	}

	pr_debug("intervals and its probability:");
	prob_list_dump_debug(o->intervals);

	if (init_client_io_uring() < 0)
		return -1;

	cli.run = true;

	signal(SIGINT, sigint_handler);

	return client_loop();
}

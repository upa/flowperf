/* client.c: flowperf client process  */

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <linux/tcp.h>

#include <liburing.h>

#include <flowperf.h>
#include <client.h>
#include <util.h>

/* strcture representing flowperf client process */
struct client {
	struct opts *o;

	/* easy list with connection_handle->next  */
	struct connection_handle *first, *last;

	int nr_flows_started;
	int nr_flows_done;

	struct io_uring ring;
};

static struct client cli;
static struct io_uring *ring = &cli.ring;

/* functions for probablity list */

#define ADDRSTRLEN	64

/* o->addrs->probs[n].data */
typedef struct prob_addr_struct {
	struct sockaddr_storage saddr;
	socklen_t	salen;
	int		family;
	int		socktype;
	int 		protocol;
	char 		addrstr[ADDRSTRLEN];
} prob_addr_t;

/* o->flows->probs[n].data */
typedef struct prob_flow_struct {
	ssize_t bytes;
} prob_flow_t;

/* o->intervals->probs[n].data */
typedef struct prob_interval_struct {
	time_t interval;
} prob_interval_t;


static int prob_list_iter_addr(prob_t *prob)
{
	struct addrinfo hints, *res;
	prob_addr_t *pa;
	int ret;

	/* resolve prob->key as addr and fill sockaddr for
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
	sockaddr_ntop(&pa->saddr, pa->addrstr, ADDRSTRLEN);
	pa->salen = res->ai_addrlen;
	pa->family = res->ai_family;
	pa->socktype = res->ai_socktype;
	pa->protocol = res->ai_protocol;
	freeaddrinfo(res);

	prob->data = pa;
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
	prob->data = pf;
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
	prob->data = pi;
	return 0;
}

/* buik timestamp logic */
struct timespec_q {
	struct timespec *tstamps[DEFAULT_QUEUE_DEPTH];
	int tail;
} tsq;

static void tsq_zerorize()
{
	tsq.tail = 0;
}

static void tsq_append(struct timespec *ts)
{
	tsq.tstamps[tsq.tail++] = ts;
	assert(tsq.tail < DEFAULT_QUEUE_DEPTH);
}

static void tsq_bulk_get_time()
{
	/* save timestamp to appended timespec objects */
	int i;
	if (tsq.tail > 0) {
		clock_gettime(CLOCK_MONOTONIC, tsq.tstamps[0]);
		for (i = 1; i < tsq.tail; i++) {
			*tsq.tstamps[i] = *tsq.tstamps[0];
		}
	}
}


#define SEND_BUF_SZ	128

struct connection_handle {
	/* a handle for a connection to a server */
	int	sock;

	struct connection_handle *next;

	prob_addr_t *pa;
	prob_flow_t *pf;
	prob_interval_t *pi;

	/* state and uring event type */
	int	state;
	int 	event;

	/* fileds for an RPC transaction */
	char	sendbuf[SEND_BUF_SZ];

	void	*buf;
	size_t	buf_sz;
	ssize_t	remain_bytes;	/* remaining bytes to be received for flowing */

	struct timespec ts_start;	/* tstamp of start time (put connect())*/
	struct timespec ts_flow_start;	/* tstamp of RPC FLOW sent */
	struct timespec ts_flow_end;	/* tstamp of RPC FLOW done */

	/* tcp_info */
	char tcp_info_s[TCP_INFO_STRLEN];
	char tcp_info_c[TCP_INFO_STRLEN];
};


static void connection_handle_append(struct connection_handle *ch)
{
	/* append ch to the list */
	ch->next = NULL;

	if (cli.first == NULL) {
		cli.first = ch;
		cli.last = ch;
	} else {
		cli.last->next = ch;
		cli.last = ch;
	}
}

static time_t timespec_sub_nsec(struct timespec *after, struct timespec *before)
{
	time_t a_nsec = (after->tv_sec * 1000000000 + after->tv_nsec);
	time_t b_nsec = (before->tv_sec * 1000000000 + before->tv_nsec);

	if (a_nsec == 0 || b_nsec == 0)
		return 0;

	return a_nsec - b_nsec;
}

void print_connection_handle_result(FILE *fp, struct connection_handle *ch)
{
	char buf[512];
	int ret;

	ret = snprintf(buf, sizeof(buf),
		       "state=%c "
		       "dst=%s "
		       "flow_size=%lu "
		       "time_conn=%lu "
		       "time_flow=%lu "
		       "tcp_c=%s",
		       connection_handle_state_name(ch->state),
		       ch->pa->addrstr,
		       ch->pf->bytes,
		       timespec_sub_nsec(&ch->ts_flow_start, &ch->ts_start),
		       timespec_sub_nsec(&ch->ts_flow_end, &ch->ts_flow_start),
		       ch->tcp_info_c
		);

	if (cli.o->server_tcp_info)
		ret += snprintf(buf + ret, sizeof(buf) - ret,
				" tcp_s=%s", ch->tcp_info_s);
	snprintf(buf + ret, sizeof(buf) - 1, "\n");

	fputs(buf, fp);
}

static void print_result(FILE *fp)
{
	struct connection_handle *ch;

	for (ch = cli.first; ch != NULL; ch = ch->next) 
		print_connection_handle_result(fp, ch);
}


static int put_connect(void)
{
	struct connection_handle *ch;
	struct io_uring_sqe *sqe;

	if (cli.o->nr_flows > 0) {
		/* number of flows to be done is specified. Don't
		 * create more than the number of connections.
		 */
		if (cli.nr_flows_started >= cli.o->nr_flows)
			return 0;
		cli.nr_flows_started++;
	}

	pr_debug("put a new connect() event");

	if ((ch = malloc(sizeof(*ch))) == NULL) {
		pr_err("malloc: %s", strerror(errno));
		return -1;
	}
	memset(ch, 0, sizeof(*ch));

        if (posix_memalign(&ch->buf, 4096, cli.o->buf_sz) < 0) {
                pr_err("posix_memalign: %s", strerror(errno));
                free(ch);
                return -1;
        }
        ch->buf_sz = cli.o->buf_sz;

	ch->pa = prob_list_pickup_data_uniformly(cli.o->addrs);
	ch->pf = prob_list_pickup_data_uniformly(cli.o->flows);
	ch->pi = prob_list_is_empty(cli.o->intervals) ?
		NULL : prob_list_pickup_data_uniformly(cli.o->intervals);

	prob_addr_t *pa = ch->pa;
	int v = 1;
	if ((ch->sock = socket(pa->family, pa->socktype, pa->protocol)) < 0) {
		pr_err("socket(): %s", strerror(errno));
		return -1;
	}
	if (setsockopt(ch->sock, SOL_TCP, TCP_NODELAY, &v, sizeof(v)) < 0) {
		pr_err("setsockopt(TCP_NODELAY): %s", strerror(errno));
		return -1;
	}

	sqe = io_uring_get_sqe_always(ring);
	ch->state = CONNECTION_HANDLE_STATE_CONNECTING;
	ch->event = EVENT_TYPE_CONNECT;
	io_uring_prep_connect(sqe, ch->sock, (struct sockaddr *)&pa->saddr, pa->salen);
	io_uring_sqe_set_data(sqe, ch);

	connection_handle_append(ch);
	tsq_append(&ch->ts_start);

	return 0;
}

static void put_read(struct connection_handle *ch, void *buf, size_t len)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe_always(ring);

	ch->event = EVENT_TYPE_READ;
	io_uring_prep_read(sqe, ch->sock, buf, len, 0);
	io_uring_sqe_set_data(sqe, ch);
}

static void put_write(struct connection_handle *ch, size_t len)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe_always(ring);
	ch->event = EVENT_TYPE_WRITE;
	io_uring_prep_write(sqe, ch->sock, ch->sendbuf, len, 0);
	io_uring_sqe_set_data(sqe, ch);
}

static void close_connection_handle(struct connection_handle *ch)
{
	pr_debug("%s: close connection handle", ch->pa->addrstr);
	if (ch->sock > 1)
		close(ch->sock);
	free(ch->buf);

	if (cli.o->nr_flows) {
		/* number of flows to be done is specified */
		cli.nr_flows_done++;
		if (cli.nr_flows_done >= cli.o->nr_flows) {
			/* specified number of flows done. finish the benchmark */
			stop_running();
			return;
		}
	}

	/* On the client side, always call close_connection_handle()
	 * when a connection finished regardless of the RPC completed
	 * or failed. Then, close_connection_handle() puts a new
	 * connect() to start the next RPC.
	 */
	put_connect();
}


static void process_connection_handle_connecting(struct connection_handle *ch,
						 struct io_uring_cqe *cqe)
{
	if (ch->event != EVENT_TYPE_CONNECT) {
		pr_err("invalid state/event pair: state=%d event=%d",
		       ch->state, ch->event);
		close_connection_handle(ch);
		return;
	}

	/* handle is CONNECTION, and connect() completed. Put the
	 * Write event to send RPC REQUEST START FLOW and set the
	 * state FLOWING.
	 */
	if (cqe->res != 0) {
		pr_warn("%s: connect: %s", ch->pa->addrstr, strerror(-cqe->res));
		close_connection_handle(ch);
		return;
	}
	pr_info("%s: connected, start RPC FLOW %lu bytes",
		ch->pa->addrstr, ch->pf->bytes);

	ch->state = CONNECTION_HANDLE_STATE_FLOWING;
	ch->remain_bytes = ch->pf->bytes;
	snprintf(ch->sendbuf, SEND_BUF_SZ, RPC_REQ_START_FLOW " %lu", ch->pf->bytes);
	put_write(ch, strlen(ch->sendbuf) + 1);
}


static void move_connection_handle_interval(struct connection_handle *ch)
{
	if (ch->pi == NULL) {
		/* interval is not specified. no need to sleep */
		ch->state = CONNCTION_HANDLE_STATE_DONE;
		close_connection_handle(ch);
		return;
	}

	struct io_uring_sqe *sqe = io_uring_get_sqe_always(ring);
	struct __kernel_timespec intval;

	pr_debug("%s: sleep for interval %lu nsec", ch->pa->addrstr, ch->pi->interval);

	intval.tv_sec = 0;
	intval.tv_nsec = ch->pi->interval;

	ch->state = CONNECTION_HANDLE_STATE_INTERVAL;
	ch->event = EVENT_TYPE_TIMEOUT;

	io_uring_prep_timeout(sqe, &intval, 0, 0);
	io_uring_sqe_set_data(sqe, ch);
}

static void process_connection_handle_flowing(struct connection_handle *ch,
					      struct io_uring_cqe *cqe)
{
	switch (ch->event) {
	case EVENT_TYPE_READ:
		/* receiving flow */
		if (cqe->res <= 0) {
			pr_warn("%s: read: %s", ch->pa->addrstr, strerror(-cqe->res));
			close_connection_handle(ch);
			return;
		}

		ch->remain_bytes -= cqe->res;
		if (ch->remain_bytes > 0) {
			/* more bytes to be received. put read */
			put_read(ch, ch->buf, ch->buf_sz);
			return;
		}

		/* all bytes transfered. Next is to save tcp_info */
		pr_debug("%s: flow %lu bytes done", ch->pa->addrstr, ch->pf->bytes);
		clock_gettime(CLOCK_MONOTONIC, &ch->ts_flow_end);

		build_tcp_info_string(ch->sock, ch->tcp_info_c, TCP_INFO_STRLEN);
		if (cli.o->server_tcp_info) {
			/* get tcp_info from the server side */
			ch->state = CONNECTION_HANDLE_STATE_TCP_INFO;
			snprintf(ch->sendbuf, SEND_BUF_SZ, RPC_REQ_TCP_INFO);
			put_write(ch, strlen(ch->sendbuf) + 1);
			return;
		}

		move_connection_handle_interval(ch);
		break;

	case EVENT_TYPE_WRITE:
		/* write "F [BYTES]" of RPC Request done. Put a read
		 * for receiving bytes of the flow. */
		if (cqe->res < 0) {
			pr_warn("%s: write: %s", ch->pa->addrstr, strerror(-cqe->res));
			close_connection_handle(ch);
			return;
		}
		tsq_append(&ch->ts_flow_start);
		put_read(ch, ch->buf, ch->buf_sz);
		break;

	default:
		pr_err("invalid state/event pair: state=%d event=%d",
		       ch->state, ch->event);
		close_connection_handle(ch);
	}
}

static void process_connection_handle_tcp_info(struct connection_handle *ch,
					       struct io_uring_cqe *cqe)
{
	switch (ch->event) {
	case EVENT_TYPE_READ:
		pr_debug("%s: server tcp_info done", ch->pa->addrstr);
		if (cqe->res <= 0) {
			pr_warn("%s: read: %s", ch->pa->addrstr, strerror(cqe->res));
			close_connection_handle(ch);
			return;
		}
		move_connection_handle_interval(ch);
		break;

	case EVENT_TYPE_WRITE:
		/* write "T" of RPC request done. Put a read for
		 * receiving bytes of the tcp_info. */
		if (cqe->res <= 0) {
			pr_warn("%s: write: %s", ch->pa->addrstr, strerror(-cqe->res));
			close_connection_handle(ch);
			return;
		}
		put_read(ch, ch->tcp_info_s, TCP_INFO_STRLEN);
		break;

	default:
		pr_err("invalid state/event pair: state=%d event=%d",
		       ch->state, ch->event);
		close_connection_handle(ch);
	}

}

static void process_connection_handle_interval(struct connection_handle *ch,
					       struct io_uring_cqe *cqe)
{
	if (ch->event != EVENT_TYPE_TIMEOUT) {
		pr_err("invalid state/event pair: state=%d event=%d",
		       ch->state, ch->event);
		goto out;
	}
	ch->state = CONNCTION_HANDLE_STATE_DONE;
out:
	close_connection_handle(ch);
}

static void client_process_cqe(struct io_uring_cqe *cqe)
{
	struct connection_handle *ch = io_uring_cqe_get_data(cqe);

	switch (ch->state) {
	case CONNECTION_HANDLE_STATE_CONNECTING:
		process_connection_handle_connecting(ch, cqe);
		break;
	case CONNECTION_HANDLE_STATE_FLOWING:
		process_connection_handle_flowing(ch, cqe);
		break;
	case CONNECTION_HANDLE_STATE_TCP_INFO:
		process_connection_handle_tcp_info(ch, cqe);
		break;
	case CONNECTION_HANDLE_STATE_INTERVAL:
		process_connection_handle_interval(ch, cqe);
		break;
	default:
		pr_err("invalid connection handle state: %d", ch->state);
		close_connection_handle(ch);
	}
}

static int client_loop(void)
{
	struct io_uring_cqe *cqes[DEFAULT_QUEUE_DEPTH];
	unsigned nr_cqes, i;
	int ret;

	pr_info("put %d connect() events", cli.o->concurrency);
	tsq_zerorize();
	for (i = 0; i < cli.o->concurrency; i++) {
		if (put_connect() < 0)
			return -1;
	}
	tsq_bulk_get_time();

	if ((ret = io_uring_submit(ring)) < 0) {
		pr_err("io_uring_submit: %s", strerror(-ret));
		return -1;
	}

	pr_notice("start the client loop");
	while (is_running()) {

		tsq_zerorize();

		nr_cqes = io_uring_peek_batch_cqe(ring, cqes, cli.o->batch_sz);
		if (nr_cqes == 0) {
			if ((ret = io_uring_wait_cqe(ring, &cqes[0])) < 0) {
				if (ret == -EINTR)
					break;
				pr_err("io_uring_wait_cqe: %s", strerror(-ret));
				return -1;
			}
			nr_cqes = 1;
		}

		for (i = 0; i < nr_cqes; i++)
			client_process_cqe(cqes[i]);

		io_uring_cq_advance(ring, i);

		tsq_bulk_get_time();

		if ((ret = io_uring_submit(ring)) < 0) {
			pr_err("io_uring_submit: %s", strerror(-ret));
			return -1;
		}
	}

	pr_info("exit iouring");
	io_uring_queue_exit(ring);

	return 0;
}


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

static void sigint_handler(int signo) {
    pr_notice("^C pressed. Shutting down.");
    stop_running();
}

int start_client(struct opts *o)
{
	int ret;

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

	pr_debug("destinations and probability (cumulative and normalized):");
	prob_list_dump_debug(o->addrs);
	if (prob_list_is_empty(o->addrs)) {
		pr_err("no destination address provided");
		return -1;
	}

	pr_debug("flow sizes and probability (cumulative and normalized):");
	prob_list_dump_debug(o->flows);
	if (prob_list_is_empty(o->flows)) {
		pr_err("no flow size provided");
		return -1;
	}

	pr_debug("intervals and probability (cumulative and normalized):");
	prob_list_dump_debug(o->intervals);

	if (init_client_io_uring() < 0)
		return -1;

	start_running();

	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, sigint_handler);

	ret = client_loop();

	print_result(stdout);

	return ret;
}


/* client.c: flowperf client process  */

#include "print.h"
#include "prob.h"
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/timerfd.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <linux/tcp.h>
#include <linux/net_tstamp.h>
#include <linux/errqueue.h>

#include <liburing.h>

#include <flowperf.h>
#include <client.h>
#include <unistd.h>
#include <util.h>
#include <event.h>

static volatile sig_atomic_t interval_trigger = 0;

/* strcture representing flowperf client process */
struct client {
	struct opts *o;

	/* easy list with connection_handle->next  */
	struct connection_handle *first, *last;

	uint64_t nr_flows_started;
	uint64_t nr_flows_done;
        uint64_t nr_flows_success;

	struct timespec start_time;

	u64_stack_t	*send_buf_cache;

	struct io_uring ring;
};

static struct client cli;
static struct io_uring *ring = &cli.ring;


static void print_cli_stat(bool finish)
{
        uint64_t cur = cli.nr_flows_success;
        static uint64_t last;
        struct timespec now;

        if (finish) {
                clock_gettime(CLOCK_REALTIME, &now);
                long long elapsed = timespec_sub_nsec(&now, &cli.start_time);
                printf("total_tps=%lf\n", (double)cur / (elapsed / 1000000000));
        } else {
                printf("tps=%lu\n", cur - last);
                last = cur;
        }
}


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

	u64_stack_t	*sock_cache;
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

	if (cli.o->cache_sockets) {
		if ((pa->sock_cache = u64_stack_alloc(cli.o->concurrency)) == NULL) {
			pr_err("u64_stack_alloc: %s", strerror(errno));
			return -1;
		}
	}

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



#define MSG_BUF_SZ	32
#define CMSG_BUF_SZ	CMSG_SPACE(sizeof(struct scm_timestamping))

struct connection_handle {
	/* a handle for a connection to a server */
	int	state;
	int	sock;

	struct connection_handle *next;

	prob_addr_t *pa;
	prob_flow_t *pf;
	prob_interval_t *pi;

	/* uring event handlers */
	struct io_event e_connect;
	struct io_event e_sendmsg;
	struct io_event e_write;
	struct io_event e_recvmsg;
	struct io_event e_timeout;

	/* fileds for an RPC transaction */
	char msg_buf[MSG_BUF_SZ];
	char *send_buf;

	/* msghdr and iov for sendmsg() and recvmsg() */
	struct msghdr mh;
	struct iovec iov[1];
	char cmsgbuf[CMSG_BUF_SZ];

	ssize_t	remain_bytes;	/* remaining bytes to be received for flowing */

	struct timespec ts_conn_start;	/* start connect() */
	struct timespec ts_conn_end;	/* end of connect() */
	struct timespec ts_flow_start;	/* first packet of the flow sent */
	struct timespec ts_flow_end;	/* last packet of the flow received */

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

void print_connection_handle_result(FILE *fp, struct connection_handle *ch)
{
	char buf[512];
	int ret;

	ret = snprintf(buf, sizeof(buf),
		       "state=%c "
		       "dst=%s "
		       "flow_size=%lu "
		       "remain=%lu "
		       "flowstart=%ld "
		       "flowend=%ld "
		       "time2conn=%lld "
		       "time2flow=%lld "
		       "tcp_c=%s",
		       connection_handle_state_name(ch->state),
		       ch->pa->addrstr,
		       ch->pf->bytes,
		       ch->remain_bytes,
		       timespec_nsec(&ch->ts_flow_start),
		       timespec_nsec(&ch->ts_flow_end),
		       timespec_sub_nsec(&ch->ts_conn_end, &ch->ts_conn_start),
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

struct timerfd_handle {
        int     state;  /* match to struct connection_handle.state */

        int             fd;     /* timerfd */
        uint64_t        v;
        struct io_event e_read;
} tfd_h;

static int start_timerfd_handle(void)
{
        struct itimerspec ts;

        memset(&tfd_h, 0, sizeof(tfd_h));
        tfd_h.state = CONNECTION_HANDLE_STATE_TIMERFD;

        tfd_h.fd = timerfd_create(CLOCK_MONOTONIC, 0);
        if (tfd_h.fd < 0) {
                pr_err("timerfd_create: %s", strerror(errno));
                return -1;
        }

        ts.it_value.tv_sec = 1;
        ts.it_value.tv_nsec = 0;
        ts.it_interval.tv_sec = 1;
        ts.it_interval.tv_nsec = 0;

        if (timerfd_settime(tfd_h.fd, 0, &ts, NULL) < 0) {
                pr_err("timerfd_settime: %s", strerror(errno));
                return -1;
        }

        io_event_init(&tfd_h.e_read, EVENT_TYPE_READ, &tfd_h);
        post_read(ring, &tfd_h.e_read, tfd_h.fd, (char *)&tfd_h.v, sizeof(tfd_h.v));

        return 0;
}

static void process_timerfd_handle(struct timerfd_handle *tfd,
                                   struct io_event *e,
                                   struct io_uring_cqe *cqe)
{
        assert(e->type == EVENT_TYPE_READ);
        if (cqe->res < 0) {
                pr_err("read timerfd: %s", strerror(errno));
                return;
        }

        print_cli_stat(false);
        post_read(ring, &tfd_h.e_read, tfd_h.fd, (char *)&tfd_h.v, sizeof(tfd_h.v));
}



static size_t prep_send_buf(struct connection_handle *ch)
{
	size_t send_sz = min(ch->remain_bytes, cli.o->buf_sz);

	/* this byte may be other char on last flowing. clear it */
	ch->send_buf[send_sz - 1] = '!';

	if (send_sz == ch->remain_bytes) {
		/* this is the last segment, put T or E */
		if (cli.o->server_tcp_info)
			ch->send_buf[send_sz - 1] = RPC_TAIL_MARK_TCP_INFO;
		else
			ch->send_buf[send_sz - 1] = RPC_TAIL_MARK_END;
	}
	return send_sz;
}

static void post_write_flowing(struct connection_handle *ch)
{
	size_t send_sz = prep_send_buf(ch);
	post_write(ring, &ch->e_write, ch->sock, ch->send_buf, send_sz);
}

static void start_flowing(struct connection_handle *ch)
{
	pr_debug("%s: start flowing %lu bytes", ch->pa->addrstr, ch->pf->bytes);
	ch->state = CONNECTION_HANDLE_STATE_FLOWING;
	ch->remain_bytes = ch->pf->bytes;

	/* we use sendmsg() for the first segment to get TX timestamp
	 * that is the start time of the flow.
	 */

	memset(&ch->mh, 0, sizeof(ch->mh));
	memset(ch->cmsgbuf, 0, CMSG_BUF_SZ);

	ch->iov[0].iov_base = ch->send_buf;
	ch->iov[0].iov_len = prep_send_buf(ch);

	ch->mh.msg_iov = ch->iov;
	ch->mh.msg_iovlen = 1;

	ch->mh.msg_control = ch->cmsgbuf;
	ch->mh.msg_controllen = CMSG_LEN(sizeof(uint32_t));

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&ch->mh);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SO_TIMESTAMPING;
        cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
        *((uint32_t *) CMSG_DATA(cmsg)) = SOF_TIMESTAMPING_TX_SCHED;
	/* XXX: use TX_SCHED instead of TX_SOFTWARE, because the time
	 * at the first packet of the segment is sent is preferred
	 * over that of the last packet is sent.
	 */

	post_sendmsg(ring, &ch->e_sendmsg, ch->sock, &ch->mh, 0);
}

static int post_new_connect(void)
{
	struct connection_handle *ch;

	if (cli.o->nr_flows > 0) {
		/* number of flows to be done is specified. Don't
		 * create more than the number of connections.
		 */
		if (cli.nr_flows_started >= cli.o->nr_flows)
			return 0;
		cli.nr_flows_started++;
	}

	pr_debug("post a new connection");

	if ((ch = malloc(sizeof(*ch))) == NULL) {
		pr_err("malloc: %s", strerror(errno));
		return -1;
	}
	memset(ch, 0, sizeof(*ch));

	if (u64_stack_len(cli.send_buf_cache) > 0) {
		/* reuse a cached send_buf */
		ch->send_buf = (void *)(uintptr_t) u64_stack_pop(cli.send_buf_cache);
	} else if ((ch->send_buf = malloc(cli.o->buf_sz)) == NULL) {
		pr_err("malloc: %s", strerror(errno));
		return -1;
	}
	memset(ch->send_buf, '!', cli.o->buf_sz);

	ch->state = CONNECTION_HANDLE_STATE_CONNECTING;
	io_event_init(&ch->e_connect, EVENT_TYPE_CONNECT, ch);
	io_event_init(&ch->e_write, EVENT_TYPE_WRITE, ch);
	io_event_init(&ch->e_sendmsg, EVENT_TYPE_SENDMSG, ch);
	io_event_init(&ch->e_recvmsg, EVENT_TYPE_RECVMSG, ch);
	io_event_init(&ch->e_timeout, EVENT_TYPE_TIMEOUT, ch);

	ch->pa = prob_list_pickup_data_uniformly(cli.o->addrs);
	ch->pf = prob_list_pickup_data_uniformly(cli.o->flows);
	ch->pi = prob_list_is_empty(cli.o->intervals) ?
		NULL : prob_list_pickup_data_uniformly(cli.o->intervals);

	prob_addr_t *pa = ch->pa;

	if (pa->sock_cache && u64_stack_len(pa->sock_cache) > 0) {
		/* use a cached socket if exists */
		pr_debug("%s: reuse a cached socket", pa->addrstr);
		ch->sock = u64_stack_pop(pa->sock_cache);
		start_flowing(ch);
		return 0;
	}

	if ((ch->sock = socket(pa->family, pa->socktype, pa->protocol)) < 0) {
		pr_err("socket(): %s", strerror(errno));
		return -1;
	}

	int val = 1;
	if (setsockopt(ch->sock, SOL_TCP, TCP_NODELAY, &val, sizeof(val)) < 0) {
		pr_err("setsockopt(TCP_NODELAY): %s", strerror(errno));
		return -1;
	}

	post_connect(ring, &ch->e_connect, ch->sock,
		     (struct sockaddr *)&pa->saddr, pa->salen);

	clock_gettime(CLOCK_REALTIME, &ch->ts_conn_start);

	return 0;
}


static void close_connection_handle(struct connection_handle *ch)
{
	if (io_event_is_posted(&ch->e_write) ||
	    io_event_is_posted(&ch->e_connect) ||
	    io_event_is_posted(&ch->e_sendmsg) ||
	    io_event_is_posted(&ch->e_recvmsg) ||
	    io_event_is_posted(&ch->e_timeout)) {
		/* still there is a posted io. defer closing */
		pr_debug("%s: there is unacked io event(s). defer closing connection",
			ch->pa->addrstr);
		return;
	}

	if (ch->pa->sock_cache && ch->state == CONNECTION_HANDLE_STATE_DONE) {
		pr_debug("%s: cache the connection", ch->pa->addrstr);
		u64_stack_push(ch->pa->sock_cache, ch->sock);
	} else {
		pr_debug("%s: close connection", ch->pa->addrstr);
		close(ch->sock);
	}

	u64_stack_push(cli.send_buf_cache, (unsigned long)ch->send_buf);
	ch->send_buf = NULL;

        /* save this connection handle to the result list */
        if (cli.o->sampling_rate == 0 ||
            ((double)rand() / RAND_MAX) <= cli.o->sampling_rate) {
                connection_handle_append(ch);
        } else
                free(ch);


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
	 *  When a connection finished regardless of the RPC completed
	 *  or failed. Then, put a new connect() to start the next
	 *  RPC.
	 */
	post_new_connect();
}

static void process_connection_handle_connecting(struct connection_handle *ch,
						 struct io_event *e,
						 struct io_uring_cqe *cqe)
{
	assert(e->type == EVENT_TYPE_CONNECT);

	/* handle is CONNECTION, and connect() completed. Start Flowing
	 */
	if (cqe->res != 0) {
		pr_warn("%s: connect: %s", ch->pa->addrstr, strerror(-cqe->res));
		close_connection_handle(ch);
		return;
	}
	clock_gettime(CLOCK_REALTIME, &ch->ts_conn_end);

	/* enable RX software timestamping and OPT CMSG for selective
	 * TX timestamping. */
	int val = (SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE |
		   SOF_TIMESTAMPING_OPT_CMSG);
	if (setsockopt(ch->sock, SOL_SOCKET, SO_TIMESTAMPING, &val, sizeof(val)) < 0) {
		pr_err("setsockopt(SO_TIEMSTAMPING): %s", strerror(errno));
		close_connection_handle(ch);
		return;
	}

	pr_debug("%s: connected", ch->pa->addrstr);

	start_flowing(ch);
}


static void process_connection_handle_flowing(struct connection_handle *ch,
					      struct io_event *e,
					      struct io_uring_cqe *cqe)
{
	assert(e->type == EVENT_TYPE_WRITE || e->type == EVENT_TYPE_SENDMSG);

	if (cqe->res <= 0) {
		pr_warn("%s: %s: %s",
			e->type == EVENT_TYPE_SENDMSG ? "sendmsg" : "write",
			ch->pa->addrstr, strerror(-cqe->res));
		close_connection_handle(ch);
		return;
	}

	ch->remain_bytes -= cqe->res;

	if (ch->remain_bytes <= 0) {
		/* All bytes sent. save the tcp_info and Let's get ack
		 * or tcp_info as ack from the server */
		build_tcp_info_string(ch->sock, ch->tcp_info_c, TCP_INFO_STRLEN);
		ch->state = CONNECTION_HANDLE_STATE_WAIT_ACK;

		if (cli.o->server_tcp_info) {
			ch->iov[0].iov_base = ch->tcp_info_s;
			ch->iov[0].iov_len = TCP_INFO_STRLEN;
		} else {
			ch->iov[0].iov_base = ch->msg_buf;
			ch->iov[0].iov_len = MSG_BUF_SZ;
		}
		memset(ch->iov[0].iov_base, 0, ch->iov[0].iov_len);

		memset(&ch->mh, 0, sizeof(ch->mh));
		memset(ch->cmsgbuf, 0, CMSG_BUF_SZ);
		ch->mh.msg_iov = ch->iov;
		ch->mh.msg_iovlen = 1;
		ch->mh.msg_control = ch->cmsgbuf;
		ch->mh.msg_controllen = sizeof(ch->cmsgbuf);
		post_recvmsg(ring, &ch->e_recvmsg, ch->sock, &ch->mh, 0);

		return;
	}

	/* we need to send more bytes */
	post_write_flowing(ch);
}

int obtain_flow_start_time(struct connection_handle *ch)
{
	/* obtain tx timestamp from MSG_ERRQUEUE and svae it onto
	 * ch->ts_flow_start. */

	struct cmsghdr *cmsg;
	char cmsgbuf[512];
	struct msghdr mh;

	memset(&mh, 0, sizeof(mh));
	memset(&cmsg, 0, sizeof(cmsg));
	memset(cmsgbuf, 0, sizeof(cmsgbuf));

	mh.msg_control = cmsgbuf;
	mh.msg_controllen = sizeof(cmsgbuf);

	if (recvmsg(ch->sock, &mh, MSG_ERRQUEUE) < 0) {
		pr_err("recvmsg for MSG_ERRQUEUE: %s", strerror(errno));
		return -1;
	}

	for (cmsg = CMSG_FIRSTHDR(&mh); cmsg && cmsg->cmsg_len;
	     cmsg = CMSG_NXTHDR(&mh, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_TIMESTAMPING) {
			struct scm_timestamping *ts;
			ts = (struct scm_timestamping *)CMSG_DATA(cmsg);
			ch->ts_flow_start = ts->ts[0];
		}
	}

	return 0;
}

static void obtain_flow_end_time(struct connection_handle *ch)
{
	/* obtain rx timestamp from cmsg and save it onto
	 * ch->ts_flow_end. */

	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(&ch->mh); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&ch->mh, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_TIMESTAMPING) {
			struct scm_timestamping *ts;
			ts = (struct scm_timestamping *)CMSG_DATA(cmsg);
			ch->ts_flow_end = ts->ts[0];
			return;
		}
	}
	pr_warn("failed to get rx timestamp for the last received packet");
}

static void process_connection_handle_wait_ack(struct connection_handle *ch,
					       struct io_event *e,
					       struct io_uring_cqe *cqe)
{
	assert(e->type == EVENT_TYPE_RECVMSG);

	if (cqe->res <= 0) {
		if (cqe->res < 0)
			pr_warn("%s: recvmsg: %s", ch->pa->addrstr, strerror(-cqe->res));
		else
			pr_warn("%s: connection closed", ch->pa->addrstr);
		goto close;
	}

	if (!cli.o->server_tcp_info && ch->msg_buf[0] != RPC_TAIL_MARK_ACK) {
		pr_err("%s: unexpected tail mark for ack: '%c'",
		       ch->pa->addrstr, ch->msg_buf[0]);
		goto close;
	}

	pr_debug("%s: %lu bytes flow acked", ch->pa->addrstr, ch->pf->bytes);

	obtain_flow_start_time(ch);
	obtain_flow_end_time(ch);

	if (ch->pi) {
		/* sleep interval */
		ch->state = CONNECTION_HANDLE_STATE_INTERVAL;
		post_timeout(ring, &ch->e_timeout, ch->pi->interval);
		return;
	}

	/* nothing to do. close! */
	ch->state = CONNECTION_HANDLE_STATE_DONE;
        cli.nr_flows_success++;

close:
	close_connection_handle(ch);
}

static void process_connection_handle_interval(struct connection_handle *ch,
					       struct io_event *e,
					       struct io_uring_cqe *cqe)
{
	assert(e->type == EVENT_TYPE_TIMEOUT);
	ch->state = CONNECTION_HANDLE_STATE_DONE;
	close_connection_handle(ch);
}

static void client_process_cqe(struct io_uring_cqe *cqe)
{
	struct io_event *e = io_uring_cqe_get_data(cqe);
	struct connection_handle *ch = io_event_ack_and_data(e);

	switch (ch->state) {
	case CONNECTION_HANDLE_STATE_CONNECTING:
		process_connection_handle_connecting(ch, e, cqe);
		break;
	case CONNECTION_HANDLE_STATE_FLOWING:
		process_connection_handle_flowing(ch, e, cqe);
		break;
	case CONNECTION_HANDLE_STATE_WAIT_ACK:
		process_connection_handle_wait_ack(ch, e, cqe);
		break;
	case CONNECTION_HANDLE_STATE_INTERVAL:
		process_connection_handle_interval(ch, e, cqe);
		break;
        case CONNECTION_HANDLE_STATE_TIMERFD:
                process_timerfd_handle((struct timerfd_handle *)ch, e, cqe);
                break;
	default:
		pr_err("invalid connection handle state: %d", ch->state);
		close_connection_handle(ch);
	}
}

static int client_loop(void)
{
	struct io_uring_cqe *cqes[MAX_BATCH_SZ];
	unsigned nr_cqes, i;
	int ret;

        pr_info("put timerfd read event");
        if (start_timerfd_handle() < 0)
                return -1;

	pr_info("put %d connect() events", cli.o->concurrency);
	for (i = 0; i < cli.o->concurrency; i++) {
		if (post_new_connect() < 0)
			return -1;
	}

	if ((ret = io_uring_submit(ring)) < 0) {
		pr_err("io_uring_submit: %s", strerror(-ret));
		return -1;
	}

	pr_notice("client loop started");
	while (is_running()) {

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

		if ((ret = io_uring_submit(ring)) < 0) {
			pr_err("io_uring_submit: %s", strerror(-ret));
			return -1;
		}
	}

	pr_info("release io_uring");
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

static void signal_handler(int signo)
{
        switch (signo) {
        case SIGINT:
                pr_notice("^C pressed. shutting down.");
                break;
        case SIGALRM:
                break;
        }

	stop_running();
}

int start_client(struct opts *o)
{
	int ret;

	memset(&cli, 0, sizeof(cli));
	cli.o = o;

	if ((cli.send_buf_cache = u64_stack_alloc(cli.o->concurrency)) == NULL) {
		pr_err("u64_stack_alloc: %s", strerror(errno));
		return -1;
	}

	if (prob_list_iterate(o->addrs, prob_list_iter_addr) < 0)
		return -1;

	if (prob_list_iterate(o->flows, prob_list_iter_flow) < 0)
		return -1;

	if (prob_list_iterate(o->intervals, prob_list_iter_interval) < 0)
		return -1;

	prob_list_convert_to_cdf(o->addrs);
	prob_list_convert_to_cdf(o->flows);
	prob_list_convert_to_cdf(o->intervals);

	pr_info("destinations and probability (cumulative and normalized):");
	prob_list_dump_info(o->addrs);
	if (prob_list_is_empty(o->addrs)) {
		pr_err("no destination address provided");
		return -1;
	}

	pr_info("flow sizes and probability (cumulative and normalized):");
	prob_list_dump_info(o->flows);
	if (prob_list_is_empty(o->flows)) {
		pr_err("no flow size provided");
		return -1;
	}

	pr_info("intervals and probability (cumulative and normalized):");
	prob_list_dump_info(o->intervals);

        pr_notice("random seed: %u", cli.o->random_seed);
	pr_notice("test duration: %d%s",
		  cli.o->duration, cli.o->duration == 0 ? " (infinite)" : "");
	pr_notice("number of flows to be done: %d%s",
		  cli.o->nr_flows, cli.o->nr_flows == 0 ? " (infinite)" : "");
        if (cli.o->sampling_rate)
                pr_notice("sampling rate: %f", cli.o->sampling_rate);

	if (init_client_io_uring() < 0)
		return -1;

        if (o->start_time) {
                pr_notice("wait until %ld", o->start_time);
                wait_until(o->start_time);
        }

	start_running();

	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, signal_handler);

        if (cli.o->duration > 0) {
                signal(SIGALRM, signal_handler);
                alarm(cli.o->duration);
        }

	clock_gettime(CLOCK_REALTIME, &cli.start_time);

	ret = client_loop();

	print_result(stdout);

        print_cli_stat(true);

	return ret;
}


/* server.c: flowperf server process */

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
#include <server.h>
#include <event.h>
#include <util.h>


struct server {
	int 	sock;
	struct opts *o;
	struct io_uring ring;

	struct io_uring_buf_ring *recv_buf_ring;
	char **recv_bufs;	/* nr_bufs x buf_sz region for io_uring_buf_ring */
};

static struct server serv;
static struct io_uring *ring = &serv.ring;


#define MSG_BUF_SZ	256
#define ADDRSTRLEN	64

struct client_handle {
	/* a handle for a client connection */
	int	sock;
	struct sockaddr_storage addr;	/* client address */
	socklen_t	addrlen;
	char		addrstr[ADDRSTRLEN];

	/* state and uring event type */
	int 	state;
	struct io_event e_accept;
	struct io_event e_write;
	struct io_event e_recv;
	struct io_event e_cancel;

	/* fields for an RPC transaction */
	char	msg_buf[MSG_BUF_SZ];
};


static int init_serv_socket()
{
	struct addrinfo hints, *res, *rp;
	int ret;

	/* create tcp server socket */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	ret = getaddrinfo(serv.o->local_addr, serv.o->port, &hints, &res);
	if (ret != 0) {
		pr_err("getaddrinfo for %s:%s: %s", serv.o->local_addr, serv.o->port,
		       gai_strerror(ret));
		return -1;
	}

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		int v = 1;
		serv.sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (serv.sock < 0)
			continue;

		if (setsockopt(serv.sock, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v)) < 0)
			pr_warn("failed to set SO_REUSEADDR: %s", strerror(errno));

		if (bind(serv.sock, rp->ai_addr, rp->ai_addrlen) == 0)
			break;
		pr_warn("bind: %s", strerror(errno));
		close(serv.sock);
		serv.sock = -1;
	}

	if (rp) {
		pr_notice("listen on %s",
			  sockaddr_ntoa((struct sockaddr_storage *)rp->ai_addr));
	}

	freeaddrinfo(res);

	if (rp == NULL) {
		pr_err("bind to %s:%s failed", serv.o->local_addr, serv.o->port);
		return -1;
	}

	if (listen(serv.sock, 256) < 0) {
		pr_err("listen failed: %s", strerror(errno));
		close(serv.sock);
		return -1;
	}

	return 0;
}

static int init_serv_io_uring()
{
	struct io_uring_buf_reg reg = {};
	int ret, i;

	ret = io_uring_queue_init(serv.o->queue_depth, ring, 0);
	if (ret < 0) {
		pr_err("io_uring_queue_init: %s", strerror(-ret));
		return -1;
	}

        /* prepare provided buffer for recv_multishot */
        if (posix_memalign((void **)&serv.recv_buf_ring, sysconf(_SC_PAGESIZE),
                           serv.o->nr_bufs * sizeof(struct io_uring_buf_ring)) != 0) {
                pr_err("posix_memalign: %s", strerror(errno));
                return -1;
        }
        reg.ring_addr = (unsigned long)serv.recv_buf_ring;
        reg.ring_entries = serv.o->nr_bufs;
        reg.bgid = 0;
        if ((ret = io_uring_register_buf_ring(ring, &reg, 0)) < 0) {
                pr_err("io_uring_register_buf_ring: %s", strerror(-ret));
                return -1;
        }
                
        /* add buffers to the buf_ring */
        io_uring_buf_ring_init(serv.recv_buf_ring);
        if ((serv.recv_bufs = calloc(serv.o->nr_bufs, sizeof(char *))) == NULL) {
                pr_err("calloc: %s", strerror(errno));
                return -1;
        }
        for (i = 0; i < serv.o->nr_bufs; i++) {
                if ((serv.recv_bufs[i] = malloc(serv.o->buf_sz)) == NULL) {
                        pr_err("malloc: %s", strerror(errno));
                        return -1;
                } 
                io_uring_buf_ring_add(serv.recv_buf_ring, serv.recv_bufs[i],
				      serv.o->buf_sz, i,
				      io_uring_buf_ring_mask(serv.o->nr_bufs), i);
        }

        io_uring_buf_ring_advance(serv.recv_buf_ring, serv.o->nr_bufs);

	return 0;
}


/* client handle processing */

static void release_client_handle(struct client_handle *ch)
{
	if (io_event_is_posted(&ch->e_recv) ||
	    io_event_is_posted(&ch->e_write) ||
	    io_event_is_posted(&ch->e_cancel)) {
		pr_debug("%s: there is unacked io event(s), defer releaseing handle",
			 ch->addrstr);
		return;
	}
	pr_debug("%s: connection closed", ch->addrstr);
	close(ch->sock);
	free(ch);
}

static void close_client_handle(struct client_handle *ch)
{
	ch->state = CLIENT_HANDLE_STATE_CLOSING;

	pr_debug("%s: closing connection", ch->addrstr);

	if (io_event_is_posted(&ch->e_recv)) {
		/* cancel recv multishot and set state CLOSING. */
		pr_debug("%s: cancel recv multishot for fd=%d", ch->addrstr, ch->sock);
		post_cancel(ring, &ch->e_cancel, ch->sock);
	} else
		release_client_handle(ch);
}

static void process_client_handle_accepting(struct client_handle *ch_accept,
					    struct io_event *e,
					    struct io_uring_cqe *cqe)
{
	struct client_handle *ch;

	assert(e->type == EVENT_TYPE_ACCEPT);

	/* multishot accept() returns a new socket. allocate a new
	 * client_handle, and put recv_multishot for this client.
	 */
	if (cqe->res < 0) {
		pr_warn("accept: %s", strerror(-cqe->res));
		return;
	}
	if ((ch = malloc(sizeof(*ch))) == NULL) {
		pr_err("malloc: %s", strerror(errno));
		close(cqe->res);
		return;
	}
	memset(ch, 0, sizeof(*ch));
	io_event_init(&ch->e_accept, EVENT_TYPE_ACCEPT, ch);
	io_event_init(&ch->e_recv, EVENT_TYPE_RECV, ch);
	io_event_init(&ch->e_write, EVENT_TYPE_WRITE, ch);
	io_event_init(&ch->e_cancel, EVENT_TYPE_CANCEL, ch);

	ch->sock = cqe->res;
	ch->addrlen = sizeof(ch->addr);
	if (getpeername(ch->sock, (struct sockaddr *)&ch->addr, &ch->addrlen) < 0) {
		pr_err("getpeername: %s", strerror(errno));
		return;
	}
	sockaddr_ntop(&ch->addr, ch->addrstr, ADDRSTRLEN);
	pr_info("%s: new connection accepted", ch->addrstr);

	int v = 1;
	if (setsockopt(ch->sock, SOL_TCP, TCP_NODELAY, &v, sizeof(v)) < 0)
		pr_warn("%s: setoskcopt(TCP_NODELAY): %s", ch->addrstr, strerror(errno));

	ch->state = CLIENT_HANDLE_STATE_ACCEPTED;
	post_recv_multishot(ring, &ch->e_recv, ch->sock, 0);
}

static void process_client_handle_accepted(struct client_handle *ch,
					   struct io_event *e,
					   struct io_uring_cqe *cqe)
{
	int buf_id;
	char *buf;
	int ret;

	if (cqe->res <= 0) {
		if (cqe->res < 0)
			pr_warn("%s: %s: %s, close connection",
				ch->addrstr, io_event_name(e), strerror(-cqe->res));
		else
			pr_info("%s: %s: close connection",
				ch->addrstr, io_event_name(e));
		goto close;
	}

	switch (e->type) {
	case EVENT_TYPE_WRITE:
		/* tcp_info_string or ack was written. nothing to do */
		break;

	case EVENT_TYPE_RECV:
		buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
		buf = serv.recv_bufs[buf_id];
		switch (buf[cqe->res - 1]) {
		case RPC_TAIL_MARK_END:
			/* send ack */
			pr_debug("%s: send ACK", ch->addrstr);
			ch->msg_buf[0] = RPC_TAIL_MARK_ACK;
			post_write(ring, &ch->e_write, ch->sock, ch->msg_buf, 1);
			break;
		case RPC_TAIL_MARK_TCP_INFO:
			/* send tcp_info */
			pr_debug("%s: send TCP_INFO", ch->addrstr);
			ret = build_tcp_info_string(ch->sock, ch->msg_buf, MSG_BUF_SZ);
			post_write(ring, &ch->e_write, ch->sock, ch->msg_buf, ret);
			break;
		}

		/* put the buffer back to the ring */
                io_uring_buf_ring_add(serv.recv_buf_ring, serv.recv_bufs[buf_id],
                                      serv.o->buf_sz, buf_id,
                                      io_uring_buf_ring_mask(serv.o->nr_bufs), 0);
                io_uring_buf_ring_advance(serv.recv_buf_ring, 1);
		break;

	default:
		pr_err("invalid event type %d", e->type);
		goto close;
	}

	return;

close:
	close_client_handle(ch);
}



static void server_process_cqe(struct io_uring_cqe *cqe) 
{
	struct io_event *e = io_uring_cqe_get_data(cqe);
	struct client_handle *ch = io_event_data(e);

	if (!(cqe->flags & IORING_CQE_F_MORE))
		io_event_ack(e);

	switch (ch->state) {
	case CLIENT_HANDLE_STATE_ACCEPTING:
		process_client_handle_accepting(ch, e, cqe);
		break;

	case CLIENT_HANDLE_STATE_ACCEPTED:
		process_client_handle_accepted(ch, e, cqe);
		break;

	case CLIENT_HANDLE_STATE_CLOSING:
		release_client_handle(ch);
		break;

	default:
		pr_err("invalid client handle state: %d", ch->state);
		close_client_handle(ch);
	}
}

static int server_loop(void)
{
	static struct client_handle accept_ch = {};
	struct io_uring_cqe *cqes[MAX_BATCH_SZ];
	unsigned nr_cqes, i;
	int ret;

	/* accept_ch is just for accet() */
	accept_ch.state = CLIENT_HANDLE_STATE_ACCEPTING;
	io_event_init(&accept_ch.e_accept, EVENT_TYPE_ACCEPT, &accept_ch);
	post_accept_multishot(ring, &accept_ch.e_accept, serv.sock);
	if ((ret = io_uring_submit(ring)) < 0) {
		pr_err("io_uring_submit: %s", strerror(-ret));
		return -1;
	}

	pr_notice("server loop started");
	while (is_running()) {
		nr_cqes = io_uring_peek_batch_cqe(ring, cqes, serv.o->batch_sz);
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
			server_process_cqe(cqes[i]);

		io_uring_cq_advance(ring, i);

		if ((ret = io_uring_submit(ring)) < 0) {
			pr_err("io_uring_submit: %s", strerror(-ret));
			return -1;
		}
	}
	
	pr_info("close socket and exit iouring");
	close(serv.sock);
	io_uring_queue_exit(ring);

	return 0;
}


static void sigint_handler(int signo) {
    pr_notice("^C pressed. Shutting down.");
    stop_running();
}


int start_server(struct opts *o)
{
	memset(&serv, 0, sizeof(serv));
	serv.o = o;

	if (init_serv_socket() < 0)
		return -1;

	if (init_serv_io_uring() < 0)
		return -1;

	start_running();

	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, sigint_handler);

	return server_loop();
}


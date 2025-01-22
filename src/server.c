/* server.c: flowperf server process */

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <netdb.h>
#include <time.h>

#include <liburing.h>

#include <flowperf.h>
#include <opts.h>
#include <util.h>

struct server {
	int 	sock;
	struct opts *o;

	struct io_uring ring;
};

struct server serv;
struct io_uring *ring = &serv.ring;


struct client_handle {
	/* a handle for a client connection */
	int	sock;
	struct sockaddr_storage addr;	/* client address */
	socklen_t addr_len;

	/* state and uring even type */
	int 	state;
	int	event;

	/* fields for an RPC transaction */
	void	*buf;
	size_t	buf_sz;
	size_t	remain_bytes;	/* remain bytes to be xmitted */
	struct timespec start, end;
};


static int init_serv_socket(struct opts *o)
{
	struct addrinfo hints, *res, *rp;
	int ret;

	memset(&serv, 0, sizeof(serv));
	serv.o = o;

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

	freeaddrinfo(res);

	if (rp == NULL) {
		pr_err("bind to %s:%s failed", serv.o->local_addr, serv.o->port);
		return -1;
	}

	pr_debug("start to listen on %s:%s", serv.o->local_addr, serv.o->port);
	if (listen(serv.sock, 256) < 0) {
		pr_err("listen failed: %s", strerror(errno));
		close(serv.sock);
		return -1;
	}

	return 0;
}

static int init_serv_io_uring(struct opts *o)
{
	int ret;

	ret = io_uring_queue_init(o->queue_depth, ring, 0);
	if (ret < 0) {
		pr_err("io_uring_queue_init: %s", strerror(-ret));
		return -1;
	}

	return 0;
}


/* client handle processing */


static int put_accept(void)
{
	make_sure_sq_is_available(ring);
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	struct client_handle *ch;

	/* put a new client handle instance */
	if ((ch = malloc(sizeof(*ch))) == NULL) {
		pr_err("malloc: %s", strerror(errno));
		return -1;
	}
	memset(ch, 0, sizeof(*ch));
	ch->state = SERVER_HANDLE_STATE_ACCEPTING;
	ch->event = EVENT_TYPE_ACCEPT;

	io_uring_prep_accept(sqe, serv.sock, (struct sockaddr *)&ch->addr,
			     (socklen_t *)&ch->addr_len, 0);
	io_uring_sqe_set_data(sqe, ch);

	return 0;
}

static int put_read(struct client_handle *ch)
{
	make_sure_sq_is_available(ring);
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

	ch->event = EVENT_TYPE_READ;
	io_uring_prep_read(sqe, ch->sock, ch->buf, ch->buf_sz, 0);
	io_uring_sqe_set_data(sqe, ch);
	return 0;
}

static int put_write(struct client_handle *ch, size_t len)
{
	make_sure_sq_is_available(ring);
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	ch->event = EVENT_TYPE_WRITE;
	io_uring_prep_write(sqe, ch->sock, ch->buf, len, 0);
	io_uring_sqe_set_data(sqe, ch);
	return 0;
}



static void cleanup(void) {
    close(serv.sock);
    io_uring_queue_exit(ring);
}

static void sigint_handler(int signo) {
    pr_notice("^C pressed. Shutting down.\n");
    cleanup();
}


int start_server(struct opts *o)
{
	if (init_serv_socket(o) < 0)
		return -1;

	if (init_serv_io_uring(o) < 0)
		return -1;

	signal(SIGINT, sigint_handler);

	cleanup();
	return 0;
}


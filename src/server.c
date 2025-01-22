/* server.c: flowperf server process */

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>
#include <linux/tcp.h>

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

	pr_debug("put a new accept() event");

	/* put a new client handle instance */
	if ((ch = malloc(sizeof(*ch))) == NULL) {
		pr_err("malloc: %s", strerror(errno));
		return -1;
	}
	memset(ch, 0, sizeof(*ch));
	if (posix_memalign(&ch->buf, 4096, serv.o->buf_sz) < 0) {
		pr_err("posix_memalign: %s", strerror(errno));
		free(ch);
		return -1;
	}
	ch->buf_sz = serv.o->buf_sz;

	ch->state = CLIENT_HANDLE_STATE_ACCEPTING;
	ch->event = EVENT_TYPE_ACCEPT;
	ch->addr_len = sizeof(ch->addr);

	io_uring_prep_accept(sqe, serv.sock,
			     (struct sockaddr *)&ch->addr, &ch->addr_len, 0);
	io_uring_sqe_set_data(sqe, ch);

	return 0;
}

static void put_read(struct client_handle *ch)
{
	make_sure_sq_is_available(ring);
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

	ch->event = EVENT_TYPE_READ;
	io_uring_prep_read(sqe, ch->sock, ch->buf, ch->buf_sz, 0);
	io_uring_sqe_set_data(sqe, ch);
}

static void put_write(struct client_handle *ch, size_t len)
{
	make_sure_sq_is_available(ring);
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	ch->event = EVENT_TYPE_WRITE;
	io_uring_prep_write(sqe, ch->sock, ch->buf, len, 0);
	io_uring_sqe_set_data(sqe, ch);
}


static void process_client_handle_accepting(struct client_handle *ch,
					    struct io_uring_cqe *cqe)
{
	if (ch->event != EVENT_TYPE_ACCEPT) {
		pr_err("invalid state/event pair: state=%d event=%d",
		       ch->state, ch->event);
		return;
	}

	/* handle is ACCEPTING, and accept event completed. The next
	 * state is ACCEPTED, and put a read event for waiting an RPC
	 * request.
	 */
	if (cqe->res < 0) {
		pr_warn("accept: %s", strerror(-cqe->res));
		goto put_next_accept;
	}
	pr_info("%s: new connection accepted", sockaddr_ntoa(&ch->addr));

	ch->sock = cqe->res;
	ch->state = CLIENT_HANDLE_STATE_ACCEPTED;
	ch->event = EVENT_TYPE_READ;
	put_read(ch);

put_next_accept:
	put_accept();
}

void move_client_handle_flowing(struct client_handle *ch, struct rpc_start_flow *rpc)
{
	/* start RPC FLOWING */
	pr_debug("%s: RPC FLOW start", sockaddr_ntoa(&ch->addr));

	ch->state = CLIENT_HANDLE_STATE_FLOWING;
	ch->event = EVENT_TYPE_WRITE;
	ch->remain_bytes = htonl(rpc->bytes);
	put_write(ch, min(ch->remain_bytes, ch->buf_sz));
}

void move_client_handle_tcp_info(struct client_handle *ch, struct rpc_tcp_info *rpc)
{
	/* Start RPC TCP_INFO */
	struct tcp_info info;
	socklen_t infolen = sizeof(info);

	pr_debug("%s: RPC TCP_INFO start", sockaddr_ntoa(&ch->addr));

	if (getsockopt(ch->sock, IPPROTO_TCP, TCP_INFO, &info, &infolen) < 0) {
		pr_warn("getsockopt(TCP_INFO): %s", strerror(errno));
		memset(&info, 0, sizeof(info)); /* zero fill */
	}

	memcpy(ch->buf, &info, sizeof(info));
	ch->state = CLIENT_HANDLE_STATE_TCP_INFO;
	ch->event = EVENT_TYPE_WRITE;
	ch->remain_bytes = sizeof(info);
	put_write(ch, min(ch->remain_bytes, ch->buf_sz));
}

static void process_client_handle_accepted(struct client_handle *ch,
					   struct io_uring_cqe *cqe)
{
	struct rpchdr *hdr;

	if (ch->event != EVENT_TYPE_READ) {
		pr_err("invalid state/event pair: state=%d event=%d",
		       ch->state, ch->event);
		return;
	}

	if (cqe->res < 0) {
		pr_warn("%s: read: %s, connection closed",
			sockaddr_ntoa(&ch->addr), strerror(-cqe->res));
		goto close;
	}
	if (cqe->res == 0) {
		pr_info("%s: connection closed", sockaddr_ntoa(&ch->addr));
		goto close;
	}
	if (cqe->res < sizeof(struct rpchdr)) {
		pr_warn("%s: too short request, connection closed",
			sockaddr_ntoa(&ch->addr));
		goto close;
	}

	/* handle is ACCPETED, and read event completed, which means
	 * a new RPC request has come. Process it.
	 */
	hdr = (struct rpchdr *)ch->buf;
	switch (hdr->type) {
	case REQ_TYPE_START_FLOW:
		move_client_handle_flowing(ch, (struct rpc_start_flow *)hdr);
		break;
	case REQ_TYPE_TCP_INFO:
		move_client_handle_tcp_info(ch, (struct rpc_tcp_info *)hdr);
		break;
	default:
		pr_notice("invalid rpchdr type: %u", hdr->type);
	}

	return;

close:
	close(ch->sock);
	free(ch);
}

static void process_client_handle_flowing(struct client_handle *ch,
					  struct io_uring_cqe *cqe)
{
	
}

static void process_client_handle_tcp_info(struct client_handle *ch,
					   struct io_uring_cqe *cqe)
{
	
}


static int process_client_cqe(struct io_uring_cqe *cqe) 
{
	struct client_handle *ch = io_uring_cqe_get_data(cqe);

	switch (ch->state) {
	case CLIENT_HANDLE_STATE_ACCEPTING:
		process_client_handle_accepting(ch, cqe);
		break;
	case CLIENT_HANDLE_STATE_ACCEPTED:
		process_client_handle_accepted(ch, cqe);
		break;
	case CLIENT_HANDLE_STATE_FLOWING:
		process_client_handle_flowing(ch, cqe);
		break;
	case CLIENT_HANDLE_STATE_TCP_INFO:
		process_client_handle_tcp_info(ch, cqe);
		break;
	default:
		pr_err("invalid client handle state: %d", ch->state);
	}

	return 0;
}

static int server_loop(void)
{
	struct io_uring_cqe *cqes[DEFAULT_QUEUE_DEPTH];
	unsigned nr_cqes, i;
	int ret;

	pr_info("put the first accept() event");
	if (put_accept() < 0)
		return -1;
	if ((ret = io_uring_submit(ring)) < 0) {
		pr_err("io_uring_submit: %s", strerror(-ret));
		return -1;
	}

	pr_notice("start the server loop");
	while (1) {
		nr_cqes = io_uring_peek_batch_cqe(ring, cqes, serv.o->batch_sz);
		if (nr_cqes == 0) {
			if ((ret = io_uring_wait_cqe(ring, &cqes[0])) < 0) {
				pr_err("io_uring_wait_cqe: %s", strerror(-ret));
				return -1;
			}
			nr_cqes = 1;
		}

		for (i = 0; i < nr_cqes; i++)
			process_client_cqe(cqes[i]);

		io_uring_cq_advance(ring, i);

		if ((ret = io_uring_submit(ring)) < 0) {
			pr_err("io_uring_submit: %s", strerror(-ret));
			return -1;
		}
	}
	
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
	int ret;

	if (init_serv_socket(o) < 0)
		return -1;

	if (init_serv_io_uring(o) < 0)
		return -1;

	signal(SIGINT, sigint_handler);

	ret = server_loop();

	cleanup();
	return ret;
}


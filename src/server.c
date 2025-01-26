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
#include <util.h>


struct server {
	int 	sock;
	struct opts *o;
	struct io_uring ring;
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
	int	event;

	int	send_zc_failed;
	/* when send_zc failed, set to 1. send_zc raises two
	 * completions: first cqe has res and IORING_CQE_F_MORE, and
	 * the second cqe has res=0 and IORING_CQE_F_NOTIF. If
	 * IORING_CQE_F_MORE and res < 0, send_zc_faild is set to 1.
	 * Next, send_zc_faild == 1 and IORING_CQE_F_NOTIF is set,
	 * close the connection due to an error.
	 */

	/* fields for an RPC transaction */
	char	msg_buf[MSG_BUF_SZ];

	ssize_t	remain_bytes;	/* remain bytes to be xmitted */
	char	send_buf[0];	/* buf for send_zc follows the handle */
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
	int ret;

	ret = io_uring_queue_init(serv.o->queue_depth, ring, 0);
	if (ret < 0) {
		pr_err("io_uring_queue_init: %s", strerror(-ret));
		return -1;
	}

	return 0;
}


/* client handle processing */

static void put_accept_multishot(void)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe_always(ring);
	static struct client_handle ch = {}; /* handle just for accept() */

	pr_debug("put accept() multishot");

	ch.state = CLIENT_HANDLE_STATE_ACCEPTING;
	ch.event = EVENT_TYPE_ACCEPT;
	ch.addrlen = sizeof(ch.addr);

	io_uring_prep_multishot_accept(sqe, serv.sock,
				       (struct sockaddr *)&ch.addr, &ch.addrlen, 0);
	io_uring_sqe_set_data(sqe, &ch);
}

static void put_read(struct client_handle *ch)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe_always(ring);
	memset(ch->msg_buf, 0, sizeof(MSG_BUF_SZ));
	ch->event = EVENT_TYPE_READ;
	io_uring_prep_read(sqe, ch->sock, ch->msg_buf, MSG_BUF_SZ, 0);
	io_uring_sqe_set_data(sqe, ch);
}

static void put_write(struct client_handle *ch, size_t len)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe_always(ring);
	ch->event = EVENT_TYPE_WRITE;
	io_uring_prep_write(sqe, ch->sock, ch->msg_buf, len, 0);
	io_uring_sqe_set_data(sqe, ch);
}

static void put_write_rep_invalid(struct client_handle *ch)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe_always(ring);
	static char ri_buf[] = "I\n";

	ch->state = CLIENT_HANDLE_STATE_ACCEPTED;
	ch->event = EVENT_TYPE_WRITE;
	io_uring_prep_write(sqe, ch->sock, ri_buf, array_size(ri_buf), 0);
	io_uring_sqe_set_data(sqe, ch);
}

static void put_send_zc(struct client_handle *ch, size_t len)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe_always(ring);
	ch->event = EVENT_TYPE_SEND_ZC;
	io_uring_prep_send_zc(sqe, ch->sock, ch->send_buf, len, 0, 0);
	io_uring_sqe_set_data(sqe, ch);
}

static void close_client_handle(struct client_handle *ch)
{
	pr_debug("%s: close connection", ch->addrstr);
	if (ch->sock > 1)
		close(ch->sock);
	free(ch);
}

static void process_client_handle_accepting(struct client_handle *ch_accept,
					    struct io_uring_cqe *cqe)
{
	struct client_handle *ch;

	assert(ch_accept->event == EVENT_TYPE_ACCEPT);

	/* multishot accept() returns a new socket. allocate a new
	 * client_handle, and put read for waiting an RPC request.
	 */
	if (cqe->res < 0) {
		pr_warn("accept: %s", strerror(-cqe->res));
		return;
	}
	if ((ch = malloc(sizeof(*ch) + serv.o->buf_sz)) == NULL) {
		pr_err("malloc: %s", strerror(errno));
		close(cqe->res);
		return;
	}
	memset(ch, 0, sizeof(*ch));
	memset(ch->send_buf, '!', serv.o->buf_sz);
	ch->sock = cqe->res;
	ch->addrlen = sizeof(ch->addr);
	if (getsockname(ch->sock, (struct sockaddr *)&ch->addr, &ch->addrlen) < 0) {
		pr_err("getsockname: %s", strerror(errno));
		return;
	}
	sockaddr_ntop(&ch->addr, ch->addrstr, ADDRSTRLEN);
	pr_info("%s: new connection accepted", ch->addrstr);

	int v = 1;
	if (setsockopt(ch->sock, SOL_TCP, TCP_NODELAY, &v, sizeof(v)) < 0)
		pr_warn("%s: setoskcopt(TCP_NODELAY): %s", ch->addrstr, strerror(errno));

	ch->state = CLIENT_HANDLE_STATE_ACCEPTED;
	put_read(ch);
}

void move_client_handle_flowing(struct client_handle *ch, ssize_t bytes)
{
	/* start RPC FLOWING */
	pr_debug("%s: START FLOW %zd", ch->addrstr, bytes);
	ch->state = CLIENT_HANDLE_STATE_FLOWING;
	ch->remain_bytes = bytes;
	put_send_zc(ch, min(ch->remain_bytes, serv.o->buf_sz));
}

void move_client_handle_tcp_info(struct client_handle *ch)
{
	/* Start RPC TCP_INFO */
	int ret;

	pr_debug("%s: RPC TCP_INFO", ch->addrstr);

	ret = build_tcp_info_string(ch->sock, ch->msg_buf, MSG_BUF_SZ);
	if (ret < 0 || MSG_BUF_SZ <= ret) {
		pr_err("build_tcp_info_string failed: %d", ret);
		put_write_rep_invalid(ch);
		return;
	}

	ch->state = CLIENT_HANDLE_STATE_TCP_INFO;
	ch->remain_bytes = ret;
	put_write(ch, min(ret, MSG_BUF_SZ));
}

static void process_client_handle_accepted(struct client_handle *ch,
					   struct io_uring_cqe *cqe)
{
	if (ch->event != EVENT_TYPE_WRITE && ch->event != EVENT_TYPE_READ) {
		pr_err("invalid state/event pair: state=%d event=%d",
		       ch->state, ch->event);
		close_client_handle(ch);
		return;
	}

	if (ch->event == EVENT_TYPE_WRITE) {
		/* error has been sent. put a read event for the next request */
		put_read(ch);
		return;
	}

	/* here we assume EVENT_TYPE_READ */
	if (cqe->res < 0) {
		pr_warn("%s: read: %s, connection closed",
			ch->addrstr, strerror(-cqe->res));
		goto close;
	}
	if (cqe->res == 0) {
		pr_info("%s: connection closed", ch->addrstr);
		goto close;
	}

	ch->msg_buf[MSG_BUF_SZ] = '\0';

	/* handle is ACCPETED, and read event occurs, which means a
	 * new RPC request has come. Process it.
	 */
	ssize_t bytes;
	if (sscanf(ch->msg_buf, RPC_REQ_START_FLOW " %zd", &bytes) == 1 && bytes > 0)
		move_client_handle_flowing(ch, bytes);
	else if (strncmp(ch->msg_buf, RPC_REQ_TCP_INFO, strlen(RPC_REQ_TCP_INFO)) == 0)
		move_client_handle_tcp_info(ch);
	else {
		pr_warn("%s: invalid request: %s", ch->addrstr, ch->msg_buf);
		put_write_rep_invalid(ch);
	}

	return;

close:
	close_client_handle(ch);
}

static void process_client_handle_flowing(struct client_handle *ch,
					  struct io_uring_cqe *cqe)
{
	if (ch->event != EVENT_TYPE_SEND_ZC) {
		pr_err("invalid state/event pair: state=%d event=%d",
		       ch->state, ch->event);
		close_client_handle(ch);
		return;
	}

	/* handle is FLOWING. A send_zc rises complitions. 
	 */
	if (cqe->res < 0) {
		if (!(cqe->flags & IORING_CQE_F_MORE)) {
			/* not multi CQEs && send return < 0 vlue.
			 * close the connection due to error. */
			pr_notice("%s: send_zc: %s, close connection",
				  ch->addrstr, strerror(-cqe->res));
			close_client_handle(ch);
		} else {
			/* multi CQEs for send_zc. defer closing the
			 * socket until cqe with IORING_CQE_F_NOTIF
			 * has come.
			 */
			pr_notice("%s: send_zc: %s, prepare for closing connection",
				  ch->addrstr, strerror(-cqe->res));
			ch->send_zc_failed = 1;
		}
		return;
	}
	if (ch->send_zc_failed && cqe->flags & IORING_CQE_F_NOTIF) {
		close_client_handle(ch);
		return;
	}

	ch->remain_bytes -= cqe->res;

	if (cqe->flags & IORING_CQE_F_MORE)
		return; /* more cqe for the last write (send_zc) will come */

	if (ch->remain_bytes > 0) {
		/* we need to send more bytes. put a new send_zc */
		put_send_zc(ch, min(ch->remain_bytes, serv.o->buf_sz));
	} else {
		/* all bytes transfered */
		pr_debug("%s: RPC FLOW finished", ch->addrstr);
		ch->state = CLIENT_HANDLE_STATE_ACCEPTED;
		put_read(ch);
	}

	return;
}

static void process_client_handle_tcp_info(struct client_handle *ch,
					   struct io_uring_cqe *cqe)
{
	if (ch->event != EVENT_TYPE_WRITE) {
		pr_err("invalid state/event pair: state=%d event=%d",
		       ch->state, ch->event);
		close_client_handle(ch);
		return;
	}
	
	/* handle is TCP_INFO, we have sent tcp_info string on
	 * ch->msg_buf. Next is to change the state to ACCEPTED.
	 */
	if (cqe->res < 0) {
		pr_notice("%s: write: %s, close connection",
			  ch->addrstr, strerror(-cqe->res));
		return;
	}

	ch->remain_bytes -= cqe->res;
	if (ch->remain_bytes > 0)
		pr_warn("%s: send tcp_info truncated %ld bytes",
			ch->addrstr, ch->remain_bytes);

	pr_debug("%s: RPC TCP_INFO finished", ch->addrstr);
	ch->state = CLIENT_HANDLE_STATE_ACCEPTED;
	put_read(ch);

	return;
}


static void server_process_cqe(struct io_uring_cqe *cqe) 
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
		close_client_handle(ch);
	}
}

static int server_loop(void)
{
	struct io_uring_cqe *cqes[MAX_BATCH_SZ];
	unsigned nr_cqes, i;
	int ret;

	put_accept_multishot();
	if ((ret = io_uring_submit(ring)) < 0) {
		pr_err("io_uring_submit: %s", strerror(-ret));
		return -1;
	}

	pr_notice("start the server loop");
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


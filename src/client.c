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
	cli.run = true;
	cli.o = o;

	if (init_client_io_uring() < 0)
		return -1;

	signal(SIGINT, sigint_handler);

	return client_loop();
}

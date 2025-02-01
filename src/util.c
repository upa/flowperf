
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <util.h>
#include <print.h>



void sockaddr_ntop(struct sockaddr_storage *ss, char *buf, socklen_t size)
{
	char addr[64] = "(invalid)";
	int port;

	switch (ss->ss_family) {
	case AF_INET:
		struct sockaddr_in *sin = (struct sockaddr_in *)ss;
		if (!inet_ntop(ss->ss_family, &sin->sin_addr, addr, sizeof(addr)))
			pr_warn("invalid IPv4 address?");
		port = ntohs(sin->sin_port);
		break;
	case AF_INET6:
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
		if (!inet_ntop(ss->ss_family, &sin6->sin6_addr, addr, sizeof(addr)))
			pr_warn("invalid IPv6 address?");
		port = ntohs(sin6->sin6_port);
		break;
	default:
		snprintf(buf, size, "invalid-family(%u)", ss->ss_family);
		return;
	}

	snprintf(buf, size, "%s:%d", addr, port);
}

char *sockaddr_ntoa(struct sockaddr_storage *ss)
{
	static char buf[128];

	sockaddr_ntop(ss, buf, sizeof(buf));

	return buf;
}


int build_tcp_info_string(int sock, char *buf, size_t size)
{
	struct tcp_info info;
	socklen_t infolen = sizeof(info);

	if (getsockopt(sock, IPPROTO_TCP, TCP_INFO, &info, &infolen) < 0) {
		pr_err("getsockopt(TCP_INFO): %s", strerror(errno));
		memset(&info, 0, infolen);
	}

	/*
	 * tcpi_sacked: the number of segments marked to be
	 * transmitted by the selective ACK mechanism during the
	 * connection. This happens when packets loss, or reordering
	 * happens.
	 *
	 * tcpi_retransmits: the number of segments retransmitted by
	 * RTO or fast retransmission during the connection.
	 */
	memset(buf, 0, size);
	return snprintf(buf, size,
			"lost=%u,"	/* tcpi_lost 		*/
			"sack=%u,"	/* tcpi_sacked		*/
			"retr=%u,"	/* tcpi_retransmits 	*/
			"sego=%u,"	/* tcpi_segs_out 	*/
			"segi=%u",	/* tcpi_segs_in 	*/
			info.tcpi_lost,
			info.tcpi_sacked,
			info.tcpi_total_retrans,
			info.tcpi_segs_out,
			info.tcpi_segs_in
		);
}


/* runnig/stop flag */
static volatile sig_atomic_t run = 0;

void start_running(void) {
	run = 1;
}

void stop_running(void) {
	run = 0;
}

bool is_running(void)
{
	return (run != 0);
}


/* stack of integer, for socket cache */
int_stack_t *int_stack_alloc(size_t size)
{
	int_stack_t *stack;

	if ((stack = malloc(sizeof(*stack))) == NULL)
		return NULL;

	if ((stack->stack = calloc(size, sizeof(int))) == NULL) {
		free(stack);
		return NULL;
	}

	stack->size = size;
	stack->len = 0;
	return stack;
}

size_t int_stack_len(int_stack_t *stack)
{
	return stack->len;
}

void int_stack_push(int_stack_t *stack, int v)
{
	assert(stack->len < stack->size);
	stack->stack[stack->len++] = v;
}

int int_stack_pop(int_stack_t *stack)
{
	assert(stack->len > 0);
	return stack->stack[--stack->len];
}

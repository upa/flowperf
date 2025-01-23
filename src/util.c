
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <liburing.h>

#include <util.h>
#include <print.h>

struct io_uring_sqe *io_uring_get_sqe_always(struct io_uring *ring)
{
	if (unlikely(io_uring_sq_space_left(ring) == 0))
		io_uring_submit_and_wait(ring, 1);
	return io_uring_get_sqe(ring);
}

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


int build_tcp_info_string(struct tcp_info *info, char *buf, size_t size)
{
	/*
	 * tcpi_sacked: the number of segments marked to be
	 * transmitted by the selective ACK mechanism during the
	 * connection. This happens when packets loss, or reordering
	 * happens.
	 *
	 * tcpi_retransmits: the number of segments retransmitted by
	 * RTO or fast retransmission during the connection.
	 */
	return snprintf(buf, size,
			"lost=%u "	/* tcpi_lost 		*/
			"sack=%u "	/* tcpi_sacked		*/
			"retr=%u "	/* tcpi_retransmits 	*/
			"sego=%u "	/* tcpi_segs_out 	*/
			"segi=%u\n",	/* tcpi_segs_in 	*/
			info->tcpi_lost,
			info->tcpi_sacked,
			info->tcpi_retransmits,
			info->tcpi_segs_out,
			info->tcpi_segs_in
		);
}

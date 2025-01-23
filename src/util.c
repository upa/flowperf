
#include <stdio.h>
#include <string.h>
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


int build_tcp_info_string(struct tcp_info *info, char *buf, size_t size)
{
	return snprintf(buf, size,
			"lost=%u "	/* tcpi_lost 		*/
			"retr=%u "	/* tcpi_retrans 	*/
			"tret=%u "	/* tcpi_retransmits 	*/
			"totr=%u "	/* tcpi_total_retrans 	*/
			"fack=%u "	/* tcpi_fackets 	*/
			"reor=%u "	/* tcpi_reodering 	*/
			"sego=%u "	/* tcpi_segs_out 	*/
			"segi=%u\n",	/* tcpi_segs_in 	*/
			info->tcpi_lost,
			info->tcpi_retrans,
			info->tcpi_retransmits,
			info->tcpi_total_retrans,
			info->tcpi_fackets,
			info->tcpi_reordering,
			info->tcpi_segs_out,
			info->tcpi_segs_in
		);
}

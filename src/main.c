
#include <client.h>
#include <server.h>
#include <options.h>
#include <print.h>


static void usage()
{
	printf("flowperf: performance measurement for flow completion times\n"
	       "\n"
		"Usage: flowperf [-s|-c] [options]"
	       "\n"
	       "    -s              server mode\n"
	       "    -c              client mode\n"
	       "\n"
	       "  Common options\n"
	       "    -p PORT         port number\n"
	       "    -q QUEUE_DEPTH  io_uring queue depth\n"
	       "    -B BUF_SIZE     size of a buffer region (default %dKB)\n"
	       "\n"
	       "    -b BATCH_SIZE   batch size for processing io_uring\n"
	       "    -v              increment verbose output level\n"
	       "    -h              print this help\n"
	       "\n"
	       "  Server mode options\n"
	       "    -a ADDRESS        local address to bind\n"
	       "    -z                use tx zero copy\n"
	       "\n"
	       "  Client mode options\n"
	       "    -n NUMBER       number of flows to be done on the benchmark\n"
	       "    -t TIME         time (sec) of the benchmark, default 10 sec\n"
	       "    -x CONCURRENCY  number of cunccurent flows\n"
	       "    -N NR_BUFS      number of buffer regions for recv (default %d):\n"
	       "                    BUF_SIZE x NR_BUFS memory regions are registered\n"
	       "                    to io_uring via io_uring_register_buf_ring()\n"
	       "    -T              get tcp_info from the server side for each RPC\n"
	       "\n"
	       "    -d ADDR:PROB    dest address and its probability\n"
	       "    -D ADDR_TXT     txt file contains 'ADDR PROBABLITY' per line\n"
	       "\n"
	       "    -f FLOW_SZ:PROB flow size (byte) and its probablity\n"
	       "    -F FLOW_TXT     txt file contains 'FLOWSIZE PROBABILITY' per line\n"
	       "\n"
	       "    -i INTVAL:PROB  interval (nsec) and its probablity\n"
	       "    -I INTVAL_TXT   txt file contains 'INTERVAL PROBABLITY' per line\n"
	       "\n\n",
	       MIN_BUF_SZ / 1024,
	       MIN_NR_BUFS);
}


static char _default_local_addr[] = DEFAULT_LOCAL_ADDR;

static int parse_args(int argc, char **argv, struct opts *o)
{
	char *c;
	int ch;

	memset(o, 0, sizeof(*o));
	o->port = DEFAULT_PORT;
	o->queue_depth = DEFAULT_QUEUE_DEPTH;
	o->buf_sz = MIN_BUF_SZ;
	o->nr_bufs = MIN_NR_BUFS;
	o->batch_sz = DEFAULT_BATCH_SZ;
	o->severity = SEVERITY_WARN;

	/* server options */
	o->local_addr = _default_local_addr;

	/* client options */
	o->nr_flows = 0;
	o->time = 10;
	o->concurrency = 1;
	if ((o->addrs = prob_list_alloc()) == NULL)
		return -1;
	if ((o->flows = prob_list_alloc()) == NULL)
		return -1;
	if ((o->intervals = prob_list_alloc()) == NULL)
		return -1;

#define OPTSTR_COMMON "scp:q:B:b:vh"
#define OPTSTR_SERVER "a:z"
#define OPTSTR_CLIENT "n:t:x:N:Td:D:f:F:i:I:"
#define OPTSTR OPTSTR_COMMON OPTSTR_SERVER OPTSTR_CLIENT

	while ((ch = getopt(argc, argv, OPTSTR)) != -1) {
		switch (ch) {
		case 's':
			o->mode = MODE_SERVER;
			break;
		case 'c':
			o->mode = MODE_CLIENT;
			break;
		case 'p':
			o->port = optarg;
			break;
		case 'q':
			o->queue_depth = atoi(optarg);
			break;
		case 'B':
			o->buf_sz = atoi(optarg);
			if (o->buf_sz < MIN_BUF_SZ) {
				pr_err("invalid buf_sz %s (must be ge %d)",
				       optarg, MIN_BUF_SZ);
			}
			break;
		case 'b':
			o->batch_sz = atoi(optarg);
			if (o->batch_sz < 1 || MAX_BATCH_SZ < o->batch_sz) {
				pr_err("invalid batch size %s (must be gt 1 and lt %d)",
				       optarg, MAX_BATCH_SZ);
				return -1;
			}
			break;
		case 'v':
			o->severity++;
			break;
		case 'h':
			usage();
			return -1;

		case 'a': /* server options */
			o->local_addr = optarg;
			break;
		case 'z':
			o->send_zero_copy = true;
			break;

		case 'n': /* client options */
			o->nr_flows = atoi(optarg);
			if (o->nr_flows < 0) {
				pr_err("invalid number of flows: %s", optarg);
				return -1;
			}
			break;
		case 't':
			o->time = atoi(optarg);
			if (o->time < 1) {
				pr_err("invalid time: %s", optarg);
				return -1;
			}
			break;
		case 'x':
			o->concurrency = atoi(optarg);
			if (o->concurrency < 1) {
				pr_err("invalid concurrency: %s", optarg);
				return -1;
			}
			break;
		case 'N':
			o->nr_bufs = atoi(optarg);
			if (o->nr_bufs < MIN_NR_BUFS) {
				pr_err("invalid nr_bufs %s (must be ge %d)",
				       optarg, MIN_NR_BUFS);
			}
			break;
		case 'T':
			o->server_tcp_info = true;
			break;

		case 'd':
			c = strrchr(optarg, ':');
			if (!c) {
				pr_err("invalid addr:prob format: %s", optarg);
				return -1;
			}
			*c = '\0';
			if (prob_list_append(o->addrs, atof(c+1), optarg) < 0)
				return -1;
			break;
		case 'D':
			if (prob_list_load_text(o->addrs, optarg) < 0)
				return -1;
			break;

		case 'f':
			c = strrchr(optarg, ':');
			if (!c) {
				pr_err("invalid flow:prob format: %s", optarg);
				return -1;
			}
			*c = '\0';
			if (prob_list_append(o->flows, atof(c+1), optarg) < 0)
				return -1;
			break;
		case 'F':
			if (prob_list_load_text(o->flows, optarg) < 0)
				return -1;
			break;

		case 'i':
			c = strrchr(optarg, ':');
			if (!c) {
				pr_err("invalid interval:prob format: %s", optarg);
				return -1;
			}
			*c = '\0';
			if (prob_list_append(o->intervals, atof(c+1), optarg) < 0)
				return -1;
			break;
		case 'I':
			if (prob_list_load_text(o->intervals, optarg) < 0)
				return -1;
			break;

		default:
			usage();
			return -1;
		}
	}

	/* validate */
	if (o->queue_depth < o->batch_sz) {
		pr_err("batch size must be less than queue depth");
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct opts o;

	if (parse_args(argc, argv, &o) < 0)
		return -1;

	set_print_severity(o.severity);

	switch (o.mode) {
	case MODE_SERVER:
		return start_server(&o);
	case MODE_CLIENT:
		/* to be implemented */
		return start_client(&o);
	}

	pr_err("-s or -c option is required.");

	return -1;
}

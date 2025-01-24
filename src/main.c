
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
	       "    -q QUEUE_DEPTH  iouring queue depth\n"
	       "    -b BUF_SIZE     buffer size for each handle\n"
	       "    -B BATCH_SIZE   batch size for processing io uring\n"
	       "    -v              increment verbose output level\n"
	       "    -h              print this help\n"
	       "\n"
	       "  Server mode options\n"
	       "    -a ADDRESS        local address to bind\n"
	       "\n"
	       "  Client mode options\n"
	       "    -n NUMBER       number of flows to be done on the benchmark\n"
	       "    -t TIME         time (sec) of the benchmark, default 10 sec\n"
	       "    -x CONCURRENCY  number of cunccurent flows\n"
	       "\n"
	       "    -d ADDR_TXT     txt file contains 'ADDR PROBABLITY' per line\n"
	       "    -D ADDR:PROB    dest address and its probability\n"
	       "\n"
	       "    -f FLOW_TXT     txt file contains 'FLOWSIZE PROBABILITY' per line\n"
	       "    -F FLOW_SZ:PROB flow size (byte) and its probablity\n"
	       "\n"
	       "    -i INTVAL_TXT   txt file contains 'INTERVAL PROBABLITY' per line\n"
	       "    -I INTVAL:PROB  interval (nsec) and its probablity\n"
	       "\n\n");
}


static char _default_local_addr[] = DEFAULT_LOCAL_ADDR;

static int parse_args(int argc, char **argv, struct opts *o)
{
	char *c;
	int ch;

	memset(o, 0, sizeof(*o));
	o->port = DEFAULT_PORT;
	o->queue_depth = DEFAULT_QUEUE_DEPTH;
	o->severity = SEVERITY_WARN;
	o->buf_sz = DEFAULT_HANDLE_BUF_SZ;
	o->batch_sz = DEFAULT_BATCH_SIZE;

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

#define OPTSTR_COMMON "scp:q:b:B:vh"
#define OPTSTR_SERVER "a:"
#define OPTSTR_CLIENT "n:t:x:d:D:f:F:i:I:"
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
		case 'b':
			o->buf_sz = atoi(optarg);
			if (o->buf_sz < 4096) {
				pr_err("too small size: %s", optarg);
				return -1;
			}
			break;
		case 'B':
			o->batch_sz = atoi(optarg);
			if (o->batch_sz < 1 || DEFAULT_QUEUE_DEPTH < o->batch_sz) {
				pr_err("invalid batch size: %s", optarg);
				return -1;
			}
			break;
		case 'v':
			o->severity++;
			break;
		case 'h':
			usage();
			return -1;

		case 'a':
			o->local_addr = optarg;
			break;

		case 'n':
			o->nr_flows = atoi(optarg);
			if (o->nr_flows < 0) {
				pr_err("invalid number of flows: %s", optarg);
				return -1;
			}
			break;
		case 't':
			o->time = atoi(optarg);
			if (o->time < 0) {
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
		case 'd':
			if (prob_list_load_text(o->addrs, optarg) < 0)
				return -1;
			break;
		case 'D':
			c = strrchr(optarg, ':');
			if (!c) {
				pr_err("invalid addr:prob format: %s", optarg);
				return -1;
			}
			*c = '\0';
			if (prob_list_append(o->addrs, atof(c+1), optarg) < 0)
				return -1;
			break;
		case 'f':
			if (prob_list_load_text(o->flows, optarg) < 0)
				return -1;
			break;
		case 'F':
			c = strrchr(optarg, ':');
			if (!c) {
				pr_err("invalid flow:prob format: %s", optarg);
				return -1;
			}
			*c = '\0';
			if (prob_list_append(o->flows, atof(c+1), optarg) < 0)
				return -1;
			break;
		case 'i':
			if (prob_list_load_text(o->intervals, optarg) < 0)
				return -1;
			break;
		case 'I':
			c = strrchr(optarg, ':');
			if (!c) {
				pr_err("invalid interval:prob format: %s", optarg);
				return -1;
			}
			*c = '\0';
			if (prob_list_append(o->intervals, atof(c+1), optarg) < 0)
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


#include <time.h>

#include <client.h>
#include <server.h>
#include <options.h>
#include <print.h>


static void usage()
{
	fprintf(stderr,
		"flowperf: performance measurement for flow completion times\n"
		"\n"
		"Usage: flowperf [-s|-c] [options]"
		"\n"
		"    -s              server mode\n"
		"    -c              client mode\n"
		"\n"
		"  Common options\n"
		"    -p PORT         port number\n"
		"    -B BUF_SIZE     size of a buffer region (default %dKB)\n"
		"\n"
		"    -q QUEUE_DEPTH  io_uring queue depth\n"
		"    -b BATCH_SIZE   batch size for processing io_uring\n"
		"    -v              increment verbose output level\n"
		"    -h              print this help\n"
		"\n"
		"  Server mode options\n"
		"    -a ADDRESS      local address to bind\n"
		"    -N NR_BUFS      number of buffer regions for recv (default %d):\n"
		"                    BUF_SIZE x NR_BUFS memory regions are registered\n"
		"                    to io_uring via io_uring_register_buf_ring()\n"
		"\n"
		"  Client mode options\n"
		"    -n NUMBER       number of flows to be done, default 0 (inifinit)\n"
		"    -t DURATION     test duration (sec), default 10, 0 means inifnite\n"
		"    -x CONCURRENCY  number of cunccurent flows, default 1\n"
		"    -T              get tcp_info from the server side for each flow\n"
		"\n"
		"    -R RANDOM_SEED  set random seed\n"
		"    -C              cache and reuse TCP connections\n"
                "    -S START_TIME   specify start time by unixtime\n"
		"\n"
		"    -d ADDR@WEIGHT    dest address and its probability\n"
		"    -D ADDR_TXT       txt contains 'ADDR WEIGHT' per line\n"
		"\n"
		"    -f FLOW_SZ@WEIGHT flow size (byte) and its probablity\n"
		"    -F FLOW_TXT       txt contains 'FLOWSIZE WEIGHT' per line\n"
		"\n"
		"    -i INTVAL@WEIGHT  interval (nsec) and its probablity\n"
		"    -I INTVAL_TXT     txt contains 'INTERVAL WEIGHT' per line\n"
		"\n"
		"    When @ does not exist on -d/-f/-i values, weight is set to 1."
		"\n\n",
		DEFAULT_BUF_SZ / 1024,
		DEFAULT_NR_BUFS);
}


static char _default_local_addr[] = DEFAULT_LOCAL_ADDR;

static int parse_args(int argc, char **argv, struct opts *o)
{
	double p;
	char *c;
	int ch;

	memset(o, 0, sizeof(*o));
	o->port = DEFAULT_PORT;
	o->queue_depth = DEFAULT_QUEUE_DEPTH;
	o->buf_sz = DEFAULT_BUF_SZ;
	o->nr_bufs = DEFAULT_NR_BUFS;
	o->batch_sz = DEFAULT_BATCH_SZ;
	o->severity = SEVERITY_WARN;

	/* server options */
	o->local_addr = _default_local_addr;
	o->random_seed = time(NULL);

	/* client options */
	o->nr_flows = -1;
	o->duration = -1;

	o->concurrency = 1;
	if ((o->addrs = prob_list_alloc()) == NULL)
		return -1;
	if ((o->flows = prob_list_alloc()) == NULL)
		return -1;
	if ((o->intervals = prob_list_alloc()) == NULL)
		return -1;

#define OPTSTR_COMMON "scp:B:q:b:vh"
#define OPTSTR_SERVER "a:N:"
#define OPTSTR_CLIENT "n:t:x:TR:CS:d:D:f:F:i:I:"
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
		case 'B':
			o->buf_sz = atoi(optarg);
			if (o->buf_sz < 1) {
				pr_err("invalid buf_sz %s", optarg);
				return -1;
			}
			break;
		case 'q':
			o->queue_depth = atoi(optarg);
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
		case 'N':
			o->nr_bufs = atoi(optarg);
			if (o->nr_bufs < 1) {
				pr_err("invalid nr_bufs %s", optarg);
				return -1;
			}
			break;

		case 'n': /* client options */
			o->nr_flows = atoi(optarg);
			if (o->nr_flows < 0) {
				pr_err("invalid number of flows: %s", optarg);
				return -1;
			}
			break;
		case 't':
			o->duration = atoi(optarg);
			if (o->duration < 0) {
				pr_err("invalid duration: %s", optarg);
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
		case 'T':
			o->server_tcp_info = true;
			break;
		case 'R':
			o->random_seed = atol(optarg);
			if (o->random_seed < 0) {
				pr_err("invalid random seed %s", optarg);
				return -1;
			}
			break;

		case 'C':
			o->cache_sockets = true;
			break;

                case 'S':
                        o->start_time = atoll(optarg);
                        if (o->start_time < 1) {
                                pr_err("invalid start time %s", optarg);
                                return -1;
                        }
                        break;

		case 'd':
			c = strrchr(optarg, '@');
			if (c) {
				*c = '\0';
				p = atof(c+1);
			} else {
				pr_info("no @ in '%s', set 1", optarg);
				p = 1;
			}
			if (prob_list_append(o->addrs, p, optarg) < 0)
				return -1;
			break;
		case 'D':
			if (prob_list_load_text(o->addrs, optarg) < 0)
				return -1;
			break;

		case 'f':
			c = strrchr(optarg, '@');
			if (c) {
				*c = '\0';
				p = atof(c+1);
			} else  {
				pr_info("no @ in '%s', set 1", optarg);
				p = 1;
			}
			if (prob_list_append(o->flows, p, optarg) < 0)
				return -1;
			break;
		case 'F':
			if (prob_list_load_text(o->flows, optarg) < 0)
				return -1;
			break;

		case 'i':
			c = strrchr(optarg, '@');
			if (c) {
				*c = '\0';
				p = atof(c+1);
			} else  {
				pr_info("no @ in '%s', set 1", optarg);
				p = 1;
			}
			if (prob_list_append(o->intervals, p, optarg) < 0)
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

	srand(o->random_seed);

	if (o->nr_flows < 0 && o->duration < 0)
		o->duration = 10;

	if (o->nr_flows < 0)
		o->nr_flows = 0;

	if (o->duration < 0)
		o->duration = 0;

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

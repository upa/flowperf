
#include <server.h>
#include <opts.h>
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
	       "    -v              increment verbose output level\n"
	       "    -h              print this help\n"
	       "\n"
	       "  Server mode options\n"
	       "    -a ADDRESS      local address to bind\n"
	       "\n\n"
		);
}

static int parse_args(int argc, char **argv, struct opts *o)
{
	int ch;

	memset(o, 0, sizeof(*o));
	o->port = DEFAULT_PORT;
	o->queue_depth = DEFAULT_QUEUE_DEPTH;
	o->severity = SEVERITY_WARN;
	o->buf_sz = DEFAULT_HANDLE_BUF_SZ;

	while ((ch = getopt(argc, argv, "scp:q:b:vha:")) != -1) {
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
			break;
		case 'v':
			o->severity++;
			break;
		case 'h':
			usage();
			return 0;
		case 'a':
			o->local_addr = optarg;
			break;
		default:
			usage();
			return -1;
		}
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
		break;
	}

	pr_err("-s or -c option is required.");

	return -1;
}

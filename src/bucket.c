
#include <time.h>

#include <util.h>

struct bucket {
        time_t window_ns;       /* update window */
        long long refill;       /* refilled per window */
        long long token;        /* number of transations per window */

        struct timespec last;   /* last time when window end */
};

#define MIN_WINDOW_NS   1000    /* 1 usec */

void bucket_init(struct bucket *b, int tps)
{
        b->window_ns = max(SEC_NS / tps / 10, MIN_WINDOW_NS);
        b->token = tps / b->window_ns;
        b->refill = b->token;
        clock_gettime(CLOCK_MONOTONIC, &b->last);
}


time_t bocket_get_wait_duration(struct bucket *b)
{
        struct timespec now;
        long long elapsed;

        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed = timespec_sub_nsec(&now, &b->last);
        if (elapsed >= b->window_ns) {
                /* refill */
                b->token = b->refill;
                b->last = now;
        }

        if (b->token > 0) {
                b->token--;
                return 0;
        }

        /* no more token. sleep until next window */
        return b->window_ns - elapsed;
}

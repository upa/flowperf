
#ifndef _EVENT_H_
#define _EVENT_H_

#include <stdbool.h>
#include <liburing.h>

/* io event wrapper for io_uring */

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

/* check one sqe exists before get sqe */
static inline struct io_uring_sqe *io_uring_get_sqe_always(struct io_uring *ring)
{
        if (unlikely(io_uring_sq_space_left(ring) == 0))
                io_uring_submit_and_wait(ring, 1);
        return io_uring_get_sqe(ring);
}

struct io_event {
        int     type;
        int     state;
        void    *data;
};

#define EVENT_STATE_INIT        0
#define EVENT_STATE_POSTED	1
#define EVENT_STATE_ACKED	2

#define EVENT_TYPE_INVALID      0
#define EVENT_TYPE_ACCEPT       1
#define EVENT_TYPE_CONNECT      2
#define EVENT_TYPE_READ         3
#define EVENT_TYPE_WRITE        4
#define EVENT_TYPE_SEND         5
#define EVENT_TYPE_RECV         6
#define EVENT_TYPE_SENDMSG	8
#define EVENT_TYPE_RECVMSG	9
#define EVENT_TYPE_TIMEOUT      10
#define EVENT_TYPE_CANCEL       11
#define __EVENT_TYPE_MAX	12


static inline bool io_event_is_posted(struct io_event *e)
{
	return e->state == EVENT_STATE_POSTED;
}

static inline void io_event_init(struct io_event *e, int type, void *data)
{
	e->state = EVENT_STATE_INIT;
	e->type = type;
	e->data = data;
}

static inline void *io_event_data(struct io_event *e)
{
	return e->data;
}

static inline void io_event_ack(struct io_event *e)
{
	e->state = EVENT_STATE_ACKED;
}

static inline void *io_event_ack_and_data(struct io_event *e)
{
	io_event_ack(e);
	return e->data;
}

static inline const char *io_event_name(struct io_event *e)
{
        static const char *type_names[] = {
                "invalid",
                "accept", "connect", "read", "write",
                "send", "recv",
                "timeout", "cancel",
        };
	
	if (e->type >= __EVENT_TYPE_MAX)
		return type_names[0];

        return type_names[e->type];
}

void post_connect(struct io_uring *ring, struct io_event *e,
                  int sock, struct sockaddr *sa, socklen_t salen);
void post_write(struct io_uring *ring, struct io_event *e,
		int fd, char *buf, size_t len);
void post_read(struct io_uring *ring, struct io_event *e,
               int fd, char *buf, size_t len);
void post_timeout(struct io_uring *ring, struct io_event *e, time_t nsec);
void post_accept_multishot(struct io_uring *ring, struct io_event *e, int fd);
void post_recv_multishot(struct io_uring *ring, struct io_event *e, int fd, int buf_grp);

void post_sendmsg(struct io_uring *ring, struct io_event *e, int fd, struct msghdr *msg,
		  unsigned flags);
void post_recvmsg(struct io_uring *ring, struct io_event *e, int fd, struct msghdr *msg,
		  unsigned flags);
void post_cancel(struct io_uring *ring, struct io_event *e, int fd);

#endif


#include <assert.h>

#include <event.h>

#define assert_event_state_for_post(e)					\
	do {								\
		assert(e->state == EVENT_STATE_INIT ||			\
		       e->state == EVENT_STATE_ACKED);			\
	} while(0)


void post_connect(struct io_uring *ring, struct io_event *e,
		  int sock, struct sockaddr *sa, socklen_t salen)
{
	struct io_uring_sqe *sqe;

	assert_event_state_for_post(e);

	sqe = io_uring_get_sqe_always(ring);
	io_uring_prep_connect(sqe, sock, sa, salen);
	io_uring_sqe_set_data(sqe, e);
	e->state = EVENT_STATE_POSTED;
}

void post_write(struct io_uring *ring, struct io_event *e,
		int fd, char *buf, size_t len)
{
	struct io_uring_sqe *sqe;

	assert_event_state_for_post(e);

	sqe = io_uring_get_sqe_always(ring);
	io_uring_prep_write(sqe, fd, buf, len, 0);
	io_uring_sqe_set_data(sqe, e);	
	e->state = EVENT_STATE_POSTED;
}

void post_read(struct io_uring *ring, struct io_event *e,
	       int fd, char *buf, size_t len)
{
	struct io_uring_sqe *sqe;

	assert_event_state_for_post(e);

	sqe = io_uring_get_sqe_always(ring);
	io_uring_prep_read(sqe, fd, buf, len, 0);
	io_uring_sqe_set_data(sqe, e);
	e->state = EVENT_STATE_POSTED;
}

void post_timeout(struct io_uring *ring, struct io_event *e, time_t nsec_abs)
{
	struct __kernel_timespec ts = {};
	struct io_uring_sqe *sqe;

	assert_event_state_for_post(e);
	
	ts.tv_nsec = nsec_abs;

	sqe = io_uring_get_sqe_always(ring);
	io_uring_prep_timeout(sqe, &ts, 0, 0);
	io_uring_sqe_set_data(sqe, e);
	e->state = EVENT_STATE_POSTED;
}

void post_recvmsg(struct io_uring *ring, struct io_event *e, int fd, struct msghdr *msg,
		  unsigned flags)
{
	struct io_uring_sqe *sqe;

	assert_event_state_for_post(e);

	sqe = io_uring_get_sqe_always(ring);
	io_uring_prep_recvmsg(sqe, fd, msg, flags);
	io_uring_sqe_set_data(sqe, e);
	e->state = EVENT_STATE_POSTED;
}

void post_accept_multishot(struct io_uring *ring, struct io_event *e, int fd)
{
	static struct sockaddr_storage ss; /* not used in practice */
	static socklen_t ss_len = sizeof(ss);
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe_always(ring);
	io_uring_prep_multishot_accept(sqe, fd, (struct sockaddr *)&ss, &ss_len, 0);
	io_uring_sqe_set_data(sqe, e);
	e->state = EVENT_STATE_POSTED;
}

void post_recv_multishot(struct io_uring *ring, struct io_event *e, int fd, int buf_grp)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe_always(ring);
	io_uring_prep_recv_multishot(sqe, fd, NULL, 0, 0);
	sqe->flags = IOSQE_BUFFER_SELECT;
	sqe->buf_group = buf_grp;
	io_uring_sqe_set_data(sqe, e);
	e->state = EVENT_STATE_POSTED;
}

void post_cancel(struct io_uring *ring, struct io_event *e, int fd)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe_always(ring);
	io_uring_prep_cancel_fd(sqe, fd, 0);
	io_uring_sqe_set_data(sqe, e);
	e->state = EVENT_STATE_POSTED;
}

/* flowperf.h */

#ifndef _FLOWPERF_H_
#define _FLOWPERF_H_


/* State machine of flowperf per-client handle on the server */

#define CLIENT_HANDLE_STATE_ACCEPTING	1
/* The initial state, waiting for a new client TCP connection by posting
 * an ACCEPT event.
 *
 * Assumed Completion Event:
 * - EVENT_TYPE_ACCEPT: Change state to ACCEPTED, and post recv muiltishot.
 */

#define CLIENT_HANDLE_STATE_ACCEPTED	2
/* Stable state. A client TCP connection is accpeted, and waiting
 *
 * Assumed Completion Event:
 * - EVENT_TYPE_RECV: consumes received bytes. If the last of byte on a received
 *   received message, the server sends tcp_info string to the client.
 * - EVENT_TYPE_WRITE: completion for tcp_info sent.
 */

#define CLIENT_HANDLE_STATE_CLOSING	3
/* Closing Connection puts cancel sqe to stop recv multishot for this client.
 */
  




/* State machine of flowperf connection handle on the client */

#define CONNECTION_HANDLE_STATE_CONNECTING	1
/* Initial state. The TCP connection is now connecting.
 *
 * Assumed Completion Event:
 * - EVENT_TYPE_CONNECT: connect() is done.
 *
 * After connect() successed, change the state to FLOWING and start to
 * send bytes.
 */

#define CONNECTION_HANDLE_STATE_FLOWING		2
/* Benchmarking, receving data from the socket.
 *
 * Assumed Completion Event:
 * - EVENT_TYPE_READ: read data until flow_start->size bytes received.
 *
 * After flow_start->size bytes received, change the state to TCP_INFO
 *  by sending TCP_INFO or to WAIT
 */
   
#define CONNECTION_HANDLE_STATE_WAIT_ACK	3

#define CONNECTION_HANDLE_STATE_INTERVAL	4
/* Sleep a while as flow interval time.
 *
 * Assumed Compeltion Event:
 * - EVENT_TYPE_TIMEOUT: wait until the posted timeout.
 *
 * After TIMEOUT completion occurs, close the connection and start the
 * next connection of an RPC.
 */


#define CONNECTION_HANDLE_STATE_DONE		5



inline static char connection_handle_state_name(int state)
{
	switch (state) {
	case CONNECTION_HANDLE_STATE_CONNECTING:
		return 'c';
	case CONNECTION_HANDLE_STATE_FLOWING:
		return 'f';
	case CONNECTION_HANDLE_STATE_WAIT_ACK:
		return 'a';
	case CONNECTION_HANDLE_STATE_INTERVAL:
		return 'i';
	case CONNECTION_HANDLE_STATE_DONE:
		return 'd';
	}
	return 'x';
}


#define EVENT_TYPE_ACCEPT	0
#define EVENT_TYPE_CONNECT	1
#define EVENT_TYPE_READ		2
#define EVENT_TYPE_WRITE	3
#define EVENT_TYPE_SEND		4
#define EVENT_TYPE_RECV		5
#define EVENT_TYPE_TIMEOUT	6
#define EVENT_TYPE_CANCEL	7

inline static const char *event_type_name(int type)
{
	static const char *type_names[] = {
		"accept", "connect", "read", "write",
		"send", "recv",
		"timeout", "cancel"
	};
	return type_names[type];
}


/* RPC Request Format. */
#define RPC_REQ_START_FLOW	"F"
/* "F [FLOW_SIZE]"
 *
 * Server returns FLOW_SIZE bytes
 */

#define RPC_REQ_TCP_INFO	"T"
/* "T"
 *
 * Server returns tcp_info in "key=value key=value ...\n" string.
 * The string is terminated by '\n'
 */

#define RPC_REP_INVALID		"I"	/* I */
/* "I"
 *
 * Server returns 'I' if RPC REQ is invalid.
 */

#define RPC_TAIL_MARK_END	'E'
#define RPC_TAIL_MARK_ACK	'A'
#define RPC_TAIL_MARK_TCP_INFO	'T'

#endif /* _FLOWPERF_H_ */

/* flowperf.h */

#ifndef _FLOWPERF_H_
#define _FLOWPERF_H_


/* State machine of flowperf per-client handle on the server */

#define CLIENT_HANDLE_STATE_ACCEPTING	1
/* The initial state, waiting for a new client TCP connection by posting
 * an ACCEPT event.
 *
 * Assumed Completion Event:
 * - EVENT_TYPE_ACCEPT: Change state to ACCEPTED, and post EVENT_TYPE_READ.
 */

#define CLIENT_HANDLE_STATE_ACCEPTED	2
/* Stable state. A client TCP connection is accpeted, and waiting for
 * an RPC request by posting a READ event.
 *
 * Assumed Completion Event:
 * - EVENT_TYPE_READ: Change the state to FLOWING or TCP_INFO accroing to
 *   the RPC request read from the socket.
 */

#define CLIENT_HANDLE_STATE_FLOWING	3
/* Sending flow. Write data to the client socket until
 * start_flow->size bytes transferred.
 *
 * Assumed Completion Event:
 * - EVENT_TYPE_WRITE: Write date to the client socket until
 *   start_flow->size bytes transmitted.
 *
 * After the flow transferred, change the state to ACCEPTED or TCP_INFO.
 */

#define CLIENT_HANDLE_STATE_TCP_INFO	4
/* Sending struct tcp_info of this client socket.
 * 
 * Assumed Completion Event:
 * - EVENT_TYPE_WRITE: Write tcp_info to the client socket.
 *
 * After the write event completed, change the state to ACCEPTED.
 */




/* State machine of flowperf connection handle on the client */

#define CONNECTION_HANDLE_STATE_CONNECTING	1
/* Initial state. The TCP connection is now connecting.
 *
 * Assumed Completion Event:
 * - EVENT_TYPE_CONNECT: connect() is done.
 *
 * After connect() successed, change the state to FLOWING by sending
 * REQ_TYPE_START_FLOW.
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
   
#define CONNECTION_HANDLE_STATE_TCP_INFO	3
/* Receving struct tcp_info
 *
 * Assumed Completion Event:
 * - EVENT_TYPE_READ: read data until sizeof(struct tcp_info) bytes received.
 *
 * After struct tcp_info received, change the state to FLOWING as the next benchmark
 * or to WAIT.
 */

#define CONNECTION_HANDLE_STATE_INTERVAL	4
/* Sleep a while as flow interval time.
 *
 * Assumed Compeltion Event:
 * - EVENT_TYPE_TIMEOUT: wait until the posted timeout.
 *
 * After TIMEOUT completion occurs, close the connection and start the
 * next connection of an RPC.
 */

#define CONNCTION_HANDLE_STATE_DONE		5


inline static char connection_handle_state_name(int state)
{
	switch (state) {
	case CONNECTION_HANDLE_STATE_CONNECTING:
		return 'c';
	case CONNECTION_HANDLE_STATE_FLOWING:
		return 'f';
	case CONNECTION_HANDLE_STATE_TCP_INFO:
		return 't';
	case CONNECTION_HANDLE_STATE_INTERVAL:
		return 'i';
	case CONNCTION_HANDLE_STATE_DONE:
		return 'd';
	}
	return 'x';
}


#define EVENT_TYPE_ACCEPT	0
#define EVENT_TYPE_CONNECT	1
#define EVENT_TYPE_READ		2
#define EVENT_TYPE_WRITE	3
#define EVENT_TYPE_SEND_ZC	4
#define EVENT_TYPE_RECV		5
#define EVENT_TYPE_TIMEOUT	6




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

#endif /* _FLOWPERF_H_ */

/* flowperf.h */

#ifndef _FLOWPERF_H_
#define _FLOWPERF_H_


/* State machine of flowperf server handle per client connection */

#define SERVER_HANDLE_STATE_ACCEPTING	1
/* The initial state, waiting for a new client TCP connection by posting
 * an ACCEPT event.
 *
 * Assumed Completion Event:
 * - EVENT_TYPE_ACCEPT: Change state to ACCEPTED, and post EVENT_TYPE_READ.
 */

#define SERVER_HANDLE_STATE_ACCEPTED	2
/* Stable state. A client TCP connection is accpeted, and waiting for
 * an RPC request by posting a READ event.
 *
 * Assumed Completion Event:
 * - EVENT_TYPE_READ: Change the state to FLOWING or TCP_INFO accroing to
 *   the RPC request read from the socket.
 */

#define SERVER_HANDLE_STATE_FLOWING	3
/* Sending flow. Write data to the client socket until
 * start_flow->size bytes transferred.
 *
 * Assumed Completion Event:
 * - EVENT_TYPE_WRITE: Write date to the client socket until
 *   start_flow->size bytes transmitted.
 *
 * After the flow transferred, change the state to ACCEPTED or TCP_INFO.
 */

#define SERVER_HANDLE_STATE_TCP_INFO	4
/* Sending struct tcp_info of this client socket.
 * 
 * Assumed Completion Event:
 * - EVENT_TYPE_WRITE: Write tcp_info to the client socket.
 *
 * After the write event completed, change the state to ACCEPTED.
 */




/* State machine of flowperf client handle per connection */

#define CLIENT_HANDLE_STATE_CONNECTING	1
/* Initial state. The TCP connection is now connecting.
 *
 * Assumed Completion Event:
 * - EVENT_TYPE_CONNECT: connect() is done.
 *
 * After connect() successed, change the state to FLOWING by sending
 * REQ_TYPE_START_FLOW.
 */

#define CLIENT_HANDLE_STATE_FLOWING	2
/* Benchmarking, receving data from the socket.
 *
 * Assumed Completion Event:
 * - EVENT_TYPE_READ: read data until flow_start->size bytes received.
 *
 * After flow_start->size bytes received, change the state to TCP_INFO
 *  by sending TCP_INFO or to WAIT
 */
   
#define CLIENT_HANDLE_STATE_TCP_INFO	3
/* Receving struct tcp_info
 *
 * Assumed Completion Event:
 * - EVENT_TYPE_READ: read data until sizeof(struct tcp_info) bytes received.
 *
 * After struct tcp_info received, change the state to FLOWING as the next benchmark
 * or to WAIT.
 */

#define CLIENT_HANDLE_STATE_WAIT	4
/* Sleep a while as flow interval gap time.
 *
 * Assumed Compeltion Event:
 * - EVENT_TYPE_TIMEOUT: wait until the posted timeout.
 *
 * After TIMEOUT completion occurs, move to the next flow benchmark.
 */

#define EVENT_TYPE_ACCEPT	0
#define EVENT_TYPE_CONNECT	1
#define EVENT_TYPE_READ		2
#define EVENT_TYPE_WRITE	3
#define EVENT_TYPE_TIMEOUT	4




/* RPC message format */

enum {
        REQ_TYPE_NONE           = 0,

        REQ_TYPE_START_FLOW     = 1,

        REQ_TYPE_TCP_INFO       = 2,
        REP_TYPE_TCP_INFO       = 3,
};

struct rpchdr {
	/* header for an RPC request from client to server */
	uint8_t         type;
        uint16_t        len;
} __attribute__((__packed__));

struct rpc_start_flow {
	struct rpchdr	hdr;
        uint32_t        bytes;  /* flow size (bytes) */
};

struct rpc_tcp_info {
	struct rpchdr	hdr;
	/* no payload */
};



#endif /* _FLOWPERF_H_ */

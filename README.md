
# flowperf: flow-based network benchmark tool

`flowperf` is a tool for testing network performance from a *flow*
perspective. A *flow* is a sequence of bytes (message) transferred
from a source to a destination. `flowperf` generates flows and records
the time required to complete each flow (Flow Completion Time, or
FCT). Unlike other network performance tools that measure throughput
of bulk transfers, `flowperf` focuses on FCT and transactions per
second as key metrics.


```console
# Run flowperf server
$ flowperf -s

# Run flowperf client, send 5 flows of 1000 bytes
$ flowperf -c -d localhost -f 1000 -n 5
state=d dst=127.0.0.1:9999 flow_size=1000 remain=0 start=335687 end=708918 time2conn=159796 time2flow=213435 tcp_c=lost=0,sack=0,retr=0,sego=3,segi=2
state=d dst=127.0.0.1:9999 flow_size=1000 remain=0 start=708918 end=909920 time2conn=73761 time2flow=127241 tcp_c=lost=0,sack=0,retr=0,sego=3,segi=2
state=d dst=127.0.0.1:9999 flow_size=1000 remain=0 start=909920 end=1088621 time2conn=63414 time2flow=115287 tcp_c=lost=0,sack=0,retr=0,sego=3,segi=2
state=d dst=127.0.0.1:9999 flow_size=1000 remain=0 start=1088621 end=1262950 time2conn=59061 time2flow=115268 tcp_c=lost=0,sack=0,retr=0,sego=3,segi=2
state=d dst=127.0.0.1:9999 flow_size=1000 remain=0 start=1262950 end=1396132 time2conn=59843 time2flow=73339 tcp_c=lost=0,sack=0,retr=0,sego=3,segi=2
```

flowperf provides the following features:

* Generate flows of different sizes based on weights (flow size
  distribution). Additionally, `flowperf` includes five predefined
  distributions from
  [homa-paper-artifact](https://github.com/PlatformLab/homa-paper-artifact),
  covering:
  memcache access in Facebook, hadoop in Facebook, search application
  at Google, all workload in a Google data center, and web search with
  DCTCP.

* Distribute multiple flows among multiple `flowperf` servers
  concurrently according to specified probabilities.
  
* One flowperf process runs on a single thread but is high performance,
  thanks to [io_uring](https://kernel.dk/io_uring.pdf).



## Build and Install

`flowperf` uses io_uring, so it can only be built on Linux.

```console
sudo apt install liburing-dev

git clone git@github.com:upa/flowperf
cd flowperf

mkdir build && cd build
cmake ..
make

sudo make install
```

## `flowperf` Basics

`flowperf` is a server-client model application. First, start a
`flowperf` server process on your server machine using `flowperf -s`.
Then, initiate a benchmark by running a flowperf client process.

A *flow* in flowperf benchmarking consists of the following steps:

1. A client connects to a server to establish a TCP connection.
2. The client sends bytes.
3. The server responds with a single byte as an acknowledgment. 
4. Upon receiving the acknowledgment, the client terminates the flow
   and closes the TCP connection.

Several options change the behavior, for example:
* `-C`: Reuse TCP connections.
* `-T`: Retrieve TCP_INFO from the server instead of sending a one-byte acknowledgment.
* `-x`: Generate multiple flows concurrently.


Running a `flowperf` client requires two mandatory options: specifying
the destination (server) address and the flow size.

`-d` specifies a server address and its weight. For example, `-d 10.0.0.1`
sends flows to `10.0.0.1`. Multiple servers can be specified
using multiple `-d` options like `-d 10.0.0.1 -d 10.0.0.2`. In this
case, flows are distributed evenly between 10.0.0.1 and 10.0.0.2.
Weight can be assigned using the `@WEIGHT` suffix: `-d 10.0.0.1@1 -d 10.0.0.2@3`.

`-f` specifies the flow size, similar to the `-d` option.  `-f 1000`
generates 1000-byte flows, and `-f 1000@1 -f 20000@3` indicates that
flows of 1000 bytes and 20000 bytes are transmitted in a 1:3 ratio.


## Examples

* Generate 100B, 1000B, and 10000B flows with uniform probability
  sending them to both 10.0.0.1 and 10.0.0.2, using 16 concurrent TCP
  connections.

```console
$ flowperf -c -d 10.0.0.1 -d 10.0.0.2 -f 100 -f 1000 -f 10000 -x 16
```

* Generate flows following the size distribution of a workload in a
  Google data center.

```console
$ flowperf -c -d 10.0.0.1 -F google-all
```

`-F` option specifies a text file that contains flow size and weight
pairs, formatted as `FLOW_SIZE WEIGHT` per line. If the specified file
does not exist, `-F` option searches for it in
`/usr/local/share/flowperf/examples`. `make install` puts
`google-all`, `google-search`, `fb-hadoop`, `fb-memcache`, and `dctcp`
in this directory.

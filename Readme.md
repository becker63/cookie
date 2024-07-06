## Current state

The only thing implemented is a reconstruction of captured tcp packets for c.

Eventually we will move this code to a XDP based router like this: https://github.com/Nat-Lab/xdp-router. 

We can use the AF_XDP socktype to send packets from the kernel level to a user level program that would be doing all the same things this current program is doing.

For now I just want to use IPC service https://zeromq.org/languages/c/ to send the packets to a web app to display them.

## Problems

I am bottlenecked by two things.
1. I Need an internal representation of the predicted next seq number in order to perfectly allocate memory for these packets.
   * This requires an implementation of the tcp state machine
   * there are good examples in the source of wireshark and this cli app: https://github.com/simsong/tcpflow
3. Im trying to determine whether or not to use a thread map or a allocate a thread for every stream
   * I need to benchmark which is better
   * This is not a priority
```txt
Pseudocode 
t = allocatetcppacket(tcp);
h = chunkIntofullrecvHTTPpackets(t);
sendOverIPCtoWebserver(h);

┌─────────────────────────────────────────────────────────────────────┐
│                                Main thread                          │
│  ┌──────┬──────┬───────┬───────┬───────┐      ┌──────────────────┐  │
│  │      │      │       │       │       │      │ Main Thread      │  │
│  │Pkt 1 │Pkt 2 │ Pkt 3 │Pkt 4  │Pkt 5  ├─────►│ Process_packet() │  │
│  │      │      │       │       │       │      │                  │  │
│  └──────┴──────┴───────┴───────┴───────┘      └──────────┬───────┘  │
│                                                          │          │
│                                                          ▼          │
│                   ┌─────────────else──────────────newStream=true?   │
│                   │                                      │          │
│                   ▼                                      ▼          │
│              append()        map_set(key=pkt.src+pkt.dst+timestamp) │
│                                            │             │          │
│                   │                        │             └──────────┼─────────┐
│                   │                        │                        │         │
└───────────────────┼────────────────────────┼────────────────────────┘         │
                    │                        │                                  │
┌───────────────────┼────────────────────────┼─────────────────────────┐        │
│                   │         Shared hashmap │                         │        │
│  ┌────────────────┼─────────────┐  ┌───────┼──────────────────────┐  │        │
│  │                │             │  │       │                      │  │        │
│  │                ▼             │  │       ▼                      │  │        │
│  │  ┌──────┐ ┌──────┐           │  │  ┌──────┐                    │  │        │
│  │  │Pkt 1 │ │Pkt 2 │           │  │  │Pkt 1 │                    │  │        │
│  │  │      │ │      │           │  │  │      │                    │  │   pthread_create()
│  │  └──────┘ └──────┘           │  │  └──────┘                    │  │        │
│  │                              │  │                              │  │        │
│  └──────────────────────────────┘  └──────────────────────────────┘  │        │
│                  ▲                                                   │        │
└──────────────────┼───────────────────────────────────────────────────┘        │
                   │                                                            │
┌──────────────────┼──────────────┐  ┌──────────────────────────────────┐       │
│ Thread 1         │              │  │  Thread 2   (does same as 1)     │       │
│                  │              │  │                                  │◄──────┘
│                  ▼              │  └──────────────────────────────────┘
│  collect packets until full     │
│  http packet can be constructed │
│                  │              │
│                  │              │
│                  ▼              │
│     zmq_send(push, http_pkt)    │
│                  │              │
│                  │              │
│                  ▼              │
│     zmq_send(push, tcp_pkts)    │
│                  │              │
│                  │              │
│                  ▼              │
│     free_shared_memory()        │
│                                 │
└─────────────────────────────────┘

```

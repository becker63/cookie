For now the only thing implemented is a reconstruction of captured tcp packets for c.

Eventually we will move this code to a XDP based router like this: https://github.com/Nat-Lab/xdp-router. 

We can use the AF_XDP socktype to send packets from the kernel level to a user level program that would be doing all the same things this current program is doing.
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

package main

/*
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/netlink.h>

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
*/
import "C"

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"
	mnl "cgolmnl"
	nfct "cgolmnfct"
	"cgolmnl/inet"
)

// To make it map key - must be comperable
type LdIP [net.IPv6len]byte

func (addr LdIP) ToIP(family uint8) net.IP {
	switch family {
	case C.AF_INET:
		return net.IP(addr[:4])
	case C.AF_INET6:
		return net.IP(addr[:])
	}
	panic(fmt.Sprintf("unknown family: %d", family))
}

func NewLdIP(family uint8, p unsafe.Pointer) LdIP {
	var a LdIP
	switch family {
	case C.AF_INET:
		copy(a[:], (*(*[net.IPv4len]byte)(p))[:])
	case C.AF_INET6:
		copy(a[:], (*(*[net.IPv6len]byte)(p))[:])
	default:
		panic(fmt.Sprintf("unknown family: %d", family))
	}
	return a
}

type Tuple struct {
	Server, Client		LdIP
	L4proto, L3proto	uint8
	Port			uint16 // TYPE in ICMP - u8
}

func (t Tuple) String() string {
	var l4proto string
	switch t.L4proto {
	case C.IPPROTO_ICMP:	l4proto = fmt.Sprintf("ICMP(%d)", t.Port)
	case C.IPPROTO_TCP:	l4proto = fmt.Sprintf("TCP(%d)", inet.Ntohs(t.Port))
	case C.IPPROTO_UDP:	l4proto = fmt.Sprintf("UDP(%d)", inet.Ntohs(t.Port))
	case C.IPPROTO_DCCP:	l4proto = fmt.Sprintf("DCCP(%d)", inet.Ntohs(t.Port))
	case C.IPPROTO_SCTP:	l4proto = fmt.Sprintf("SCTP(%d)", inet.Ntohs(t.Port))
	case C.IPPROTO_UDPLITE:	l4proto = fmt.Sprintf("UDPLITE(%d)", inet.Ntohs(t.Port))
	default:		l4proto = fmt.Sprintf("unknown(%d)", t.L4proto)
	}
	
	return fmt.Sprintf("%s:%s << %s",
		t.Server.ToIP(t.L3proto), l4proto, t.Client.ToIP(t.L3proto))
}

type Counter struct {
	Pkts, Bytes		uint64
	Deleting		bool
}

var nstats = make(map[Tuple]*Counter)

func make_tuple(ct *nfct.Conntrack) (*Tuple, error) {
	t := &Tuple{}
	var err error

	t.L3proto, err = ct.AttrU8(nfct.ATTR_L3PROTO) // err might be ENODATA
	if err != nil {
		fmt.Fprintf(os.Stderr, "ignore - no ATTR_L3PROTO: %s\n", err)
		return nil, syscall.EPROTO
	}
	t.L4proto, err = ct.AttrU8(nfct.ATTR_L4PROTO)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ignore - no ATTR_L4PROTO: %s\n", err)
		return nil, syscall.EPROTO
	}

	var p unsafe.Pointer
	switch t.L3proto {
	case C.AF_INET:
		if p, err = ct.Attr(nfct.ATTR_IPV4_DST); err != nil { // AttrU32
			fmt.Fprintf(os.Stderr, "ignore - no ATTR_IPV4_DST: %s\n", err)
			return nil, err.(syscall.Errno)
		}
		t.Server = NewLdIP(t.L3proto, p)
		if p, err = ct.Attr(nfct.ATTR_IPV4_SRC); err != nil {
			fmt.Fprintf(os.Stderr, "ignore - no ATTR_IPV4_SRC: %s\n", err)
			return nil, err.(syscall.Errno)
		}
		t.Client = NewLdIP(t.L3proto, p)

	case C.AF_INET6:
		if p, err = ct.Attr(nfct.ATTR_IPV6_DST); err != nil {
			fmt.Fprintf(os.Stderr, "ignore - no ATTR_IPV6_DST: %s\n", err)
			return nil, err.(syscall.Errno)
		}
		t.Server = NewLdIP(t.L3proto, p)
		if p, err = ct.Attr(nfct.ATTR_IPV6_SRC); err != nil {
			fmt.Fprintf(os.Stderr, "ignore - no ATTR_IPV6_SRC: %s\n", err)
			return nil, err.(syscall.Errno)
		}
		t.Client = NewLdIP(t.L3proto, p)

	default:
		fmt.Fprintf(os.Stderr, "ignore unknown family: %d\n", t.L3proto)
		return nil, syscall.EPROTONOSUPPORT
	}

	switch t.L4proto {
	case C.IPPROTO_ICMP:
		if icmp_type, err := ct.AttrU8(nfct.ATTR_ICMP_TYPE); err != nil {
			fmt.Fprintf(os.Stderr, "ICMP TYPE - no ATTR_ICMP_TYPE: %s\n", err)
		} else {
			t.Port = uint16(icmp_type)
		}
	case C.IPPROTO_TCP: fallthrough
	case C.IPPROTO_UDP: fallthrough
	case C.IPPROTO_DCCP: fallthrough
	case C.IPPROTO_SCTP: fallthrough
	case C.IPPROTO_UDPLITE:
		if t.Port, err = ct.AttrU16(nfct.ATTR_PORT_DST); err != nil {
			fmt.Fprintf(os.Stderr, "DST PORT - no ATTR_PORT_DST: %s\n", err)
		}
	default:
		// fmt.Fprintf(os.Stderr, "no port, type - unknown protocol: %d\n", t.L4proto)
		t.Port = 0
	}

	return t, nil
}

func data_cb(nlh *mnl.Nlmsghdr, data interface{}) (int, syscall.Errno) {
	ct, err := nfct.ConntrackNew()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nfct_new: %s\n", err)
		return mnl.MNL_CB_ERROR, err.(syscall.Errno)
	}
	ct.NlmsgParse(nlh)
	defer ct.Destroy()

	// make_counter
	orig_packets, _ := ct.AttrU64(nfct.ATTR_ORIG_COUNTER_PACKETS)
	repl_packets, _ := ct.AttrU64(nfct.ATTR_REPL_COUNTER_PACKETS)
	orig_bytes, _ := ct.AttrU64(nfct.ATTR_ORIG_COUNTER_BYTES)
	repl_bytes, _ := ct.AttrU64(nfct.ATTR_REPL_COUNTER_BYTES)

	t, err := make_tuple(ct)
	if err != nil {
		// return mnl.MNL_CB_ERROR, err.(syscall.Errno)
		return mnl.MNL_CB_OK, 0
	}

	counter := nstats[*t]
	// NF_NETLINK_CONNTRACK_DESTROY / NFCT_T_DESTROY
	if nlh.Type & 0xFF == C.IPCTNL_MSG_CT_DELETE {
		counter.Deleting = true
	}
	
	if counter != nil {
		counter.Pkts = counter.Pkts + orig_packets + repl_packets
		counter.Bytes = counter.Bytes + orig_bytes + repl_bytes
	} else {
		counter = &Counter{orig_packets + repl_packets, orig_bytes + repl_bytes, false}
		nstats[*t] = counter
	}

	return mnl.MNL_CB_OK, 0
}

func handle(nl *mnl.Socket) int {
	buf := make([]byte, mnl.MNL_SOCKET_BUFFER_SIZE)

	nrcv, err := nl.Recvfrom(buf)
	if err != nil {
		// It only happens if NETLINK_NO_ENOBUFS is not set, it means
		// we are leaking statistics.
		if err == syscall.ENOBUFS {
			fmt.Fprintf(os.Stderr, "The daemon has hit ENOBUFS, you can " +
				"increase the size of your receiver " +
				"buffer to mitigate this or enable " +
				"reliable delivery.\n")
		} else {
			fmt.Fprintf(os.Stderr, "mnl_socket_recvfrom: %s\n", err)
		}
		return -1
	}

	if ret, err := mnl.CbRun(buf[:nrcv], 0, 0, data_cb, nil); ret <= mnl.MNL_CB_ERROR {
		fmt.Fprintf(os.Stderr, "mnl_cb_run: %s", err)
		return -1
	} else if ret <= mnl.MNL_CB_STOP {
		return 0
	}

	return 0
}

func show_nstats() {
	for k, v := range nstats {
		if v.Deleting {
			delete(nstats, k)
		}
		if v.Pkts == 0 {
			continue
		}
		fmt.Printf("%s\t(%d, %d)\n", k, v.Pkts, v.Bytes)
		v.Pkts = 0
		v.Bytes = 0
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <poll-secs>\n", os.Args[0])
		os.Exit(C.EXIT_FAILURE)
	}
	secs, _ := strconv.Atoi(os.Args[1])

	fmt.Printf("Polling every %d seconds from kernel...\n", secs)

	// Set high priority for this process, less chances to overrun
	// the netlink receiver buffer since the scheduler gives this process
	// more chances to run.
	C.nice(C.int(-20))

	// Open netlink socket to operate with netfilter
	nl, err := mnl.SocketOpen(C.NETLINK_NETFILTER)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mnl_socket_open: %s\n", err)
		os.Exit(C.EXIT_FAILURE)
	}

	// Subscribe to destroy events to avoid leaking counters. The same
	// socket is used to periodically atomically dump and reset counters.
	if err := nl.Bind(C.NF_NETLINK_CONNTRACK_DESTROY, mnl.MNL_SOCKET_AUTOPID); err != nil {
		fmt.Fprintf(os.Stderr, "mnl_socket_bind: %s\n", err)
		os.Exit(C.EXIT_FAILURE)
	}

	// Set netlink receiver buffer to 16 MBytes, to avoid packet drops */
	buffersize := (1 << 22)
	C.setsockopt(C.int(nl.Fd()), C.SOL_SOCKET, C.SO_RCVBUFFORCE,
		unsafe.Pointer(&buffersize), SizeofSocklen_t)

	// The two tweaks below enable reliable event delivery, packets may
	// be dropped if the netlink receiver buffer overruns. This happens ...
	//
	// a) if the kernel spams this user-space process until the receiver
	//    is filled.
	//
	// or:
	//
	// b) if the user-space process does not pull messages from the
	//    receiver buffer so often.
	nl.SetsockoptCint(C.NETLINK_BROADCAST_ERROR, 1)
	nl.SetsockoptCint(C.NETLINK_NO_ENOBUFS, 1)

	buf := make([]byte, mnl.MNL_SOCKET_BUFFER_SIZE)
	nlh, _ := mnl.NlmsgPutHeaderBytes(buf)
	// Counters are atomically zeroed in each dump
	nlh.Type = (C.NFNL_SUBSYS_CTNETLINK << 8) | C.IPCTNL_MSG_CT_GET_CTRZERO
	nlh.Flags = C.NLM_F_REQUEST | C.NLM_F_DUMP

	nfh := (*Nfgenmsg)(nlh.PutExtraHeader(SizeofNfgenmsg))
	nfh.Nfgen_family = C.AF_INET
	nfh.Version = C.NFNETLINK_V0
	nfh.Res_id = 0

	// Filter by mark: We only want to dump entries whose mark is zero
	nlh.PutU32(C.CTA_MARK, inet.Htonl(0))
	nlh.PutU32(C.CTA_MARK_MASK, inet.Htonl(0xffffffff))

	// prepare for epoll
	epfd, err := syscall.EpollCreate1(0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "EpollCreate1: %s", err)
		os.Exit(C.EXIT_FAILURE)
	}
	defer syscall.Close(epfd)

	var event syscall.EpollEvent
	events := make([]syscall.EpollEvent, 64)
	event.Events = syscall.EPOLLIN
	event.Fd = int32(nl.Fd())
	if err := syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, int(event.Fd), &event); err != nil {
		fmt.Fprintf(os.Stderr, "EpollCtl: %s", err)
		os.Exit(C.EXIT_FAILURE)
	}

	// Every N seconds ...
	ticker := time.NewTicker(time.Second * time.Duration(secs))
	go func() {
		for _ = range ticker.C {
			if _, err := nl.SendNlmsg(nlh);  err != nil {
				fmt.Fprintf(os.Stderr, "mnl_socket_sendto: %s\n", err)
				os.Exit(C.EXIT_FAILURE)
			}
		}
	}()

	for true {
		nevents, err := syscall.EpollWait(epfd, events, -1)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			fmt.Fprintf(os.Stderr, "EpollWait: %s\n", err)
			os.Exit(C.EXIT_FAILURE)
		}
		// Handled event and periodic atomic-dump-and-reset messages
		for i := 0; i < nevents; i++ {
			if events[i].Fd == event.Fd {
				if ret := handle(nl); ret < 0 {
					fmt.Fprintf(os.Stderr, "handle failed: %d\n", ret)
					os.Exit(C.EXIT_FAILURE)
				}
				// print the content of the list
				show_nstats()
			}
		}
	}		
}

package main

/*
#include <stdlib.h>
#include <arpa/inet.h>

#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
*/
import "C"

import (
	"fmt"
	nfct "github.com/chamaken/cgolmnfct"
	mnl "github.com/chamaken/cgolmnl"
	"os"
	"strconv"
	"syscall"
	"time"
)

type callbackArgs struct {
	nl  *mnl.Socket
	seq uint32
	bit int
}

func set_label(ct *nfct.Conntrack, cbargs *callbackArgs) {
	buf := make([]byte, mnl.MNL_SOCKET_BUFFER_SIZE)
	p, _ := ct.Attr(nfct.ATTR_CONNLABELS)
	b := (*nfct.Bitmask)(p)
	bit := cbargs.bit

	if b != nil {
		if bit < 0 {
			b, _ = nfct.NewBitmask(0)
		} else if b.TestBit(uint(bit)) == 1 {
			return
		}
	} else {
		b, _ = nfct.NewBitmask(0)
	}

	if b == nil {
		return
	}
	if bit >= 0 {
		b.SetBit(uint(bit))
	}
	ct.SetAttrPtr(nfct.ATTR_CONNLABELS, b)

	if bit >= 0 {
		b, _ = nfct.NewBitmask(uint(bit))
		if b != nil {
			b.SetBit(uint(bit))
			ct.SetAttrPtr(nfct.ATTR_CONNLABELS_MASK, b)
		}
	}

	cbargs.seq++

	nlh, _ := mnl.NlmsgPutHeaderBytes(buf)
	nlh.Type = (C.NFNL_SUBSYS_CTNETLINK << 8) | C.IPCTNL_MSG_CT_NEW
	nlh.Flags = C.NLM_F_REQUEST | C.NLM_F_CREATE
	nlh.Seq = cbargs.seq

	nfh := (*Nfgenmsg)(nlh.PutExtraHeader(SizeofNfgenmsg))
	nfh.Nfgen_family, _ = ct.AttrU8(nfct.ATTR_L3PROTO)
	nfh.Version = C.NFNETLINK_V0
	nfh.Res_id = 0

	ct.NlmsgBuild(nlh)

	if ret, err := cbargs.nl.SendNlmsg(nlh); ret < 0 {
		fmt.Fprintf(os.Stderr, "mnl_socket_sendto: %s\n", err)
	}
}

func data_cb(nlh *mnl.Nlmsghdr, data interface{}) (int, syscall.Errno) {
	buf := make([]byte, 4096)
	ct, err := nfct.NewConntrack()
	if err != nil {
		return mnl.MNL_CB_OK, 0
	}

	ct.NlmsgParse(nlh)
	ct.Snprintf(buf, nfct.NFCT_T_UNKNOWN, nfct.NFCT_O_DEFAULT, 0)
	fmt.Printf("%s\n", buf)

	set_label(ct, data.(*callbackArgs))

	ct.Destroy()

	return mnl.MNL_CB_OK, 0
}

func show_labels(l *nfct.Labelmap) {
	var name string
	var i uint
	if l != nil {
		fmt.Println("usage: program label, configured labes are:")
		for name = l.Name(i); name != ""; i++ {
			if len(name) > 0 {
				fmt.Fprintf(os.Stderr, "%s -> bit %d\n", name, i)
			}
		}
	} else {
		fmt.Fprint(os.Stderr, "no labels configure, usage program bit")
	}
}

func sock_nl_create() *mnl.Socket {
	nl, err := mnl.NewSocket(C.NETLINK_NETFILTER)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mnl_socket_open: %s\n", err)
		os.Exit(C.EXIT_FAILURE)
	}

	if err := nl.Bind(0, mnl.MNL_SOCKET_AUTOPID); err != nil {
		fmt.Fprintf(os.Stderr, "mnl_socket_bind: %s\n", err)
		os.Exit(C.EXIT_FAILURE)
	}

	return nl
}

func main() {
	buf := make([]byte, mnl.MNL_SOCKET_BUFFER_SIZE)
	l, err := nfct.NewLabelmap("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "nfct_labelmap_new: %s\n", err)
		os.Exit(C.EXIT_FAILURE)
	}
	defer l.Destroy()

	if len(os.Args) < 2 {
		show_labels(l)
	}

	cbargs := &callbackArgs{}
	if l != nil {
		cbargs.bit = l.Bit(os.Args[1])
	} else {
		cbargs.bit = -1
	}

	if cbargs.bit < 0 {
		cbargs.bit, _ = strconv.Atoi(os.Args[1])
		if cbargs.bit == 0 && os.Args[1][0] != '0' {
			show_labels(l)
		}
	}

	if cbargs.bit < 0 {
		fmt.Println("will clear all labels")
	} else {
		fmt.Printf("will set label bit %d\n", cbargs.bit)
	}

	nl := sock_nl_create()
	portid := nl.Portid()

	nlh, _ := mnl.NlmsgPutHeaderBytes(buf)
	nlh.Type = (C.NFNL_SUBSYS_CTNETLINK << 8) | C.IPCTNL_MSG_CT_GET
	nlh.Flags = C.NLM_F_REQUEST | C.NLM_F_DUMP
	seq := uint32(time.Now().Unix())
	nlh.Seq = seq

	nfh := (*Nfgenmsg)(nlh.PutExtraHeader(SizeofNfgenmsg))
	nfh.Nfgen_family = C.AF_UNSPEC
	nfh.Version = C.NFNETLINK_V0
	nfh.Res_id = 0

	if _, err := nl.SendNlmsg(nlh); err != nil {
		fmt.Fprintf(os.Stderr, "mnl_socket_sendto: %s\n", err)
		os.Exit(C.EXIT_FAILURE)
	}

	cbargs.nl = sock_nl_create()
	cbargs.seq = seq

	ret := mnl.MNL_CB_OK
	for ret > 0 {
		nrecv, err := nl.Recvfrom(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mnl_socket_recvfrom: %s\n", err)
			os.Exit(C.EXIT_FAILURE)
		}
		if ret, err = mnl.CbRun(buf[:nrecv], seq, portid, data_cb, &cbargs); ret < 0 {
			fmt.Fprintf(os.Stderr, "mnl_cb_run: %s\n", err)
			os.Exit(C.EXIT_FAILURE)
		}
	}
	cbargs.nl.Close()
	nl.Close()
}

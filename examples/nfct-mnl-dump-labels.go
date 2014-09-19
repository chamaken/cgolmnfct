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
	"syscall"
	"time"
)

func print_label(ct *nfct.Conntrack, labelmap *nfct.Labelmap) {
	p, err := ct.Attr(nfct.ATTR_CONNLABELS)
	if err != nil {
		return
	}
	b := (*nfct.Bitmask)(p)

	fmt.Print("labels:")
	max := b.Maxbit()
	var i uint
	for i = 0; i <= max; i++ {
		if b.TestBit(i) != 0 {
			label := ""
			if labelmap != nil {
				label = labelmap.Name(i)
			}
			fmt.Printf("\t'%s' (%d)\n", label, i)
		}
	}
}

func data_cb(nlh *mnl.Nlmsghdr, data interface{}) (int, syscall.Errno) {
	buf := make([]byte, mnl.MNL_SOCKET_BUFFER_SIZE)
	ct, err := nfct.NewConntrack()
	if err != nil {
		return mnl.MNL_CB_OK, 0
	}
	ct.NlmsgParse(nlh)
	ct.Snprintf(buf, nfct.NFCT_T_UNKNOWN, nfct.NFCT_O_DEFAULT, 0)
	fmt.Printf("%s\n", buf)

	print_label(ct, data.(*nfct.Labelmap))

	ct.Destroy()

	return mnl.MNL_CB_OK, 0
}

func main() {
	buf := make([]byte, mnl.MNL_SOCKET_BUFFER_SIZE)
	l, err := nfct.NewLabelmap("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "nfct_labelmap_new: %s\n", err)
		os.Exit(C.EXIT_FAILURE)
	}
	defer l.Destroy()

	nl, err := mnl.NewSocket(C.NETLINK_NETFILTER)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mnl_socket_open: %s\n", err)
		os.Exit(C.EXIT_FAILURE)
	}
	defer nl.Close()

	if err = nl.Bind(0, mnl.MNL_SOCKET_AUTOPID); err != nil {
		fmt.Fprintf(os.Stderr, "mnl_socket_bind: %s\n", err)
		os.Exit(C.EXIT_FAILURE)
	}
	portid := nl.Portid()

	nlh, _ := mnl.NlmsgPutHeaderBytes(buf)
	nlh.Type = (C.NFNL_SUBSYS_CTNETLINK << 8) | C.IPCTNL_MSG_CT_GET
	nlh.Flags = C.NLM_F_REQUEST | C.NLM_F_DUMP
	seq := uint32(time.Now().Unix())
	nlh.Seq = seq

	nfh := (*Nfgenmsg)(nlh.PutExtraHeader(SizeofNfgenmsg))
	nfh.Nfgen_family = C.AF_INET
	nfh.Version = C.NFNETLINK_V0
	nfh.Res_id = 0

	if _, err := nl.SendNlmsg(nlh); err != nil {
		fmt.Fprintf(os.Stderr, "mnl_socket_sendto: %s\n", err)
		os.Exit(C.EXIT_FAILURE)
	}

	ret := mnl.MNL_CB_OK
	for ret > 0 {
		nrecv, err := nl.Recvfrom(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mnl_socket_recvfrom: %s\n", err)
			os.Exit(C.EXIT_FAILURE)
		}
		if ret, err = mnl.CbRun(buf[:nrecv], seq, portid, data_cb, l); ret < 0 {
			fmt.Fprintf(os.Stderr, "mnl_cb_run: %s\n", err)
			os.Exit(C.EXIT_FAILURE)
		}
	}
}

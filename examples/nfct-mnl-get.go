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
	"os"
	"time"
	"syscall"
	mnl "cgolmnl"
	. "cgolmnl/inet"
	nfct "cgolmnfct"
)

func data_cb(nlh *mnl.Nlmsghdr, data interface{}) (int, syscall.Errno) {
	buf := make([]byte, 4096)
	ct, err := nfct.ConntrackNew()
	if err != nil {
		return mnl.MNL_CB_OK, 0
	}

	ct.NlmsgParse(nlh)

	ct.Snprintf(buf, nfct.NFCT_T_UNKNOWN, nfct.NFCT_O_DEFAULT, 0)
	fmt.Printf("%s\n", buf)

	ct.Destroy()

	return mnl.MNL_CB_OK, 0
}

func main() {
	buf := make([]byte, mnl.MNL_SOCKET_BUFFER_SIZE)

	nl, err := mnl.SocketOpen(C.NETLINK_NETFILTER)
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
	nlh.Flags = C.NLM_F_REQUEST|C.NLM_F_ACK
	seq := uint32(time.Now().Unix())
	nlh.Seq = seq

	nfh := (*Nfgenmsg)(nlh.PutExtraHeader(SizeofNfgenmsg))
	nfh.Nfgen_family = C.AF_INET
	nfh.Version = C.NFNETLINK_V0
	nfh.Res_id = 0

	ct, err := nfct.ConntrackNew()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nfct_new: %s\n", err)
		os.Exit(C.EXIT_FAILURE)
	}

	ct.SetAttrU8(nfct.ATTR_L3PROTO, C.AF_INET)
	ct.SetAttrU32(nfct.ATTR_IPV4_SRC, InetAddr("1.1.1.1"))
	ct.SetAttrU32(nfct.ATTR_IPV4_DST, InetAddr("2.2.2.2"))

	ct.SetAttrU8(nfct.ATTR_L4PROTO, C.IPPROTO_TCP)
	ct.SetAttrU16(nfct.ATTR_PORT_SRC, Htons(20))
	ct.SetAttrU16(nfct.ATTR_PORT_DST, Htons(10))

	ct.NlmsgBuild(nlh)

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
		if ret, err = mnl.CbRun(buf[:nrecv], seq, portid, data_cb, nil); ret < 0 {
			fmt.Fprintf(os.Stderr, "mnl_cb_run: %s\n", err)
			os.Exit(C.EXIT_FAILURE)
		}
	}
}

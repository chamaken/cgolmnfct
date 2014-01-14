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
	nfct "cgolmnfct"
)

func data_cb(nlh *mnl.Nlmsghdr, data interface{}) (int, syscall.Errno) {
	msg_type := nfct.NFCT_T_UNKNOWN
	buf := make([]byte, 4096)

	exp, err := nfct.ExpectNew()
	if err != nil {
		return mnl.MNL_CB_OK, 0
	}

	if ret, err := exp.NlmsgParse(nlh); ret < 0 {
		fmt.Fprintf(os.Stderr, "failed to parse message from kernel: %s\n", err)
		return mnl.MNL_CB_ERROR, err.(syscall.Errno)
	}

	exp.Snprintf(buf, msg_type, nfct.NFCT_O_DEFAULT, 0)
	fmt.Printf("%s\n", buf)

	exp.Destroy()

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
	nlh.Type = (C.NFNL_SUBSYS_CTNETLINK_EXP << 8) | C.IPCTNL_MSG_EXP_GET
	nlh.Flags = C.NLM_F_REQUEST|C.NLM_F_DUMP|C.NLM_F_ACK
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
		if ret, err = mnl.CbRun(buf[:nrecv], seq, portid, data_cb, nil); ret < 0 {
			fmt.Fprintf(os.Stderr, "mnl_cb_run: %s\n", err)
			os.Exit(C.EXIT_FAILURE)
		}
	}
}

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
)

func data_cb(nlh *mnl.Nlmsghdr, data interface{}) (int, syscall.Errno) {
	var msg_type nfct.ConntrackMsgType
	buf := make([]byte, 4096)

	switch nlh.Type & 0xFF {
	case C.IPCTNL_MSG_CT_NEW:
		if nlh.Flags&(C.NLM_F_CREATE|C.NLM_F_EXCL) != 0 {
			msg_type = nfct.NFCT_T_NEW
		} else {
			msg_type = nfct.NFCT_T_UPDATE
		}
	case C.IPCTNL_MSG_CT_DELETE:
		msg_type = nfct.NFCT_T_DESTROY
	}

	ct, err := nfct.NewConntrack()
	if err != nil {
		return mnl.MNL_CB_OK, 0
	}
	ct.NlmsgParse(nlh)

	ct.Snprintf(buf, msg_type, nfct.NFCT_O_DEFAULT, 0)

	fmt.Printf("%s\n", buf)

	ct.Destroy()

	return mnl.MNL_CB_OK, 0
}

func main() {
	buf := make([]byte, mnl.MNL_SOCKET_BUFFER_SIZE)

	nl, err := mnl.NewSocket(C.NETLINK_NETFILTER)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mnl_socket_open: %s\n", err)
		os.Exit(C.EXIT_FAILURE)
	}
	defer nl.Close()

	if err = nl.Bind(C.NF_NETLINK_CONNTRACK_NEW|
		C.NF_NETLINK_CONNTRACK_UPDATE|
		C.NF_NETLINK_CONNTRACK_DESTROY,
		mnl.MNL_SOCKET_AUTOPID); err != nil {
		fmt.Fprintf(os.Stderr, "mnl_socket_bind: %s\n", err)
		os.Exit(C.EXIT_FAILURE)
	}

	ret := mnl.MNL_CB_OK
	for ret > 0 {
		nrecv, err := nl.Recvfrom(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mnl_socket_recvfrom: %s\n", err)
			os.Exit(C.EXIT_FAILURE)
		}
		if ret, err = mnl.CbRun(buf[:nrecv], 0, 0, data_cb, nil); ret < 0 {
			fmt.Fprintf(os.Stderr, "mnl_cb_run: %s\n", err)
			os.Exit(C.EXIT_FAILURE)
		}
	}
}

package testlib

/*
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
*/
import "C"

const (
	AF_INET               = C.AF_INET
	NFNETLINK_V0          = C.NFNETLINK_V0
	IPCTNL_MSG_CT_DELETE  = C.IPCTNL_MSG_CT_DELETE
	NFNL_SUBSYS_CTNETLINK = C.NFNL_SUBSYS_CTNETLINK
)

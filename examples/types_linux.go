// +build ignore
package main

/*
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netfilter/nfnetlink.h>
*/
import "C"

const SizeofNfgenmsg = C.sizeof_struct_nfgenmsg

type Nfgenmsg C.struct_nfgenmsg

// nfct-daemon
const SizeofSocklen_t = C.sizeof_socklen_t

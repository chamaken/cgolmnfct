// +build ignore
package main

/*
#include <linux/netfilter/nfnetlink.h>
*/
import "C"

const SizeofNfgenmsg	= C.sizeof_struct_nfgenmsg
type Nfgenmsg		C.struct_nfgenmsg
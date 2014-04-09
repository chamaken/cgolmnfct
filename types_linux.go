// +build ignore

package cgolmnfct

/*
#cgo CFLAGS: -I./include
#include <stdint.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
*/
import "C"

type (
	Size_t		C.size_t
	Ssize_t		C.ssize_t
)


// conntrack attribute groups
const SizeofAttrGrpIpv4	= C.sizeof_struct_nfct_attr_grp_ipv4
type AttrGrpIpv4	C.struct_nfct_attr_grp_ipv4

const SizeofAttrGrpIpv6	= C.sizeof_struct_nfct_attr_grp_ipv6
type AttrGrpIpv6	C.struct_nfct_attr_grp_ipv6

const SizeofAttrGrpPort	= C.sizeof_struct_nfct_attr_grp_port
type AttrGrpPort	C.struct_nfct_attr_grp_port

const SizeofAttrGrpIcmp	= C.sizeof_struct_nfct_attr_grp_icmp
type AttrGrpIcmp	C.struct_nfct_attr_grp_icmp

const SizeofAttrGrpCtrs	= C.sizeof_struct_nfct_attr_grp_ctrs
type AttrGrpCtrs	C.struct_nfct_attr_grp_ctrs

const SizeofAttrGrpAddr	= C.sizeof_union_nfct_attr_grp_addr
type AttrGrpAddr	C.union_nfct_attr_grp_addr


// event filtering
const SizeofFilterProto	= C.sizeof_struct_nfct_filter_proto
type FilterProto	C.struct_nfct_filter_proto

const SizeofFilterIpv4	= C.sizeof_struct_nfct_filter_ipv4
type FilterIpv4		C.struct_nfct_filter_ipv4

const SizeofFilterIpv6	= C.sizeof_struct_nfct_filter_ipv6
type FilterIpv6		C.struct_nfct_filter_ipv6

// Go wrapper of libnetfilter_conntrack using cgo
// 
// ---- Citing the original libnetfilter_conntrack
// 
// libnetfilter_conntrack is a userspace library providing a programming
// interface (API) to the in-kernel connection tracking state table. The
// library libnetfilter_conntrack has been previously known as
// libnfnetlink_conntrack and libctnetlink. This library is currently used by
// conntrack-tools among many other applications.
// 
// libnetfilter_conntrack homepage is:
//      http://netfilter.org/projects/libnetfilter_conntrack/
// 
// Dependencies
//   libnetfilter_conntrack requires libnfnetlink and a kernel that includes the
//   nf_conntrack_netlink subsystem (i.e. 2.6.14 or later, >= 2.6.18 recommended).
// 
// Main Features
//  - listing/retrieving entries from the kernel connection tracking table.
//  - inserting/modifying/deleting entries from the kernel connection tracking
//    table.
//  - listing/retrieving entries from the kernel expect table.
//  - inserting/modifying/deleting entries from the kernel expect table.
// 
// Git Tree
//   The current development version of libnetfilter_conntrack can be accessed at
//   https://git.netfilter.org/cgi-bin/gitweb.cgi?p=libnetfilter_conntrack.git
// 
// Privileges
//   You need the CAP_NET_ADMIN capability in order to allow your application
//   to receive events from and to send commands to kernel-space, excepting
//   the conntrack table dumping operation.
// 
// Using libnetfilter_conntrack
//   To write your own program using libnetfilter_conntrack, you should start by
//   reading the doxygen documentation (start by \link LibrarySetup \endlink page)
//   and check examples available under utils/ in the libnetfilter_conntrack
//   source code tree. You can compile these examples by invoking `make check'.
// 
// Authors
//   libnetfilter_conntrack has been almost entirely written by Pablo Neira Ayuso.
// 
// Python Binding
//   pynetfilter_conntrack is a Python binding of libnetfilter_conntrack written
//   by Victor Stinner. You can visit his official web site at
//   http://software.inl.fr/trac/trac.cgi/wiki/pynetfilter_conntrack.

package cgolmnfct

/*
#cgo CFLAGS: -I./include
#cgo LDFLAGS: -lmnl
#include <libmnl/libmnl.h>
*/
import "C"
import (
	"unsafe"
	mnl "cgolmnl"
)

// allocate a new conntrack
//
// In case of success, this function returns a valid pointer to a memory blob,
// otherwise nil and error are returned.
func NewConntrack() (*Conntrack, error) {
	return conntrackNew()
}

// release a conntrack object
func (ct *Conntrack) Destroy() {
	conntrackDestroy(ct)
}

// clone a conntrack object
//
// On error, nil and error are returned. Otherwise,
// a valid pointer to the clone conntrack is returned.
func (ct *Conntrack) Clone() (*Conntrack, error) {
	return conntrackClone(ct)
}

// set a certain option for a conntrack object
func (ct *Conntrack) Setobjopt(option uint) error {
	return conntrackSetobjopt(ct, option)
}

// get a certain option for a conntrack object
//
// In case of error, -1 is returned and errno is appropiately set. On success,
// 1 is returned if option is set, otherwise 0 is returned.
func (ct *Conntrack) Objopt(option uint) (int, error) {
	return conntrackGetobjopt(ct, option)
}

// set the value of a certain conntrack attribute
func (ct *Conntrack) SetAttrL(attr_type ConntrackAttr, value unsafe.Pointer, size Size_t) error {
	return conntrackSetAttrL(ct, attr_type, value, size)
}

// set the value of a certain conntrack attribute
//
// This change value type to just pointer not unsafe by wrapping raw SetAttrL.
func (ct *Conntrack) SetAttrLPtr(attr_type ConntrackAttr, value interface{}) error {
	return conntrackSetAttrLPtr(ct, attr_type, value)
}

// set the value of a certain conntrack attribute
//
// Note that certain attributes are unsettable:
// 	- ATTR_USE
// 	- ATTR_ID
// 	- ATTR_*_COUNTER_*
//	- ATTR_SECCTX
//	- ATTR_TIMESTAMP_*
// The call of this function for such attributes do nothing.
func (ct *Conntrack) SetAttr(attr_type ConntrackAttr, value unsafe.Pointer) error {
	return conntrackSetAttr(ct, attr_type, value)
}

// set the value of a certain conntrack attribute
//
// This function change value type to just pointer not unsafe by wrapping raw SetAttr.
func (ct *Conntrack) SetAttrPtr(attr_type ConntrackAttr, value interface{}) error {
	return conntrackSetAttrPtr(ct, attr_type, value)
}

// set the value of a certain conntrack attribute
func (ct *Conntrack) SetAttrU8(attr_type ConntrackAttr, value uint8) error {
	return conntrackSetAttrU8(ct, attr_type, value)
}

// set the value of a certain conntrack attribute
func (ct *Conntrack) SetAttrU16(attr_type ConntrackAttr, value uint16) error {
	return conntrackSetAttrU16(ct, attr_type, value)
}

// set the value of a certain conntrack attribute
func (ct *Conntrack) SetAttrU32(attr_type ConntrackAttr, value uint32) error {
	return conntrackSetAttrU32(ct, attr_type, value)
}

// set the value of a certain conntrack attribute
func (ct *Conntrack) SetAttrU64(attr_type ConntrackAttr, value uint64) error {
	return conntrackSetAttrU64(ct, attr_type, value)
}

// get a conntrack attribute
//
// In case of success a valid pointer to the attribute requested is returned,
// on error nil is returned and errno is set appropiately.
func (ct *Conntrack) Attr(attr_type ConntrackAttr) (unsafe.Pointer, error) {
	return conntrackGetAttr(ct, attr_type)
}

// get attribute of unsigned 8-bits long
//
// Returns the value of the requested attribute, if the attribute is not 
// set, 0 is returned. In order to check if the attribute is set or not,
// use AttrIsSet.
func (ct *Conntrack) AttrU8(attr_type ConntrackAttr) (uint8, error) {
	return conntrackGetAttrU8(ct, attr_type)
}

// get attribute of unsigned 16-bits long
//
// Returns the value of the requested attribute, if the attribute is not 
// set, 0 is returned. In order to check if the attribute is set or not,
// use AttrIsSet.
func (ct *Conntrack) AttrU16(attr_type ConntrackAttr) (uint16, error) {
	return conntrackGetAttrU16(ct, attr_type)
}

// get attribute of unsigned 32-bits long
//
// Returns the value of the requested attribute, if the attribute is not 
// set, 0 is returned. In order to check if the attribute is set or not,
// use AttrIsSet.
func (ct *Conntrack) AttrU32(attr_type ConntrackAttr) (uint32, error) {
	return conntrackGetAttrU32(ct, attr_type)
}

// get attribute of unsigned 64-bits long
//
// Returns the value of the requested attribute, if the attribute is not 
// set, 0 is returned. In order to check if the attribute is set or not,
// use nfct_attr_is_set.
func (ct *Conntrack) AttrU64(attr_type ConntrackAttr) (uint64, error) {
	return conntrackGetAttrU64(ct, attr_type)
}

// check if a certain attribute is set
//
// On error, err is returned, otherwise
// true is returned if the attribute is set or false if not set.
func (ct *Conntrack) AttrIsSet(attr_type ConntrackAttr) (bool, error) {
	return conntrackAttrIsSet(ct, attr_type)
}

// check if an array of attribute types is set
//
// On error, err is returned, otherwise
// true is returned if the attribute is set or false if not set.
func (ct *Conntrack) AttrIsSetArray(type_array []ConntrackAttr) (bool, error) {
	return conntrackAttrIsSetArray(ct, type_array)
}

// unset a certain attribute
//
// On error, err is returned.
func (ct *Conntrack) AttrUnset(attr_type ConntrackAttr) error {
	return conntrackAttrUnset(ct, attr_type)
}

// set a group of attributes
//
// Note that calling this function for ATTR_GRP_COUNTER_* and ATTR_GRP_ADDR_*
// have no effect.
func (ct *Conntrack) SetAttrGrp(attr_type ConntrackAttrGrp, data unsafe.Pointer) error {
	return conntrackSetAttrGrp(ct, attr_type, data)
}

// set a group of attributes
//
// This function change value type to just pointer not unsafe by wrapping raw SetAttrGrp.
func (ct *Conntrack) SetAttrGrpPtr(attr_type ConntrackAttrGrp, data interface{}) error {
	return conntrackSetAttrGrpPtr(ct, attr_type, data)
}

// get an attribute group
//
// On error, it returns err. On success, the
// data pointer contains the attribute group.
func (ct *Conntrack) AttrGrp(attr_type ConntrackAttrGrp, data unsafe.Pointer) error {
	return conntrackGetAttrGrp(ct, attr_type, data)
}

// get an attribute group
//
// This function change value type to just pointer not unsafe by wrapping raw AttrGrp.
func (ct *Conntrack) AttrGrpPtr(attr_type ConntrackAttrGrp, data interface{}) error {
	return conntrackGetAttrGrpPtr(ct, attr_type, data)
}

// check if an attribute group is set
//
// If the attribute group is set, this function returns true, otherwise false.
// On error, it returns error.
func (ct *Conntrack) AttrGrpIsSet(attr_type ConntrackAttrGrp) (bool, error) {
	return conntrackAttrGrpIsSet(ct, attr_type)
}

// unset an attribute group
//
// On error, it returns error.
func (ct *Conntrack) AttrGrpUnset(attr_type ConntrackAttrGrp) error {
	return conntrackAttrGrpUnset(ct, attr_type)
}

// print a conntrack object to a buffer
//
// If you are listening to events, probably you want to display the message 
// type as well. In that case, set the message type parameter to any of the
// known existing types, ie. NFCT_T_NEW, NFCT_T_UPDATE, NFCT_T_DESTROY.
// If you pass NFCT_T_UNKNOWN, the message type will not be output. 
//
// Currently, the output available are:
// 	- NFCT_O_DEFAULT: default /proc-like output
// 	- NFCT_O_XML: XML output
//
// The output flags are:
// 	- NFCT_OF_SHOW_LAYER3: include layer 3 information in the output, 
// 	this is *only* required by NFCT_O_DEFAULT.
// 	- NFCT_OF_TIME: display current time.
// 	- NFCT_OF_ID: display the ID number.
// 	- NFCT_OF_TIMESTAMP: display creation and (if exists) deletion time.
//
// To use NFCT_OF_TIMESTAMP, you have to:
//
//    $ echo 1 > /proc/sys/net/netfilter/nf_conntrack_timestamp
//
// This requires a Linux kernel >= 2.6.38.
//
// Note that NFCT_OF_TIME displays the current time when nfct_snprintf() has
// been called. Thus, it can be used to know when a flow was destroy if you
// print the message just after you receive the destroy event. If you want
// more accurate timestamping, use NFCT_OF_TIMESTAMP.
//
// This function returns the size of the information that _would_ have been 
// written to the buffer, even if there was no room for it. Thus, the
// behaviour is similar to snprintf. On error, error is returned.
func (ct *Conntrack) Snprintf(buf []byte, msg_type ConntrackMsgType, out_type, flags uint) (int, error) {
	return conntrackSnprintf(buf, ct, msg_type, out_type, flags)
}

// print a bitmask object to a buffer including labels
//
// When map is nil, the function is equal to nfct_snprintf().
// Otherwise, if the conntrack object has a connlabel attribute, the active
// labels are translated using the label map and added to the buffer.
func (ct *Conntrack) SnprintfLabels(buf []byte, msg_type, out_type, flags uint, label_map *Labelmap) (int, error) {
	return conntrackSnprintfLabels(buf, ct, msg_type, out_type, flags, label_map)
}

// compare two conntrack objects
//
// This function only compare attribute set in both objects, by default 
// the comparison is not strict, ie. if a certain attribute is not set in one
// of the objects, then such attribute is not used in the comparison.
// If you want more strict comparisons, you can use the appropriate flags
// to modify this behaviour (see NFCT_CMP_STRICT and NFCT_CMP_MASK).
//
// The available flags are:
//
// 	- NFCT_CMP_STRICT: the compared objects must have the same attributes
// 	and the same values, otherwise it returns that the objects are 
// 	different.
// 	- NFCT_CMP_MASK: the first object is used as mask, this means that 
// 	if an attribute is present in ct1 but not in ct2, this function 
// 	returns that the objects are different.
// 	- NFCT_CMP_ALL: full comparison of both objects
// 	- NFCT_CMP_ORIG: it only compares the source and destination address;
// 	source and destination ports; the layer 3 and 4 protocol numbers
// 	of the original direction; and the id (if present).
// 	- NFCT_CMP_REPL: like NFCT_CMP_REPL but it compares the flow
// 	information that goes in the reply direction.
// 	- NFCT_CMP_TIMEOUT_EQ: timeout(ct1) == timeout(ct2)
// 	- NFCT_CMP_TIMEOUT_GT: timeout(ct1) > timeout(ct2)
// 	- NFCT_CMP_TIMEOUT_LT: timeout(ct1) < timeout(ct2)
// 	- NFCT_CMP_TIMEOUT_GE: timeout(ct1) >= timeout(ct2)
// 	- NFCT_CMP_TIMEOUT_LE: timeout(ct1) <= timeout(ct2)
//
// The status bits comparison is status(ct1) & status(ct2) == status(ct1).
//
// If both conntrack object are equal, this function returns 1, otherwise
// 0 is returned.
func (ct *Conntrack) Cmp(ct2 *Conntrack, flags uint) int {
	return conntrackCmp(ct, ct2, flags)
}

// copy part of one source object to another
//
// This function copies one part of the source object to the target.
// It behaves like clone but:
//
// 1) You have to pass an already allocated space for the target object
// 2) You can copy only a part of the source object to the target
//
// The current supported flags are:
// 	- NFCT_CP_ALL: that copies the object entirely.
// 	- NFCT_CP_ORIG and NFCT_CP_REPL: that can be used to copy the
// 	information that identifies a flow in the original and the reply
// 	direction. This information is usually composed of: source and
// 	destination IP address; source and destination ports; layer 3
// 	and 4 protocol number.
// 	- NFCT_CP_META: that copies the metainformation 
// 	(all the attributes >= ATTR_TCP_STATE)
//	- NFCT_CP_OVERRIDE: changes the default behaviour of nfct_copy() since
//	it overrides the destination object. After the copy, the destination
//	is a clone of the origin. This flag provides faster copying.
func (ct *Conntrack) Copy(dst *Conntrack, flags uint) {
	conntrackCopy(dst, ct, flags)
}

// copy an attribute of one source object to another
//
// This function copies one attribute (if present) to another object.
func (ct *Conntrack) CopyAttr(dst *Conntrack, attr_type ConntrackAttr) {
	conntrackCopyAttr(dst, ct, attr_type)
}

// create a filter
func NewFilter() (*Filter, error) {
	return filterCreate()
}

// destroy a filter
//
// This function releases the memory that is used by the filter object. 
// However, please note that this function does *not* detach an already
// attached filter.
func (filter *Filter) Destroy() {
	filterDestroy(filter)
}

// add a filter attribute of the filter object
//
// Limitations: You can add up to 127 IPv4 addresses and masks for 
// NFCT_FILTER_SRC_IPV4 and, similarly, 127 for NFCT_FILTER_DST_IPV4.
func (filter *Filter) AddAttr(attr_type FilterAttr, value unsafe.Pointer) error {
	return filterAddAttr(filter, attr_type, value)
}

// add an u32 filter attribute of the filter object
//
// Limitations: You can add up to 255 protocols which is a reasonable limit.
func (filter *Filter) AddAttrU32(attr FilterAttr, value uint32)	error {
	return filterAddAttrU32(filter, attr, value)
}

// set the filter logic for an attribute type
//
// You can only use this function once to set the filtering logic for 
// one attribute. You can define two logics: NFCT_FILTER_POSITIVE_LOGIC
// that accept events that match the filter, and NFCT_FILTER_NEGATIVE_LOGIC
// that rejects events that match the filter. Default filtering logic is
// NFCT_FILTER_POSITIVE_LOGIC.
func (filter *Filter) SetLogic(attr FilterAttr, logic FilterLogic) error {
	return filterSetLogic(filter, attr, logic)
}

// attach a filter to a socket descriptor
//
// If the function returns EINVAL probably you have found a bug in it.
// Please, report this.
func (filter *Filter) Attach(fd int) error {
	return filterAttach(fd, filter)
}

// create a dump filter
func NewFilterDump() (*FilterDump, error) {
	return filterDumpCreate()
}

// destroy a dump filter
//
// This function releases the memory that is used by the filter object.
func (filter_dump *FilterDump) Destroy() {
	filterDumpDestroy(filter_dump)
}

// set filter attribute
func (filter_dump *FilterDump) SetAttr(attr_type FilterDumpAttr, data unsafe.Pointer) error {
	return filterDumpSetAttr(filter_dump, attr_type, data)
}

// set filter attribute
//
// This function change value type to just pointer not unsafe by wrapping raw SetAttr.
func (filter_dump *FilterDump) SetAttrPtr(attr_type FilterDumpAttr, data interface{}) error {
	return filterDumpSetAttrPtr(filter_dump, attr_type, data)
}

// set u8 dump filter attribute
func (filter_dump *FilterDump) SetAttrU8(attr_type FilterDumpAttr, data uint8) error {
	return filterDumpSetAttrU8(filter_dump, attr_type, data)
}


// get name of the label bit
//
// returns a string of the name associated with the label.
// If no name has been configured, the empty string is returned.
// If bit is out of range, nil is returned.
func (m *Labelmap) Name(bit uint) string {
	return labelmapGetName(m, bit)
}

// get bit associated with the name
//
// returns the bit associated with the name, or negative value on error.
func (m *Labelmap) Bit(name string) int {
	return labelmapGetBit(m, name)
}

// create a new label map
//
// If mapfile is NULL, the default mapping file /etc/xtables/connlabel.conf
// is used.
func NewLabelmap(mapfile string) (*Labelmap, error) {
	return labelmapNew(mapfile)
}

// destroy nfct_labelmap object
//
// This function releases the memory that is used by the labelmap object.
func (m *Labelmap) Destroy() {
	labelmapDestroy(m)
}


// duplicate a bitmask object
//
// returns an identical copy of the bitmask.
func (b *Bitmask) Clone() (*Bitmask, error) {
	return bitmaskClone(b)
}

// set bit in the bitmask
func (b *Bitmask) SetBit(bit uint) {
	bitmaskSetBit(b, bit)
}

// test if a bit in the bitmask is set
//
// returns 0 if the bit is not set.
func (b *Bitmask) TestBit(bit uint) int {
	return bitmaskTestBit(b, bit)
}

// unset bit in the bitmask
func (b *Bitmask) UnsetBit(bit uint) {
	bitmaskUnsetBit(b, bit)
}

// return highest bit that may be set/unset
func (b *Bitmask) Maxbit() uint {
	return bitmaskMaxbit(b)
}

// allocate a new bitmask
//
// param max is valid bit that can be set/unset.
func NewBitmask(max uint) (*Bitmask, error) {
	return bitmaskNew(max)
}

// destroy bitmask object
//
// This function releases the memory that is used by the bitmask object.
//
// If you assign a bitmask object to a nf_conntrack object using
// nfct_set_attr ATTR_CONNLABEL, then the ownership of the bitmask
// object passes on to the nf_conntrack object. The nfct_bitmask object
// will be destroyed when the nf_conntrack object is destroyed.
func (b *Bitmask) Destroy() {
	bitmaskDestroy(b)
}


// build a netlink message from a conntrack object
func (ct *Conntrack) NlmsgBuild(nlh *mnl.Nlmsghdr) (int, error) {
	return conntrackNlmsgBuild(nlh, ct)
}

// translate a netlink message to a conntrack object
func (ct *Conntrack) NlmsgParse(nlh *mnl.Nlmsghdr) (int, error) {
	return conntrackNlmsgParse(nlh, ct)
}

// translate a netlink attribute payload to a conntrack object
func (ct *Conntrack) PayloadParse(payload unsafe.Pointer, payload_len Size_t, l3num uint16) (int, error) {
	return conntrackPayloadParse(payload, payload_len, l3num, ct)
}

// translate a netlink attribute payload to a conntrack object
//
// This function change payload type to []byte not unsafe by wrapping raw PayloadParse.
func (ct *Conntrack) PayloadParseBytes(payload []byte, l3num uint16) (int, error) {
	return conntrackPayloadParseBytes(payload, l3num, ct)
}

// allocate a new expectation
func NewExpect() (*Expect, error) {
	return expectNew()
}

// release an expectation object
func (exp *Expect) Destroy() {
	expectDestroy(exp)
}

// clone a expectation object
//
// On error, nil and error is returned. Otherwise,
// a valid pointer to the clone expect is returned.
func (exp *Expect) Clone() (*Expect, error) {
	return expectClone(exp)
}

// compare two expectation objects
//
// This function only compare attribute set in both objects, by default
// the comparison is not strict, ie. if a certain attribute is not set in one
// of the objects, then such attribute is not used in the comparison.
// If you want more strict comparisons, you can use the appropriate flags
// to modify this behaviour (see NFCT_CMP_STRICT and NFCT_CMP_MASK).
//
// The available flags are:
//      - NFCT_CMP_STRICT: the compared objects must have the same attributes
//      and the same values, otherwise it returns that the objects are
//      different.
//      - NFCT_CMP_MASK: the first object is used as mask, this means that
//      if an attribute is present in exp1 but not in exp2, this function
//      returns that the objects are different.
//
// Other existing flags that are used by nfct_cmp() are ignored.
//
// If both conntrack object are equal, this function returns 1, otherwise
// 0 is returned.
func (exp *Expect) Cmp(exp2 *Expect, flags int) int {
	return expectCmp(exp, exp2, flags)
}

// set the value of a certain expect attribute
//
// Note that certain attributes are unsettable:
// 	- ATTR_EXP_USE
// 	- ATTR_EXP_ID
// 	- ATTR_EXP_*_COUNTER_*
// The call of this function for such attributes do nothing.
func (exp *Expect) SetAttr(attr_type ExpectAttr, value unsafe.Pointer) error {
	return expectSetAttr(exp, attr_type, value)
}

// set the value of a certain expect attribute
//
// This function change value type to just pointer not unsafe by wrapping raw SetAttr.
func (exp *Expect) SetAttrPtr(attr_type ExpectAttr, value interface{}) error {
	return expectSetAttrPtr(exp, attr_type, value)
}

// set the value of a certain expect attribute
func (exp *Expect) SetAttrU8(attr_type ExpectAttr, value uint8) error {
	return expectSetAttrU8(exp, attr_type, value)
}

// set the value of a certain expect attribute
func (exp *Expect) SetAttrU16(attr_type ExpectAttr, value uint16) error {
	return expectSetAttrU16(exp, attr_type, value)
}

// set the value of a certain expect attribute
func (exp *Expect) SetAttrU32(attr_type ExpectAttr, value uint32) error {
	return expectSetAttrU32(exp, attr_type, value)
}

// get an expect attribute
//
// In case of success a valid pointer to the attribute requested is returned,
// on error nil and error are returned
func (exp *Expect) Attr(attr_type ExpectAttr) (unsafe.Pointer, error) {
	return expectGetAttr(exp, attr_type)
}

// get attribute of unsigned 8-bits long
//
// Returns the value of the requested attribute, if the attribute is not 
// set, 0 is returned. In order to check if the attribute is set or not,
// use AttrIsSet.
func (exp *Expect) AttrU8(attr_type ExpectAttr) (uint8, error) {
	return expectGetAttrU8(exp, attr_type)
}

// get attribute of unsigned 16-bits long
//
// Returns the value of the requested attribute, if the attribute is not 
// set, 0 is returned. In order to check if the attribute is set or not,
// use AttrIsSet.
func (exp *Expect) AttrU16(attr_type ExpectAttr) (uint16, error) {
	return expectGetAttrU16(exp, attr_type)
}

// get attribute of unsigned 32-bits long
//
// Returns the value of the requested attribute, if the attribute is not 
// set, 0 is returned. In order to check if the attribute is set or not,
// use AttrIsSet.
func (exp *Expect) AttrU32(attr_type ExpectAttr) (uint32, error) {
	return expectGetAttrU32(exp, attr_type)
}

// check if a certain attribute is set
//
// On error, error is returned, otherwise
// true is returned if the attribute is set or false if not set.
func (exp *Expect) AttrIsSet(attr_type ExpectAttr) (bool, error) {
	return expectAttrIsSet(exp, attr_type)
}

// unset a certain attribute
func (exp *Expect) AttrUnset(attr_type ExpectAttr) error {
	return expectAttrUnset(exp, attr_type)
}

// print a conntrack object to a buffer
//
// If you are listening to events, probably you want to display the message 
// type as well. In that case, set the message type parameter to any of the
// known existing types, ie. NFEXP_T_NEW, NFEXP_T_UPDATE, NFEXP_T_DESTROY.
// If you pass NFEXP_T_UNKNOWN, the message type will not be output. 
// 
// Currently, the output available are:
// 	- NFEXP_O_DEFAULT: default /proc-like output
// 	- NFEXP_O_XML: XML output
// 
// The output flags are:
// 	- NFEXP_O_LAYER: include layer 3 information in the output, this is
// 			*only* required by NFEXP_O_DEFAULT.
func (exp *Expect) Snprintf(buf []byte, msg_type ConntrackMsgType, out_type, flags uint) (int, error) {
	return expectSnprintf(buf, exp, msg_type, out_type, flags)
}

// build a netlink message from a conntrack object
func (exp *Expect) NlmsgBuild(nlh *mnl.Nlmsghdr) (int, error) {
	return expectNlmsgBuild(nlh, exp)
}

// translate a netlink message to a conntrack object
func (exp *Expect) NlmsgParse(nlh *mnl.Nlmsghdr) (int, error) {
	return expectNlmsgParse(nlh, exp)
}

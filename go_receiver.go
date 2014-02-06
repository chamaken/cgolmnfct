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
	// "errors"
	// "os"
)

/*
 * conntrack.go
 */

// Conntrack object handling
func (ct *Conntrack) Destroy()							{ ConntrackDestroy(ct) }
func (ct *Conntrack) Clone() (*Conntrack, error)				{ return ConntrackClone(ct)}
func (ct *Conntrack) Setobjopt(option uint) error				{ return ConntrackSetobjopt(ct, option) }
func (ct *Conntrack) Objopt(option uint) (int, error)				{ return ConntrackGetobjopt(ct, option) }
func (ct *Conntrack) SetAttrL(attr_type ConntrackAttr, value unsafe.Pointer, size Size_t) error	{ return ConntrackSetAttrL(ct, attr_type, value, size) }
func (ct *Conntrack) SetAttrLPtr(attr_type ConntrackAttr, value interface{}) error	{ return ConntrackSetAttrLPtr(ct, attr_type, value) }
func (ct *Conntrack) SetAttr(attr_type ConntrackAttr, value unsafe.Pointer) error	{ return ConntrackSetAttr(ct, attr_type, value) }
func (ct *Conntrack) SetAttrPtr(attr_type ConntrackAttr, value interface{}) error	{ return ConntrackSetAttrPtr(ct, attr_type, value) }
func (ct *Conntrack) SetAttrU8(attr_type ConntrackAttr, value uint8) error	{ return ConntrackSetAttrU8(ct, attr_type, value) }
func (ct *Conntrack) SetAttrU16(attr_type ConntrackAttr, value uint16) error	{ return ConntrackSetAttrU16(ct, attr_type, value) }
func (ct *Conntrack) SetAttrU32(attr_type ConntrackAttr, value uint32) error	{ return ConntrackSetAttrU32(ct, attr_type, value) }
func (ct *Conntrack) SetAttrU64(attr_type ConntrackAttr, value uint64) error	{ return ConntrackSetAttrU64(ct, attr_type, value) }
func (ct *Conntrack) Attr(attr_type ConntrackAttr) (unsafe.Pointer, error)	{ return ConntrackGetAttr(ct, attr_type) }
func (ct *Conntrack) AttrU8(attr_type ConntrackAttr) (uint8, error)		{ return ConntrackGetAttrU8(ct, attr_type) }
func (ct *Conntrack) AttrU16(attr_type ConntrackAttr) (uint16, error)	{ return ConntrackGetAttrU16(ct, attr_type) }
func (ct *Conntrack) AttrU32(attr_type ConntrackAttr) (uint32, error)	{ return ConntrackGetAttrU32(ct, attr_type) }
func (ct *Conntrack) AttrU64(attr_type ConntrackAttr) (uint64, error)	{ return ConntrackGetAttrU64(ct, attr_type) }
func (ct *Conntrack) AttrIsSet(attr_type ConntrackAttr) (bool, error)	{ return ConntrackAttrIsSet(ct, attr_type) }
func (ct *Conntrack) AttrIsSetArray(type_array []ConntrackAttr) (bool, error)	{ return ConntrackAttrIsSetArray(ct, type_array) }
func (ct *Conntrack) AttrUnset(attr_type ConntrackAttr) error		{ return ConntrackAttrUnset(ct, attr_type) }
func (ct *Conntrack) SetAttrGrp(attr_type ConntrackAttrGrp, data unsafe.Pointer) error	{ return ConntrackSetAttrGrp(ct, attr_type, data) }
func (ct *Conntrack) SetAttrGrpPtr(attr_type ConntrackAttrGrp, data interface{}) error	{ return ConntrackSetAttrGrpPtr(ct, attr_type, data) }
func (ct *Conntrack) AttrGrp(attr_type ConntrackAttrGrp, data unsafe.Pointer) error	{ return ConntrackGetAttrGrp(ct, attr_type, data) }
func (ct *Conntrack) AttrGrpPtr(attr_type ConntrackAttrGrp, data interface{}) error	{ return ConntrackGetAttrGrpPtr(ct, attr_type, data) }
func (ct *Conntrack) AttrGrpIsSet(attr_type ConntrackAttrGrp) (bool, error)	{ return ConntrackAttrGrpIsSet(ct, attr_type) }
func (ct *Conntrack) AttrGrpUnset(attr_type ConntrackAttrGrp) error	{ return ConntrackAttrGrpUnset(ct, attr_type) }
func (ct *Conntrack) Snprintf(buf []byte, msg_type ConntrackMsgType, out_type, flags uint) (int, error)	{ return ConntrackSnprintf(buf, ct, msg_type, out_type, flags) }
func (ct *Conntrack) SnprintfLabels(buf []byte, msg_type, out_type, flags uint, label_map *Labelmap) (int, error) { return ConntrackSnprintfLabels(buf, ct, msg_type, out_type, flags, label_map) }
func (ct *Conntrack) Cmp(ct2 *Conntrack, flags uint) int	{ return ConntrackCmp(ct, ct2, flags) }
func (ct *Conntrack) Copy(dst *Conntrack, flags uint)	{ ConntrackCopy(dst, ct, flags) }
func (ct *Conntrack) CopyAttr(dst *Conntrack, attr_type ConntrackAttr)	{ ConntrackCopyAttr(dst, ct, attr_type) }

// Kernel-space filtering for events
func (filter *Filter) Destroy()		{ FilterDestroy(filter) }
func (filter *Filter) AddAttr(attr_type FilterAttr, value unsafe.Pointer) error	{ return FilterAddAttr(filter, attr_type, value) }
func (filter *Filter) AddAttrU32(attr FilterAttr, value uint32)	error	{ return FilterAddAttrU32(filter, attr, value) }
func (filter *Filter) SetLogic(attr FilterAttr, logic FilterLogic) (int, error)	{ return FilterSetLogic(filter, attr, logic) }
func (filter *Filter) Attach(fd int) (int, error)	{ return FilterAttach(fd, filter) }

// dump filtering
func (filter_dump *FilterDump) Destroy()		{ FilterDumpDestroy(filter_dump) }
func (filter_dump *FilterDump) SetAttr(attr_type FilterDumpAttr, data unsafe.Pointer) error	{ return FilterDumpSetAttr(filter_dump, attr_type, data) }
func (filter_dump *FilterDump) SetAttrPtr(attr_type FilterDumpAttr, data interface{}) error	{ return FilterDumpSetAttrPtr(filter_dump, attr_type, data) }
func (filter_dump *FilterDump) SetAttrU8(attr_type FilterDumpAttr, data uint8) error	{ return FilterDumpSetAttrU8(filter_dump, attr_type, data) }

// Conntrack labels
func (m *Labelmap) Name(bit uint) string		{ return LabelmapGetName(m, bit) }
func (m *Labelmap) Bit(name string) int		{ return LabelmapGetBit(m, name) }
func (m *Labelmap) Destroy()			{ LabelmapDestroy(m) }

// bitmask object
func (b *Bitmask) Clone() (*Bitmask, error)	{ return BitmaskClone(b) }
func (b *Bitmask) SetBit(bit uint)			{ BitmaskSetBit(b, bit) }
func (b *Bitmask) TestBit(bit uint) int		{ return BitmaskTestBit(b, bit) }
func (b *Bitmask) UnsetBit(bit uint)		{ BitmaskUnsetBit(b, bit) }
func (b *Bitmask) Maxbit() uint			{ return BitmaskMaxbit(b) }
func (b *Bitmask) Destroy()				{ BitmaskDestroy(b) }

// New low level API: netlink functions
func (ct *Conntrack) NlmsgBuild(nlh *mnl.Nlmsghdr) (int, error)	{ return ConntrackNlmsgBuild(nlh, ct) }
func (ct *Conntrack) NlmsgParse(nlh *mnl.Nlmsghdr) (int, error)	{ return ConntrackNlmsgParse(nlh, ct) }
func (ct *Conntrack) PayloadParse(payload unsafe.Pointer, payload_len Size_t, l3num uint16) (int, error)	{ return ConntrackPayloadParse(payload, payload_len, l3num, ct) }
func (ct *Conntrack) PayloadParseBytes(payload []byte, l3num uint16) (int, error)	{ return ConntrackPayloadParseBytes(payload, l3num, ct) }

// expect.go
func (exp *Expect) Destroy()	{ ExpectDestroy(exp) }
func (exp *Expect) Clone() (*Expect, error)	{ return ExpectClone(exp) }
func (exp *Expect) Cmp(exp2 *Expect, flags int) int	{ return ExpectCmp(exp, exp2, flags) }
func (exp *Expect) SetAttr(attr_type ExpectAttr, value unsafe.Pointer) error	{ return ExpectSetAttr(exp, attr_type, value) }
func (exp *Expect) SetAttrPtr(attr_type ExpectAttr, value interface{}) error	{ return ExpectSetAttrPtr(exp, attr_type, value) }
func (exp *Expect) SetAttrU8(attr_type ExpectAttr, value uint8) error	{ return ExpectSetAttrU8(exp, attr_type, value) }
func (exp *Expect) SetAttrU16(attr_type ExpectAttr, value uint16) error	{ return ExpectSetAttrU16(exp, attr_type, value) }
func (exp *Expect) SetAttrU32(attr_type ExpectAttr, value uint32) error	{ return ExpectSetAttrU32(exp, attr_type, value) }
func (exp *Expect) Attr(attr_type ExpectAttr) (unsafe.Pointer, error)	{ return ExpectGetAttr(exp, attr_type) }
func (exp *Expect) AttrU8(attr_type ExpectAttr) (uint8, error)		{ return ExpectGetAttrU8(exp, attr_type) }
func (exp *Expect) AttrU16(attr_type ExpectAttr) (uint16, error)	{ return ExpectGetAttrU16(exp, attr_type) }
func (exp *Expect) AttrU32(attr_type ExpectAttr) (uint32, error)	{ return ExpectGetAttrU32(exp, attr_type) }
func (exp *Expect) AttrIsSet(attr_type ExpectAttr) (bool, error)	{ return ExpectAttrIsSet(exp, attr_type) }
func (exp *Expect) AttrUnset(attr_type ExpectAttr) (int, error)		{ return ExpectAttrUnset(exp, attr_type) }
func (exp *Expect) Snprintf(buf []byte, msg_type ConntrackMsgType, out_type, flags uint) (int, error) { return ExpectSnprintf(buf, exp, msg_type, out_type, flags) }
func (exp *Expect) NlmsgBuild(nlh *mnl.Nlmsghdr) (int, error)	{ return ExpectNlmsgBuild(nlh, exp) }
func (exp *Expect) NlmsgParse(nlh *mnl.Nlmsghdr) (int, error)	{ return ExpectNlmsgParse(nlh, exp) }

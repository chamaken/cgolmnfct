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

/*
 * conntrack.go
 */

func (ct *Conntrack) Destroy() {
	conntrackDestroy(ct)
}

func (ct *Conntrack) Clone() (*Conntrack, error) {
	return conntrackClone(ct)
}

func (ct *Conntrack) Setobjopt(option uint) error {
	return conntrackSetobjopt(ct, option)
}

func (ct *Conntrack) Objopt(option uint) (int, error) {
	return conntrackGetobjopt(ct, option)
}

func (ct *Conntrack) SetAttrL(attr_type ConntrackAttr, value unsafe.Pointer, size Size_t) error {
	return conntrackSetAttrL(ct, attr_type, value, size)
}

func (ct *Conntrack) SetAttrLPtr(attr_type ConntrackAttr, value interface{}) error {
	return conntrackSetAttrLPtr(ct, attr_type, value)
}

func (ct *Conntrack) SetAttr(attr_type ConntrackAttr, value unsafe.Pointer) error {
	return conntrackSetAttr(ct, attr_type, value)
}

func (ct *Conntrack) SetAttrPtr(attr_type ConntrackAttr, value interface{}) error {
	return conntrackSetAttrPtr(ct, attr_type, value)
}

func (ct *Conntrack) SetAttrU8(attr_type ConntrackAttr, value uint8) error {
	return conntrackSetAttrU8(ct, attr_type, value)
}

func (ct *Conntrack) SetAttrU16(attr_type ConntrackAttr, value uint16) error {
	return conntrackSetAttrU16(ct, attr_type, value)
}

func (ct *Conntrack) SetAttrU32(attr_type ConntrackAttr, value uint32) error {
	return conntrackSetAttrU32(ct, attr_type, value)
}

func (ct *Conntrack) SetAttrU64(attr_type ConntrackAttr, value uint64) error {
	return conntrackSetAttrU64(ct, attr_type, value)
}

func (ct *Conntrack) Attr(attr_type ConntrackAttr) (unsafe.Pointer, error) {
	return conntrackGetAttr(ct, attr_type)
}

func (ct *Conntrack) AttrU8(attr_type ConntrackAttr) (uint8, error) {
	return conntrackGetAttrU8(ct, attr_type)
}

func (ct *Conntrack) AttrU16(attr_type ConntrackAttr) (uint16, error) {
	return conntrackGetAttrU16(ct, attr_type)
}

func (ct *Conntrack) AttrU32(attr_type ConntrackAttr) (uint32, error) {
	return conntrackGetAttrU32(ct, attr_type)
}

func (ct *Conntrack) AttrU64(attr_type ConntrackAttr) (uint64, error) {
	return conntrackGetAttrU64(ct, attr_type)
}

func (ct *Conntrack) AttrIsSet(attr_type ConntrackAttr) (bool, error) {
	return conntrackAttrIsSet(ct, attr_type)
}

func (ct *Conntrack) AttrIsSetArray(type_array []ConntrackAttr) (bool, error) {
	return conntrackAttrIsSetArray(ct, type_array)
}

func (ct *Conntrack) AttrUnset(attr_type ConntrackAttr) error {
	return conntrackAttrUnset(ct, attr_type)
}

func (ct *Conntrack) SetAttrGrp(attr_type ConntrackAttrGrp, data unsafe.Pointer) error {
	return conntrackSetAttrGrp(ct, attr_type, data)
}

func (ct *Conntrack) SetAttrGrpPtr(attr_type ConntrackAttrGrp, data interface{}) error {
	return conntrackSetAttrGrpPtr(ct, attr_type, data)
}

func (ct *Conntrack) AttrGrp(attr_type ConntrackAttrGrp, data unsafe.Pointer) error {
	return conntrackGetAttrGrp(ct, attr_type, data)
}

func (ct *Conntrack) AttrGrpPtr(attr_type ConntrackAttrGrp, data interface{}) error {
	return conntrackGetAttrGrpPtr(ct, attr_type, data)
}

func (ct *Conntrack) AttrGrpIsSet(attr_type ConntrackAttrGrp) (bool, error) {
	return conntrackAttrGrpIsSet(ct, attr_type)
}

func (ct *Conntrack) AttrGrpUnset(attr_type ConntrackAttrGrp) error {
	return conntrackAttrGrpUnset(ct, attr_type)
}

func (ct *Conntrack) Snprintf(buf []byte, msg_type ConntrackMsgType, out_type, flags uint) (int, error) {
	return conntrackSnprintf(buf, ct, msg_type, out_type, flags)
}

func (ct *Conntrack) SnprintfLabels(buf []byte, msg_type, out_type, flags uint, label_map *Labelmap) (int, error) {
	return conntrackSnprintfLabels(buf, ct, msg_type, out_type, flags, label_map)
}

func (ct *Conntrack) Cmp(ct2 *Conntrack, flags uint) int {
	return conntrackCmp(ct, ct2, flags)
}

func (ct *Conntrack) Copy(dst *Conntrack, flags uint) {
	conntrackCopy(dst, ct, flags)
}

func (ct *Conntrack) CopyAttr(dst *Conntrack, attr_type ConntrackAttr) {
	conntrackCopyAttr(dst, ct, attr_type)
}


// Kernel-space filtering for events
func (filter *Filter) Destroy() {
	filterDestroy(filter)
}

func (filter *Filter) AddAttr(attr_type FilterAttr, value unsafe.Pointer) error {
	return filterAddAttr(filter, attr_type, value)
}

func (filter *Filter) AddAttrU32(attr FilterAttr, value uint32)	error {
	return filterAddAttrU32(filter, attr, value)
}

func (filter *Filter) SetLogic(attr FilterAttr, logic FilterLogic) (int, error) {
	return filterSetLogic(filter, attr, logic)
}

func (filter *Filter) Attach(fd int) (int, error) {
	return filterAttach(fd, filter)
}


// dump filtering
func (filter_dump *FilterDump) Destroy() {
	filterDumpDestroy(filter_dump)
}

func (filter_dump *FilterDump) SetAttr(attr_type FilterDumpAttr, data unsafe.Pointer) error {
	return filterDumpSetAttr(filter_dump, attr_type, data)
}

func (filter_dump *FilterDump) SetAttrPtr(attr_type FilterDumpAttr, data interface{}) error {
	return filterDumpSetAttrPtr(filter_dump, attr_type, data)
}

func (filter_dump *FilterDump) SetAttrU8(attr_type FilterDumpAttr, data uint8) error {
	return filterDumpSetAttrU8(filter_dump, attr_type, data)
}


// Conntrack labels
func (m *Labelmap) Name(bit uint) string {
	return labelmapGetName(m, bit)
}

func (m *Labelmap) Bit(name string) int {
	return labelmapGetBit(m, name)
}

func (m *Labelmap) Destroy() {
	labelmapDestroy(m)
}


// bitmask object
func (b *Bitmask) Clone() (*Bitmask, error) {
	return bitmaskClone(b)
}

func (b *Bitmask) SetBit(bit uint) {
	bitmaskSetBit(b, bit)
}

func (b *Bitmask) TestBit(bit uint) int {
	return bitmaskTestBit(b, bit)
}

func (b *Bitmask) UnsetBit(bit uint) {
	bitmaskUnsetBit(b, bit)
}

func (b *Bitmask) Maxbit() uint {
	return bitmaskMaxbit(b)
}

func (b *Bitmask) Destroy() {
	bitmaskDestroy(b)
}


// New low level API: netlink functions
func (ct *Conntrack) NlmsgBuild(nlh *mnl.Nlmsghdr) (int, error) {
	return conntrackNlmsgBuild(nlh, ct)
}

func (ct *Conntrack) NlmsgParse(nlh *mnl.Nlmsghdr) (int, error) {
	return conntrackNlmsgParse(nlh, ct)
}

func (ct *Conntrack) PayloadParse(payload unsafe.Pointer, payload_len Size_t, l3num uint16) (int, error) {
	return conntrackPayloadParse(payload, payload_len, l3num, ct)
}

func (ct *Conntrack) PayloadParseBytes(payload []byte, l3num uint16) (int, error) {
	return conntrackPayloadParseBytes(payload, l3num, ct)
}


// expect.go
func (exp *Expect) Destroy() {
	expectDestroy(exp)
}

func (exp *Expect) Clone() (*Expect, error) {
	return expectClone(exp)
}

func (exp *Expect) Cmp(exp2 *Expect, flags int) int {
	return expectCmp(exp, exp2, flags)
}

func (exp *Expect) SetAttr(attr_type ExpectAttr, value unsafe.Pointer) error {
	return expectSetAttr(exp, attr_type, value)
}

func (exp *Expect) SetAttrPtr(attr_type ExpectAttr, value interface{}) error {
	return expectSetAttrPtr(exp, attr_type, value)
}

func (exp *Expect) SetAttrU8(attr_type ExpectAttr, value uint8) error {
	return expectSetAttrU8(exp, attr_type, value)
}

func (exp *Expect) SetAttrU16(attr_type ExpectAttr, value uint16) error {
	return expectSetAttrU16(exp, attr_type, value)
}

func (exp *Expect) SetAttrU32(attr_type ExpectAttr, value uint32) error {
	return expectSetAttrU32(exp, attr_type, value)
}

func (exp *Expect) Attr(attr_type ExpectAttr) (unsafe.Pointer, error) {
	return expectGetAttr(exp, attr_type)
}

func (exp *Expect) AttrU8(attr_type ExpectAttr) (uint8, error) {
	return expectGetAttrU8(exp, attr_type)
}

func (exp *Expect) AttrU16(attr_type ExpectAttr) (uint16, error) {
	return expectGetAttrU16(exp, attr_type)
}

func (exp *Expect) AttrU32(attr_type ExpectAttr) (uint32, error) {
	return expectGetAttrU32(exp, attr_type)
}

func (exp *Expect) AttrIsSet(attr_type ExpectAttr) (bool, error) {
	return expectAttrIsSet(exp, attr_type)
}

func (exp *Expect) AttrUnset(attr_type ExpectAttr) error {
	return expectAttrUnset(exp, attr_type)
}

func (exp *Expect) Snprintf(buf []byte, msg_type ConntrackMsgType, out_type, flags uint) (int, error) {
	return expectSnprintf(buf, exp, msg_type, out_type, flags)
}

func (exp *Expect) NlmsgBuild(nlh *mnl.Nlmsghdr) (int, error) {
	return expectNlmsgBuild(nlh, exp)
}

func (exp *Expect) NlmsgParse(nlh *mnl.Nlmsghdr) (int, error) {
	return expectNlmsgParse(nlh, exp)
}

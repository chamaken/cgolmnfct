package cgolmnfct

import (
	mnl "github.com/chamaken/cgolmnl"
	"reflect"
	"syscall"
	"unsafe"
)

/*
#cgo CFLAGS: -I./include
#cgo LDFLAGS: -lnetfilter_conntrack
#include <stdlib.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
*/
import "C"

type Conntrack C.struct_nf_conntrack
type Bitmask C.struct_nfct_bitmask
type Labelmap C.struct_nfct_labelmap
type Filter C.struct_nfct_filter

// all represented [0]byte

// struct nf_conntrack *nfct_new(void)
func conntrackNew() (*Conntrack, error) {
	ret, err := C.nfct_new()
	return (*Conntrack)(ret), err
}

// void nfct_destroy(struct nf_conntrack *ct)
func conntrackDestroy(ct *Conntrack) {
	C.nfct_destroy((*C.struct_nf_conntrack)(ct))
}

// struct nf_conntrack *nfct_clone(const struct nf_conntrack *ct)
func conntrackClone(ct *Conntrack) (*Conntrack, error) {
	ret, err := C.nfct_clone((*C.struct_nf_conntrack)(ct))
	return (*Conntrack)(ret), err
}

// nfct_setobjopt(struct nf_conntrack *ct, unsigned int option)
func conntrackSetobjopt(ct *Conntrack, option uint) error {
	if option > NFCT_SOPT_MAX {
		return syscall.EINVAL
	}
	ret, err := C.nfct_setobjopt((*C.struct_nf_conntrack)(ct), C.uint(option))
	if ret == -1 {
		return err
	}
	return nil
}

// int nfct_getobjopt(const struct nf_conntrack *ct, unsigned int option)
func conntrackGetobjopt(ct *Conntrack, option uint) (int, error) {
	if option > NFCT_GOPT_MAX {
		return -1, syscall.EINVAL
	}
	ret, err := C.nfct_getobjopt((*C.struct_nf_conntrack)(ct), C.uint(option))
	if ret == -1 {
		return -1, err
	}
	return int(ret), nil
}

// NO -  LibrarySetup Library setup

// void
// nfct_set_attr_l(struct nf_conntrack *ct, const enum nf_conntrack_attr type,
//		   const void *value, size_t len)
func conntrackSetAttrL(ct *Conntrack, attr_type ConntrackAttr, value unsafe.Pointer, size Size_t) error {
	if attr_type >= ATTR_MAX {
		return syscall.EINVAL
	}
	C.nfct_set_attr_l((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type),
		value, C.size_t(size))
	return nil
}
func conntrackSetAttrLPtr(ct *Conntrack, attr_type ConntrackAttr, value interface{}) error {
	if attr_type >= ATTR_MAX {
		return syscall.EINVAL
	}
	v := reflect.ValueOf(value)
	if v.Kind() != reflect.Ptr {
		panic("pointer required for value")
	}
	t := reflect.Indirect(v).Type()
	conntrackSetAttrL(ct, attr_type, unsafe.Pointer(v.Pointer()), Size_t(t.Size()))
	return nil
}

// void nfct_set_attr(struct nf_conntrack *ct,
//		      const enum nf_conntrack_attr type,
//		      const void *value)
func conntrackSetAttr(ct *Conntrack, attr_type ConntrackAttr, value unsafe.Pointer) error {
	if attr_type >= ATTR_MAX {
		return syscall.EINVAL
	}
	C.nfct_set_attr((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type), value)
	return nil
}
func conntrackSetAttrPtr(ct *Conntrack, attr_type ConntrackAttr, value interface{}) error {
	if attr_type >= ATTR_MAX {
		return syscall.EINVAL
	}
	v := reflect.ValueOf(value)
	if v.Kind() != reflect.Ptr {
		panic("pointer required for value")
	}
	conntrackSetAttr(ct, attr_type, unsafe.Pointer(v.Pointer()))
	return nil
}

// void nfct_set_attr_u8(struct nf_conntrack *ct,
//		         const enum nf_conntrack_attr type,
//		         u_int8_t value)
func conntrackSetAttrU8(ct *Conntrack, attr_type ConntrackAttr, value uint8) error {
	if attr_type >= ATTR_MAX {
		return syscall.EINVAL
	}
	C.nfct_set_attr_u8((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type), C.u_int8_t(value))
	return nil
}

// void nfct_set_attr_u16(struct nf_conntrack *ct,
//		          const enum nf_conntrack_attr type,
//		          u_int16_t value)
func conntrackSetAttrU16(ct *Conntrack, attr_type ConntrackAttr, value uint16) error {
	if attr_type >= ATTR_MAX {
		return syscall.EINVAL
	}
	C.nfct_set_attr_u16((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type), C.u_int16_t(value))
	return nil
}

// void nfct_set_attr_u32(struct nf_conntrack *ct,
//		          const enum nf_conntrack_attr type,
//		          u_int32_t value)
func conntrackSetAttrU32(ct *Conntrack, attr_type ConntrackAttr, value uint32) error {
	if attr_type >= ATTR_MAX {
		return syscall.EINVAL
	}
	C.nfct_set_attr_u32((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type), C.u_int32_t(value))
	return nil
}

// void nfct_set_attr_u64(struct nf_conntrack *ct,
//		          const enum nf_conntrack_attr type,
//		          u_int64_t value)
func conntrackSetAttrU64(ct *Conntrack, attr_type ConntrackAttr, value uint64) error {
	if attr_type >= ATTR_MAX {
		return syscall.EINVAL
	}
	C.nfct_set_attr_u64((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type), C.u_int64_t(value))
	return nil
}

// const void *nfct_get_attr(const struct nf_conntrack *ct,
//			     const enum nf_conntrack_attr type)
func conntrackGetAttr(ct *Conntrack, attr_type ConntrackAttr) (unsafe.Pointer, error) {
	ret, err := C.nfct_get_attr((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type))
	// why can not just return?
	return ret, err
}

// u_int8_t nfct_get_attr_u8(const struct nf_conntrack *ct,
//			     const enum nf_conntrack_attr type)
func conntrackGetAttrU8(ct *Conntrack, attr_type ConntrackAttr) (uint8, error) {
	ret, err := C.nfct_get_attr_u8((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type))
	return uint8(ret), err
}

// u_int16_t nfct_get_attr_u16(const struct nf_conntrack *ct,
//			       const enum nf_conntrack_attr type)
func conntrackGetAttrU16(ct *Conntrack, attr_type ConntrackAttr) (uint16, error) {
	ret, err := C.nfct_get_attr_u16((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type))
	return uint16(ret), err
}

// u_int32_t nfct_get_attr_u32(const struct nf_conntrack *ct,
//			       const enum nf_conntrack_attr type)
func conntrackGetAttrU32(ct *Conntrack, attr_type ConntrackAttr) (uint32, error) {
	ret, err := C.nfct_get_attr_u32((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type))
	return uint32(ret), err
}

// u_int64_t nfct_get_attr_u64(const struct nf_conntrack *ct,
//			       const enum nf_conntrack_attr type)
func conntrackGetAttrU64(ct *Conntrack, attr_type ConntrackAttr) (uint64, error) {
	ret, err := C.nfct_get_attr_u64((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type))
	return uint64(ret), err
}

// int nfct_attr_is_set(const struct nf_conntrack *ct,
//		        const enum nf_conntrack_attr type)
func conntrackAttrIsSet(ct *Conntrack, attr_type ConntrackAttr) (bool, error) {
	// is error needed?
	// yes, original document says:
	//
	//   On error, -1 is returned and errno is set appropiately, otherwise
	//   the value of the attribute is returned.
	ret, err := C.nfct_attr_is_set((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type))
	return ret > 0, err
}

// int nfct_attr_is_set_array(const struct nf_conntrack *ct,
//			      const enum nf_conntrack_attr *type_array,
//			      int size)
func conntrackAttrIsSetArray(ct *Conntrack, type_array []ConntrackAttr) (bool, error) {
	// ret, err := C.nfct_attr_is_set_array((*C.struct_nf_conntrack)(ct), (*C.enum_conntrack_attr)(&type_array[0]), C.int(size))
	// will cause in build
	//   panic: runtime error: invalid memory address or nil pointer dereference
	//   [signal 0xb code=0x1 addr=0x18 pc=0x40c6fe]

	// is *uint32 casting right? go build says if using C.int:
	//   cannot use (*_Ctype_int)(unsafe.Pointer(&type_array[0])) (type *_Ctype_int) as type *uint32 in function argument
	ret, err := C.nfct_attr_is_set_array((*C.struct_nf_conntrack)(ct), (*uint32)(unsafe.Pointer(&type_array[0])), C.int(len(type_array)))
	return ret > 0, err
}

// int nfct_attr_unset(struct nf_conntrack *ct,
//		       const enum nf_conntrack_attr type)
func conntrackAttrUnset(ct *Conntrack, attr_type ConntrackAttr) error {
	_, err := C.nfct_attr_unset((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type))
	return err
}

// void nfct_set_attr_grp(struct nf_conntrack *ct,
//		          const enum nf_conntrack_attr_grp type,
//		          const void *data)
func conntrackSetAttrGrp(ct *Conntrack, attr_type ConntrackAttrGrp, data unsafe.Pointer) error {
	if attr_type >= ATTR_GRP_MAX {
		return syscall.EINVAL
	}
	C.nfct_set_attr_grp((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr_grp(attr_type), data)
	return nil
}
func conntrackSetAttrGrpPtr(ct *Conntrack, attr_type ConntrackAttrGrp, data interface{}) error {
	v := reflect.ValueOf(data)
	if v.Kind() != reflect.Ptr {
		panic("pointer required for value")
	}
	return conntrackSetAttrGrp(ct, attr_type, unsafe.Pointer(v.Pointer()))
}

// int nfct_get_attr_grp(const struct nf_conntrack *ct,
//		         const enum nf_conntrack_attr_grp type,
//		         void *data)
func conntrackGetAttrGrp(ct *Conntrack, attr_type ConntrackAttrGrp, data unsafe.Pointer) error {
	_, err := C.nfct_get_attr_grp((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr_grp(attr_type), data)
	return err
}
func conntrackGetAttrGrpPtr(ct *Conntrack, attr_type ConntrackAttrGrp, data interface{}) error {
	v := reflect.ValueOf(data)
	if v.Kind() != reflect.Ptr {
		panic("pointer required for value")
	}
	return conntrackGetAttrGrp(ct, attr_type, unsafe.Pointer(v.Pointer()))
}

// int nfct_attr_grp_is_set(const struct nf_conntrack *ct,
//			    const enum nf_conntrack_attr_grp type)
func conntrackAttrGrpIsSet(ct *Conntrack, attr_type ConntrackAttrGrp) (bool, error) {
	ret, err := C.nfct_attr_grp_is_set((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr_grp(attr_type))
	return ret > 0, err
}

// int nfct_attr_grp_unset(struct nf_conntrack *ct,
//			   const enum nf_conntrack_attr_grp type)
func conntrackAttrGrpUnset(ct *Conntrack, attr_type ConntrackAttrGrp) error {
	_, err := C.nfct_attr_grp_unset((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr_grp(attr_type))
	return err
}

// NO - Low level object to Netlink message
// NO - Send commands to kernel-space and receive replies

// int nfct_snprintf(char *buf,
//		     unsigned int size,
//		     const struct nf_conntrack *ct,
//		     unsigned int msg_type,
//		     unsigned int out_type,
//		     unsigned int flags)
func conntrackSnprintf(buf []byte, ct *Conntrack, msg_type ConntrackMsgType, out_type, flags uint) (int, error) {
	ret, err := C.nfct_snprintf((*C.char)(unsafe.Pointer(&buf[0])), C.uint(len(buf)), (*C.struct_nf_conntrack)(ct),
		C.uint(msg_type), C.uint(out_type), C.uint(flags))
	return int(ret), err
}

// int nfct_snprintf_labels(char *buf,
//			 unsigned int size,
//			 const struct nf_conntrack *ct,
//			 unsigned int msg_type,
//			 unsigned int out_type,
//			 unsigned int flags,
//			 struct nfct_labelmap *map)
func conntrackSnprintfLabels(buf []byte, ct *Conntrack, msg_type, out_type, flags uint,
	label_map *Labelmap) (int, error) {
	ret, err := C.nfct_snprintf_labels((*C.char)(unsafe.Pointer(&buf[0])), C.uint(len(buf)), (*C.struct_nf_conntrack)(ct),
		C.uint(msg_type), C.uint(out_type), C.uint(flags), (*C.struct_nfct_labelmap)(label_map))
	return int(ret), err
}

// NO - nfct_compare

// int nfct_cmp(const struct nf_conntrack *ct1,
//	        const struct nf_conntrack *ct2,
//	        unsigned int flags)
func conntrackCmp(ct1, ct2 *Conntrack, flags uint) int {
	return int(C.nfct_cmp((*C.struct_nf_conntrack)(ct1), (*C.struct_nf_conntrack)(ct2), C.uint(flags)))
}

// void nfct_copy(struct nf_conntrack *ct1,
//	          const struct nf_conntrack *ct2,
//	          unsigned int flags)
func conntrackCopy(ct1, ct2 *Conntrack, flags uint) {
	C.nfct_copy((*C.struct_nf_conntrack)(ct1), (*C.struct_nf_conntrack)(ct2), C.uint(flags))
}

// void nfct_copy_attr(struct nf_conntrack *ct1,
//		       const struct nf_conntrack *ct2,
//		       const enum nf_conntrack_attr type)
func conntrackCopyAttr(ct1, ct2 *Conntrack, attr_type ConntrackAttr) {
	C.nfct_copy_attr((*C.struct_nf_conntrack)(ct1), (*C.struct_nf_conntrack)(ct2), C.enum_nf_conntrack_attr(attr_type))
}

// struct nfct_filter *nfct_filter_create(void)
func filterCreate() (*Filter, error) {
	ret, err := C.nfct_filter_create()
	return (*Filter)(ret), err
}

// void nfct_filter_destroy(struct nfct_filter *filter)
func filterDestroy(filter *Filter) {
	C.nfct_filter_destroy((*C.struct_nfct_filter)(filter))
}

// void nfct_filter_add_attr(struct nfct_filter *filter,
//			     const enum nfct_filter_attr type,
//			     const void *value)
func filterAddAttr(filter *Filter, attr_type FilterAttr, value unsafe.Pointer) error {
	if attr_type >= NFCT_FILTER_MAX {
		return syscall.EINVAL
	}
	C.nfct_filter_add_attr((*C.struct_nfct_filter)(filter), C.enum_nfct_filter_attr(attr_type), value)
	return nil
}
func filterAddAttrPtr(filter *Filter, attr_type FilterAttr, value interface{}) error {
	v := reflect.ValueOf(value)
	if v.Kind() != reflect.Ptr {
		panic("pointer required for value")
	}
	return filterAddAttr(filter, attr_type, unsafe.Pointer(v.Pointer()))
}

// void nfct_filter_add_attr_u32(struct nfct_filter *filter,
//				 const enum nfct_filter_attr attr,
//				 const u_int32_t value);
func filterAddAttrU32(filter *Filter, attr FilterAttr, value uint32) error {
	if attr >= NFCT_FILTER_MAX {
		return syscall.EINVAL
	}
	C.nfct_filter_add_attr_u32((*C.struct_nfct_filter)(filter), C.enum_nfct_filter_attr(attr), C.u_int32_t(value))
	return nil
}

// int nfct_filter_set_logic(struct nfct_filter *filter,
//			     const enum nfct_filter_attr attr,
//			     const enum nfct_filter_logic logic);
func filterSetLogic(filter *Filter, attr FilterAttr, logic FilterLogic) error {
	_, err := C.nfct_filter_set_logic((*C.struct_nfct_filter)(filter), C.enum_nfct_filter_attr(attr), C.enum_nfct_filter_logic(logic))
	return err
}

// int nfct_filter_attach(int fd, struct nfct_filter *filter);
func filterAttach(fd int, filter *Filter) error {
	_, err := C.nfct_filter_attach(C.int(fd), (*C.struct_nfct_filter)(filter))
	return err
}

// int nfct_filter_detach(int fd);

// detach an existing filter
func FilterDetach(fd int) error {
	_, err := C.nfct_filter_detach(C.int(fd))
	return err
}

// const char *nfct_labelmap_get_name(struct nfct_labelmap *m, unsigned int bit)
func labelmapGetName(m *Labelmap, bit uint) string {
	return C.GoString(C.nfct_labelmap_get_name((*C.struct_nfct_labelmap)(m), C.uint(bit)))
}

// int nfct_labelmap_get_bit(struct nfct_labelmap *m, const char *name)
func labelmapGetBit(m *Labelmap, name string) int {
	cstr := C.CString(name)
	defer C.free(unsafe.Pointer(cstr))
	return int(C.nfct_labelmap_get_bit((*C.struct_nfct_labelmap)(m), cstr))
}

// struct nfct_labelmap *nfct_labelmap_new(const char *mapfile)
func labelmapNew(mapfile string) (*Labelmap, error) {
	var cstr *C.char
	if len(mapfile) == 0 {
		cstr = nil
	} else {
		cstr = C.CString(mapfile)
		defer C.free(unsafe.Pointer(cstr))
	}
	ret, err := C.nfct_labelmap_new(cstr)
	return (*Labelmap)(ret), err
}

// void nfct_labelmap_destroy(struct nfct_labelmap *map)
func labelmapDestroy(labelmap *Labelmap) {
	C.nfct_labelmap_destroy((*C.struct_nfct_labelmap)(labelmap))
}

// struct nfct_bitmask *nfct_bitmask_new(unsigned int max)
func bitmaskNew(max uint) (*Bitmask, error) {
	ret, err := C.nfct_bitmask_new(C.uint(max))
	return (*Bitmask)(ret), err
}

// struct nfct_bitmask *nfct_bitmask_clone(const struct nfct_bitmask *b)
func bitmaskClone(b *Bitmask) (*Bitmask, error) {
	ret, err := C.nfct_bitmask_clone((*C.struct_nfct_bitmask)(b))
	return (*Bitmask)(ret), err
}

// void nfct_bitmask_set_bit(struct nfct_bitmask *b, unsigned int bit)
func bitmaskSetBit(b *Bitmask, bit uint) {
	C.nfct_bitmask_set_bit((*C.struct_nfct_bitmask)(b), C.uint(bit))
}

// int nfct_bitmask_test_bit(const struct nfct_bitmask *b, unsigned int bit)
func bitmaskTestBit(b *Bitmask, bit uint) int {
	return int(C.nfct_bitmask_test_bit((*C.struct_nfct_bitmask)(b), C.uint(bit)))
}

// void nfct_bitmask_unset_bit(struct nfct_bitmask *b, unsigned int bit)
func bitmaskUnsetBit(b *Bitmask, bit uint) {
	C.nfct_bitmask_unset_bit((*C.struct_nfct_bitmask)(b), C.uint(bit))
}

// unsigned int nfct_bitmask_maxbit(const struct nfct_bitmask *b)
func bitmaskMaxbit(b *Bitmask) uint {
	return uint(C.nfct_bitmask_maxbit((*C.struct_nfct_bitmask)(b)))
}

// void nfct_bitmask_destroy(struct nfct_bitmask *b)
func bitmaskDestroy(b *Bitmask) {
	C.nfct_bitmask_destroy((*C.struct_nfct_bitmask)(b))
}

// void nfct_bitmask_clear(struct nfct_bitmask *b)
func bitmaskClear(b *Bitmask) {
	C.nfct_bitmask_clear((*C.struct_nfct_bitmask)(b))
}

// bool nfct_bitmask_equal(const struct nfct_bitmask *b1, const struct nfct_bitmask *b2)
func bitmaskEqual(b1, b2 *Bitmask) bool {
	return (bool)(C.nfct_bitmask_equal((*C.struct_nfct_bitmask)(b1), (*C.struct_nfct_bitmask)(b2)))
}

// int nfct_nlmsg_build(struct nlmsghdr *nlh, const struct nf_conntrack *ct);
func conntrackNlmsgBuild(nlh *mnl.Nlmsg, ct *Conntrack) (int, error) {
	ret, err := C.nfct_nlmsg_build(
		(*C.struct_nlmsghdr)(unsafe.Pointer(nlh.Nlmsghdr)),
		(*C.struct_nf_conntrack)(ct))
	return int(ret), err
}

// int nfct_nlmsg_parse(const struct nlmsghdr *nlh, struct nf_conntrack *ct);
func conntrackNlmsgParse(nlh *mnl.Nlmsg, ct *Conntrack) (int, error) {
	ret, err := C.nfct_nlmsg_parse(
		(*C.struct_nlmsghdr)(unsafe.Pointer(nlh.Nlmsghdr)),
		(*C.struct_nf_conntrack)(ct))
	return int(ret), err
}

// int nfct_payload_parse(const void *payload, size_t payload_len, uint16_t l3num, struct nf_conntrack *ct);
func conntrackPayloadParse(payload unsafe.Pointer, payload_len Size_t, l3num uint16, ct *Conntrack) (int, error) {
	ret, err := C.nfct_payload_parse(payload, C.size_t(payload_len), C.uint16_t(l3num), (*C.struct_nf_conntrack)(ct))
	return int(ret), err
}
func conntrackPayloadParseBytes(payload []byte, l3num uint16, ct *Conntrack) (int, error) {
	ret, err := C.nfct_payload_parse(unsafe.Pointer(&payload[0]), C.size_t(len(payload)), C.uint16_t(l3num), (*C.struct_nf_conntrack)(ct))
	return int(ret), err
}

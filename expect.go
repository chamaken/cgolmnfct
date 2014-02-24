package cgolmnfct

import (
	"reflect"
	"syscall"
	"unsafe"
	mnl "cgolmnl"
)

/*
#cgo CFLAGS: -I./include
#cgo LDFLAGS: -lnetfilter_conntrack
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
*/
import "C"


type Expect	C.struct_nf_expect // [0]byte


// struct nf_expect *nfexp_new(void)
func expectNew() (*Expect, error) {
	ret, err := C.nfexp_new()
	return (*Expect)(ret), err
}

// void nfexp_destroy(struct nf_expect *exp)
func expectDestroy(exp *Expect) {
	C.nfexp_destroy((*C.struct_nf_expect)(exp))
}

// struct nf_expect *nfexp_clone(const struct nf_expect *exp)
func expectClone(exp *Expect) (*Expect, error) {
	ret, err := C.nfexp_clone((*C.struct_nfexpect)(exp))
	return (*Expect)(ret), err
}

// int nfexp_cmp(const struct nf_expect *exp1, const struct nf_expect *exp2,
//		 unsigned int flags)
func expectCmp(exp1, exp2 *Expect, flags int) int {
	return int(C.nfexp_cmp((*C.struct_nf_expect)(exp1), (*C.struct_nf_expect)(exp2), C.uint(flags)))
}

// NO Library setup

// void nfexp_set_attr(struct nf_expect *exp,
//		       const enum nf_expect_attr type,
//		       const void *value)
func expectSetAttr(exp *Expect, attr_type ExpectAttr, value unsafe.Pointer) error {
	if attr_type >= ATTR_EXP_MAX {
		return syscall.EINVAL
	}
	C.nfexp_set_attr((*C.struct_nf_expect)(exp), C.enum_nf_expect_attr(attr_type), value)
	return nil
}
func expectSetAttrPtr(exp *Expect, attr_type ExpectAttr, value interface{}) error {
	v := reflect.ValueOf(value)
	if v.Kind() != reflect.Ptr {
		panic("pointer required for value")
	}
	return expectSetAttr(exp, attr_type, unsafe.Pointer(v.Pointer()))
}

// void nfexp_set_attr_u8(struct nf_expect *exp,
//			  const enum nf_expect_attr type,
//		          u_int8_t value)
func expectSetAttrU8(exp *Expect, attr_type ExpectAttr, value uint8) error {
	if attr_type >= ATTR_EXP_MAX {
		return syscall.EINVAL
	}
	C.nfexp_set_attr_u8((*C.struct_nf_expect)(exp), C.enum_nf_expect_attr(attr_type), (C.u_int8_t)(value))
	return nil
}

// void nfexp_set_attr_u16(struct nf_expect *exp,
//			   const enum nf_expect_attr type,
//			   u_int16_t value)
func expectSetAttrU16(exp *Expect, attr_type ExpectAttr, value uint16) error {
	if attr_type >= ATTR_EXP_MAX {
		return syscall.EINVAL
	}
	C.nfexp_set_attr_u16((*C.struct_nf_expect)(exp), C.enum_nf_expect_attr(attr_type), (C.u_int16_t)(value))
	return nil
}

// void nfexp_set_attr_u32(struct nf_expect *exp,
//			   const enum nf_expect_attr type,
//			   u_int32_t value)
func expectSetAttrU32(exp *Expect, attr_type ExpectAttr, value uint32) error {
	if attr_type >= ATTR_EXP_MAX {
		return syscall.EINVAL
	}
	C.nfexp_set_attr_u32((*C.struct_nf_expect)(exp), C.enum_nf_expect_attr(attr_type), (C.u_int32_t)(value))
	return nil
}

// const void *nfexp_get_attr(const struct nf_expect *exp,
//			      const enum nf_expect_attr type)
func expectGetAttr(exp *Expect, attr_type ExpectAttr) (unsafe.Pointer, error) {
	ret, err := C.nfexp_get_attr((*C.struct_nf_expect)(exp), C.enum_nf_expect_attr(attr_type))
	return ret, err
}

// u_int8_t nfexp_get_attr_u8(const struct nf_expect *exp,
//			      const enum nf_expect_attr type)
func expectGetAttrU8(exp *Expect, attr_type ExpectAttr) (uint8, error) {
	ret, err := C.nfexp_get_attr_u8((*C.struct_nf_expect)(exp), C.enum_nf_expect_attr(attr_type))
	return uint8(ret), err
}

// u_int16_t nfexp_get_attr_u16(const struct nf_expect *exp,
//			      const enum nf_expect_attr type)
func expectGetAttrU16(exp *Expect, attr_type ExpectAttr) (uint16, error) {
	ret, err := C.nfexp_get_attr_u16((*C.struct_nf_expect)(exp), C.enum_nf_expect_attr(attr_type))
	return uint16(ret), err
}

// u_int32_t nfexp_get_attr_u32(const struct nf_expect *exp,
//			      const enum nf_expect_attr type)
func expectGetAttrU32(exp *Expect, attr_type ExpectAttr) (uint32, error) {
	ret, err := C.nfexp_get_attr_u32((*C.struct_nf_expect)(exp), C.enum_nf_expect_attr(attr_type))
	return uint32(ret), err
}

// int nfexp_attr_is_set(const struct nf_expect *exp,
//		         const enum nf_expect_attr type)
func expectAttrIsSet(exp *Expect, attr_type ExpectAttr) (bool, error) {
	ret, err := C.nfexp_attr_is_set((*C.struct_nf_expect)(exp), C.enum_nf_expect_attr(attr_type))
	return ret > 0, err
}

// int nfexp_attr_unset(struct nf_expect *exp,
//		        const enum nf_expect_attr type)
func expectAttrUnset(exp *Expect, attr_type ExpectAttr) error {
	_, err := C.nfexp_attr_unset((*C.struct_nf_expect)(exp), C.enum_nf_expect_attr(attr_type))
	return err
}

// NO Low level object to Netlink message
// NO Send commands to kernel-space and receive replies

// int nfexp_snprintf(char *buf,
//		      unsigned int size,
//		      const struct nf_expect *exp,
//		      unsigned int msg_type,
//		      unsigned int out_type,
//		      unsigned int flags)
func expectSnprintf(buf []byte, exp *Expect, msg_type ConntrackMsgType, out_type, flags uint) (int, error) {
	ret, err := C.nfexp_snprintf((*C.char)(unsafe.Pointer(&buf[0])), C.uint(len(buf)), (*C.struct_nf_expect)(exp),
		C.uint(msg_type), C.uint(out_type), C.uint(flags))
	return int(ret), err
}

// int
// nfexp_nlmsg_build(struct nlmsghdr *nlh, const struct nf_expect *exp)
func expectNlmsgBuild(nlh *mnl.Nlmsghdr, exp *Expect) (int, error) {
	ret, err := C.nfexp_nlmsg_build((*C.struct_nlmsghdr)(unsafe.Pointer(nlh)), (*C.struct_nf_expect)(exp))
	return int(ret), err
}

// int nfexp_nlmsg_parse(const struct nlmsghdr *nlh, struct nf_expect *exp)
func expectNlmsgParse(nlh *mnl.Nlmsghdr, exp *Expect) (int, error) {
	ret, err := C.nfexp_nlmsg_parse((*C.struct_nlmsghdr)(unsafe.Pointer(nlh)), (*C.struct_nf_expect)(exp))
	return int(ret), err
}

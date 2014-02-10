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


// [0]byte
type Expect	C.struct_nf_expect


// nfexp_new - allocate a new expectation
//
// struct nf_expect *nfexp_new(void)
func ExpectNew() (*Expect, error) {
	ret, err := C.nfexp_new()
	return (*Expect)(ret), err
}
func NewExpect() (*Expect, error) { return ExpectNew() }

// nfexp_destroy - release an expectation object
//
// void nfexp_destroy(struct nf_expect *exp)
func ExpectDestroy(exp *Expect) {
	C.nfexp_destroy((*C.struct_nf_expect)(exp))
}

// nfexp_clone - clone a expectation object
//
// struct nf_expect *nfexp_clone(const struct nf_expect *exp)
func ExpectClone(exp *Expect) (*Expect, error) {
	ret, err := C.nfexp_clone((*C.struct_nfexpect)(exp))
	return (*Expect)(ret), err
}

// nfexp_cmp - compare two expectation objects
//
// int nfexp_cmp(const struct nf_expect *exp1, const struct nf_expect *exp2,
//		 unsigned int flags)
func ExpectCmp(exp1, exp2 *Expect, flags int) int {
	return int(C.nfexp_cmp((*C.struct_nf_expect)(exp1), (*C.struct_nf_expect)(exp2), C.uint(flags)))
}

// NO Library setup

// Expect object handling

// nfexp_set_attr - set the value of a certain expect attribute
//
// void nfexp_set_attr(struct nf_expect *exp,
//		       const enum nf_expect_attr type,
//		       const void *value)
func ExpectSetAttr(exp *Expect, attr_type ExpectAttr, value unsafe.Pointer) error {
	if attr_type >= ATTR_EXP_MAX {
		return syscall.EINVAL
	}
	C.nfexp_set_attr((*C.struct_nf_expect)(exp), C.enum_nf_expect_attr(attr_type), value)
	return nil
}
func ExpectSetAttrPtr(exp *Expect, attr_type ExpectAttr, value interface{}) error {
	v := reflect.ValueOf(value)
	if v.Kind() != reflect.Ptr {
		panic("pointer required for value")
	}
	return ExpectSetAttr(exp, attr_type, unsafe.Pointer(v.Pointer()))
}

// nfexp_set_attr_u8 - set the value of a certain expect attribute
//
// void nfexp_set_attr_u8(struct nf_expect *exp,
//			  const enum nf_expect_attr type,
//		          u_int8_t value)
func ExpectSetAttrU8(exp *Expect, attr_type ExpectAttr, value uint8) error {
	if attr_type >= ATTR_EXP_MAX {
		return syscall.EINVAL
	}
	C.nfexp_set_attr_u8((*C.struct_nf_expect)(exp), C.enum_nf_expect_attr(attr_type), (C.u_int8_t)(value))
	return nil
}

// nfexp_set_attr_u16 - set the value of a certain expect attribute
//
// void nfexp_set_attr_u16(struct nf_expect *exp,
//			   const enum nf_expect_attr type,
//			   u_int16_t value)
func ExpectSetAttrU16(exp *Expect, attr_type ExpectAttr, value uint16) error {
	if attr_type >= ATTR_EXP_MAX {
		return syscall.EINVAL
	}
	C.nfexp_set_attr_u16((*C.struct_nf_expect)(exp), C.enum_nf_expect_attr(attr_type), (C.u_int16_t)(value))
	return nil
}

// nfexp_set_attr_u32 - set the value of a certain expect attribute
//
// void nfexp_set_attr_u32(struct nf_expect *exp,
//			   const enum nf_expect_attr type,
//			   u_int32_t value)
func ExpectSetAttrU32(exp *Expect, attr_type ExpectAttr, value uint32) error {
	if attr_type >= ATTR_EXP_MAX {
		return syscall.EINVAL
	}
	C.nfexp_set_attr_u32((*C.struct_nf_expect)(exp), C.enum_nf_expect_attr(attr_type), (C.u_int32_t)(value))
	return nil
}

// nfexp_get_attr - get an expect attribute
//
// const void *nfexp_get_attr(const struct nf_expect *exp,
//			      const enum nf_expect_attr type)
func ExpectGetAttr(exp *Expect, attr_type ExpectAttr) (unsafe.Pointer, error) {
	ret, err := C.nfexp_get_attr((*C.struct_nf_expect)(exp), C.enum_nf_expect_attr(attr_type))
	return ret, err
}

// nfexp_get_attr_u8 - get attribute of unsigned 8-bits long
//
// u_int8_t nfexp_get_attr_u8(const struct nf_expect *exp,
//			      const enum nf_expect_attr type)
func ExpectGetAttrU8(exp *Expect, attr_type ExpectAttr) (uint8, error) {
	ret, err := C.nfexp_get_attr_u8((*C.struct_nf_expect)(exp), C.enum_nf_expect_attr(attr_type))
	return uint8(ret), err
}

// nfexp_get_attr_u16 - get attribute of unsigned 16-bits long
//
// u_int16_t nfexp_get_attr_u16(const struct nf_expect *exp,
//			      const enum nf_expect_attr type)
func ExpectGetAttrU16(exp *Expect, attr_type ExpectAttr) (uint16, error) {
	ret, err := C.nfexp_get_attr_u16((*C.struct_nf_expect)(exp), C.enum_nf_expect_attr(attr_type))
	return uint16(ret), err
}

// nfexp_get_attr_u32 - get attribute of unsigned 32-bits long
//
// u_int32_t nfexp_get_attr_u32(const struct nf_expect *exp,
//			      const enum nf_expect_attr type)
func ExpectGetAttrU32(exp *Expect, attr_type ExpectAttr) (uint32, error) {
	ret, err := C.nfexp_get_attr_u32((*C.struct_nf_expect)(exp), C.enum_nf_expect_attr(attr_type))
	return uint32(ret), err
}

// nfexp_attr_is_set - check if a certain attribute is set
//
// int nfexp_attr_is_set(const struct nf_expect *exp,
//		         const enum nf_expect_attr type)
func ExpectAttrIsSet(exp *Expect, attr_type ExpectAttr) (bool, error) {
	ret, err := C.nfexp_attr_is_set((*C.struct_nf_expect)(exp), C.enum_nf_expect_attr(attr_type))
	return ret > 0, err
}

// nfexp_attr_unset - unset a certain attribute
//
// int nfexp_attr_unset(struct nf_expect *exp,
//		        const enum nf_expect_attr type)
func ExpectAttrUnset(exp *Expect, attr_type ExpectAttr) error {
	_, err := C.nfexp_attr_unset((*C.struct_nf_expect)(exp), C.enum_nf_expect_attr(attr_type))
	return err
}

// NO Low level object to Netlink message
// NO Send commands to kernel-space and receive replies


// Expect object handling

// nfexp_snprintf - print a conntrack object to a buffer
//
// int nfexp_snprintf(char *buf,
//		      unsigned int size,
//		      const struct nf_expect *exp,
//		      unsigned int msg_type,
//		      unsigned int out_type,
//		      unsigned int flags)
func ExpectSnprintf(buf []byte, exp *Expect, msg_type ConntrackMsgType, out_type, flags uint) (int, error) {
	ret, err := C.nfexp_snprintf((*C.char)(unsafe.Pointer(&buf[0])), C.uint(len(buf)), (*C.struct_nf_expect)(exp),
		C.uint(msg_type), C.uint(out_type), C.uint(flags))
	return int(ret), err
}

// New low level API: netlink functions

// int
// nfexp_nlmsg_build(struct nlmsghdr *nlh, const struct nf_expect *exp)
func ExpectNlmsgBuild(nlh *mnl.Nlmsghdr, exp *Expect) (int, error) {
	ret, err := C.nfexp_nlmsg_build((*C.struct_nlmsghdr)(unsafe.Pointer(nlh)), (*C.struct_nf_expect)(exp))
	return int(ret), err
}

// int nfexp_nlmsg_parse(const struct nlmsghdr *nlh, struct nf_expect *exp)
func ExpectNlmsgParse(nlh *mnl.Nlmsghdr, exp *Expect) (int, error) {
	ret, err := C.nfexp_nlmsg_parse((*C.struct_nlmsghdr)(unsafe.Pointer(nlh)), (*C.struct_nf_expect)(exp))
	return int(ret), err
}

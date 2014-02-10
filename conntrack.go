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
#include <stdlib.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
*/
import "C"

// [0]byte
type Conntrack	C.struct_nf_conntrack
type Bitmask	C.struct_nfct_bitmask
type Labelmap	C.struct_nfct_labelmap
type Filter	C.struct_nfct_filter
type FilterDump	C.struct_nfct_filter_dump


// Conntrack object handling

// nfct_conntrack_new - allocate a new conntrack
//
// struct nf_conntrack *nfct_new(void)
func ConntrackNew() (*Conntrack, error) {
	ret, err := C.nfct_new()
	return (*Conntrack)(ret), err
}
func NewConntrack() (*Conntrack, error) { return ConntrackNew() }

// nfct_destroy - release a conntrack object
//
// void nfct_destroy(struct nf_conntrack *ct)
func ConntrackDestroy(ct *Conntrack) {
	C.nfct_destroy((*C.struct_nf_conntrack)(ct))
}

// nfct_clone - clone a conntrack object
//
// struct nf_conntrack *nfct_clone(const struct nf_conntrack *ct)
func ConntrackClone(ct *Conntrack) (*Conntrack, error) {
	ret, err := C.nfct_clone((*C.struct_nf_conntrack)(ct))
	return (*Conntrack)(ret), err
}

// nfct_setobjopt - set a certain option for a conntrack object
//
// nfct_setobjopt(struct nf_conntrack *ct, unsigned int option)
func ConntrackSetobjopt(ct *Conntrack, option uint) error {
	if option > NFCT_SOPT_MAX {
		return syscall.EINVAL
	}
	ret, err := C.nfct_setobjopt((*C.struct_nf_conntrack)(ct), C.uint(option))
	if ret == -1 {
		return err
	}
	return nil
}

// nfct_getobjopt - get a certain option for a conntrack object
//
// int nfct_getobjopt(const struct nf_conntrack *ct, unsigned int option)
func ConntrackGetobjopt(ct *Conntrack, option uint) (int, error) {
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


// setter
// nfct_set_attr_l - set the value of a certain conntrack attribute
//
// void
// nfct_set_attr_l(struct nf_conntrack *ct, const enum nf_conntrack_attr type,
//		   const void *value, size_t len)
func ConntrackSetAttrL(ct *Conntrack, attr_type ConntrackAttr, value unsafe.Pointer, size Size_t) error {
	if attr_type >= ATTR_MAX {
		return syscall.EINVAL
	}
	C.nfct_set_attr_l((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type),
		value, C.size_t(size))
	return nil
}
func ConntrackSetAttrLPtr(ct *Conntrack, attr_type ConntrackAttr, value interface{}) error {
	if attr_type >= ATTR_MAX {
		return syscall.EINVAL
	}
	v := reflect.ValueOf(value)
	if v.Kind() != reflect.Ptr {
		panic("pointer required for value")
	}
	t := reflect.Indirect(v).Type()
	ConntrackSetAttrL(ct, attr_type, unsafe.Pointer(v.Pointer()), Size_t(t.Size()))
	return nil
}

// nfct_set_attr - set the value of a certain conntrack attribute
//
// void nfct_set_attr(struct nf_conntrack *ct,
//		      const enum nf_conntrack_attr type,
//		      const void *value)
func ConntrackSetAttr(ct *Conntrack, attr_type ConntrackAttr, value unsafe.Pointer) error {
	if attr_type >= ATTR_MAX {
		return syscall.EINVAL
	}
	C.nfct_set_attr((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type), value)
	return nil
}
func ConntrackSetAttrPtr(ct *Conntrack, attr_type ConntrackAttr, value interface{}) error {
	if attr_type >= ATTR_MAX {
		return syscall.EINVAL
	}
	v := reflect.ValueOf(value)
	if v.Kind() != reflect.Ptr {
		panic("pointer required for value")
	}
	ConntrackSetAttr(ct, attr_type, unsafe.Pointer(v.Pointer()))
	return nil
}

// nfct_set_attr_u8 - set the value of a certain conntrack attribute
//
// void nfct_set_attr_u8(struct nf_conntrack *ct,
//		         const enum nf_conntrack_attr type,
//		         u_int8_t value)
func ConntrackSetAttrU8(ct *Conntrack, attr_type ConntrackAttr, value uint8) error {
	if attr_type >= ATTR_MAX {
		return syscall.EINVAL
	}
	C.nfct_set_attr_u8((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type), C.u_int8_t(value))
	return nil
}

// nfct_set_attr_u16 - set the value of a certain conntrack attribute
//
//
// void nfct_set_attr_u16(struct nf_conntrack *ct,
//		          const enum nf_conntrack_attr type,
//		          u_int16_t value)
func ConntrackSetAttrU16(ct *Conntrack, attr_type ConntrackAttr, value uint16) error {
	if attr_type >= ATTR_MAX {
		return syscall.EINVAL
	}
	C.nfct_set_attr_u16((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type), C.u_int16_t(value))
	return nil
}

// nfct_set_attr_u32 - set the value of a certain conntrack attribute
//
// void nfct_set_attr_u32(struct nf_conntrack *ct,
//		          const enum nf_conntrack_attr type,
//		          u_int32_t value)
func ConntrackSetAttrU32(ct *Conntrack, attr_type ConntrackAttr, value uint32) error {
	if attr_type >= ATTR_MAX {
		return syscall.EINVAL
	}
	C.nfct_set_attr_u32((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type), C.u_int32_t(value))
	return nil
}

// nfct_set_attr_u64 - set the value of a certain conntrack attribute
//
// void nfct_set_attr_u64(struct nf_conntrack *ct,
//		          const enum nf_conntrack_attr type,
//		          u_int64_t value)
func ConntrackSetAttrU64(ct *Conntrack, attr_type ConntrackAttr, value uint64) error {
	if attr_type >= ATTR_MAX {
		return syscall.EINVAL
	}
	C.nfct_set_attr_u64((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type), C.u_int64_t(value))
	return nil
}

// nfct_get_attr - get a conntrack attribute
//
// const void *nfct_get_attr(const struct nf_conntrack *ct,
//			     const enum nf_conntrack_attr type)
func ConntrackGetAttr(ct *Conntrack, attr_type ConntrackAttr) (unsafe.Pointer, error) {
	ret, err := C.nfct_get_attr((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type))
	// why can not just return?
	return ret, err
}

// nfct_get_attr_u8 - get attribute of unsigned 8-bits long
//
// u_int8_t nfct_get_attr_u8(const struct nf_conntrack *ct,
//			     const enum nf_conntrack_attr type)
func ConntrackGetAttrU8(ct *Conntrack, attr_type ConntrackAttr) (uint8, error) {
	ret, err := C.nfct_get_attr_u8((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type))
	return uint8(ret), err
}

// nfct_get_attr_u16 - get attribute of unsigned 16-bits long
//
// u_int16_t nfct_get_attr_u16(const struct nf_conntrack *ct,
//			       const enum nf_conntrack_attr type)
func ConntrackGetAttrU16(ct *Conntrack, attr_type ConntrackAttr) (uint16, error) {
	ret, err := C.nfct_get_attr_u16((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type))
	return uint16(ret), err
}

// nfct_get_attr_u32 - get attribute of unsigned 32-bits long
//
// u_int32_t nfct_get_attr_u32(const struct nf_conntrack *ct,
//			       const enum nf_conntrack_attr type)
func ConntrackGetAttrU32(ct *Conntrack, attr_type ConntrackAttr) (uint32, error) {
	ret, err := C.nfct_get_attr_u32((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type))
	return uint32(ret), err
}

// nfct_get_attr_u64 - get attribute of unsigned 64-bits long
//
// u_int64_t nfct_get_attr_u64(const struct nf_conntrack *ct,
//			       const enum nf_conntrack_attr type)
func ConntrackGetAttrU64(ct *Conntrack, attr_type ConntrackAttr) (uint64, error) {
	ret, err := C.nfct_get_attr_u64((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type))
	return uint64(ret), err
}

// nfct_attr_is_set - check if a certain attribute is set
//
// int nfct_attr_is_set(const struct nf_conntrack *ct,
//		        const enum nf_conntrack_attr type)
func ConntrackAttrIsSet(ct *Conntrack, attr_type ConntrackAttr) (bool, error) {
	// is error needed?
	// yes, original document says:
	//
	//   On error, -1 is returned and errno is set appropiately, otherwise
	//   the value of the attribute is returned.
	ret, err := C.nfct_attr_is_set((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type))
	return ret > 0, err
}

// nfct_attr_is_set_array - check if an array of attribute types is set
//
// int nfct_attr_is_set_array(const struct nf_conntrack *ct,
//			      const enum nf_conntrack_attr *type_array,
//			      int size)
func ConntrackAttrIsSetArray(ct *Conntrack, type_array []ConntrackAttr) (bool, error) {
	// ret, err := C.nfct_attr_is_set_array((*C.struct_nf_conntrack)(ct), (*C.enum_conntrack_attr)(&type_array[0]), C.int(size))
	// will cause in build
	//   panic: runtime error: invalid memory address or nil pointer dereference
	//   [signal 0xb code=0x1 addr=0x18 pc=0x40c6fe]

	// is *uint32 casting right? go build says if using C.int:
	//   cannot use (*_Ctype_int)(unsafe.Pointer(&type_array[0])) (type *_Ctype_int) as type *uint32 in function argument
	ret, err := C.nfct_attr_is_set_array((*C.struct_nf_conntrack)(ct), (*uint32)(unsafe.Pointer(&type_array[0])), C.int(len(type_array)))
	return ret > 0, err
}

// nfct_attr_unset - unset a certain attribute
//
// int nfct_attr_unset(struct nf_conntrack *ct,
//		       const enum nf_conntrack_attr type)
func ConntrackAttrUnset(ct *Conntrack, attr_type ConntrackAttr) error {
	_, err := C.nfct_attr_unset((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr(attr_type))
	return err
}

// nfct_set_attr_grp - set a group of attributes
//
// void nfct_set_attr_grp(struct nf_conntrack *ct,
//		          const enum nf_conntrack_attr_grp type,
//		          const void *data)
func ConntrackSetAttrGrp(ct *Conntrack, attr_type ConntrackAttrGrp, data unsafe.Pointer) error {
	if attr_type >= ATTR_GRP_MAX {
		return syscall.EINVAL
	}
	C.nfct_set_attr_grp((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr_grp(attr_type), data)
	return nil
}
func ConntrackSetAttrGrpPtr(ct *Conntrack, attr_type ConntrackAttrGrp, data interface{}) error {
	v := reflect.ValueOf(data)
	if v.Kind() != reflect.Ptr {
		panic("pointer required for value")
	}
	return ConntrackSetAttrGrp(ct, attr_type, unsafe.Pointer(v.Pointer()))
}

// nfct_get_attr_grp - get an attribute group
//
// int nfct_get_attr_grp(const struct nf_conntrack *ct,
//		         const enum nf_conntrack_attr_grp type,
//		         void *data)
func ConntrackGetAttrGrp(ct *Conntrack, attr_type ConntrackAttrGrp, data unsafe.Pointer) error {
	_, err := C.nfct_get_attr_grp((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr_grp(attr_type), data)
	return err
}
func ConntrackGetAttrGrpPtr(ct *Conntrack, attr_type ConntrackAttrGrp, data interface{}) error {
	v := reflect.ValueOf(data)
	if v.Kind() != reflect.Ptr {
		panic("pointer required for value")
	}
	return ConntrackGetAttrGrp(ct, attr_type, unsafe.Pointer(v.Pointer()))
}

// nfct_attr_grp_is_set - check if an attribute group is set
//
// int nfct_attr_grp_is_set(const struct nf_conntrack *ct,
//			    const enum nf_conntrack_attr_grp type)
func ConntrackAttrGrpIsSet(ct *Conntrack, attr_type ConntrackAttrGrp) (bool, error) {
	ret, err := C.nfct_attr_grp_is_set((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr_grp(attr_type))
	return ret > 0, err
}

// nfct_attr_grp_unset - unset an attribute group
//
// int nfct_attr_grp_unset(struct nf_conntrack *ct,
//			   const enum nf_conntrack_attr_grp type)
func ConntrackAttrGrpUnset(ct *Conntrack, attr_type ConntrackAttrGrp) error {
	_, err := C.nfct_attr_grp_unset((*C.struct_nf_conntrack)(ct), C.enum_nf_conntrack_attr_grp(attr_type))
	return err
}


// NO - Low level object to Netlink message
// NO - Send commands to kernel-space and receive replies

// Conntrack object handling

// nfct_snprintf - print a conntrack object to a buffer
//
// int nfct_snprintf(char *buf,
//		     unsigned int size,
//		     const struct nf_conntrack *ct,
//		     unsigned int msg_type,
//		     unsigned int out_type,
//		     unsigned int flags)
func ConntrackSnprintf(buf []byte, ct *Conntrack, msg_type ConntrackMsgType, out_type, flags uint) (int, error) {
	ret, err := C.nfct_snprintf((*C.char)(unsafe.Pointer(&buf[0])), C.uint(len(buf)), (*C.struct_nf_conntrack)(ct),
				    C.uint(msg_type), C.uint(out_type), C.uint(flags))
	return int(ret), err
}

// nfct_snprintf_labels - print a bitmask object to a buffer including labels
//
// int nfct_snprintf_labels(char *buf,
//			 unsigned int size,
//			 const struct nf_conntrack *ct,
//			 unsigned int msg_type,
//			 unsigned int out_type,
//			 unsigned int flags,
//			 struct nfct_labelmap *map)
func ConntrackSnprintfLabels(buf []byte, ct *Conntrack, msg_type, out_type, flags uint,
	label_map *Labelmap) (int, error) {
	ret, err := C.nfct_snprintf_labels((*C.char)(unsafe.Pointer(&buf[0])), C.uint(len(buf)), (*C.struct_nf_conntrack)(ct),
					   C.uint(msg_type), C.uint(out_type), C.uint(flags), (*C.struct_nfct_labelmap)(label_map))
	return int(ret), err
}

// nfct_compare - compare two conntrack objects

// nfct_cmp - compare two conntrack objects
//
// int nfct_cmp(const struct nf_conntrack *ct1,
//	        const struct nf_conntrack *ct2,
//	        unsigned int flags)
func ConntrackCmp(ct1, ct2 *Conntrack, flags uint) int {
	return int(C.nfct_cmp((*C.struct_nf_conntrack)(ct1), (*C.struct_nf_conntrack)(ct2), C.uint(flags)))
}

// nfct_copy - copy part of one source object to another
//
// void nfct_copy(struct nf_conntrack *ct1,
//	          const struct nf_conntrack *ct2,
//	          unsigned int flags)
func ConntrackCopy(ct1, ct2 *Conntrack, flags uint) {
	C.nfct_copy((*C.struct_nf_conntrack)(ct1), (*C.struct_nf_conntrack)(ct2), C.uint(flags))
}

// nfct_copy_attr - copy an attribute of one source object to another
//
// void nfct_copy_attr(struct nf_conntrack *ct1,
//		       const struct nf_conntrack *ct2,
//		       const enum nf_conntrack_attr type)
func ConntrackCopyAttr(ct1, ct2 *Conntrack, attr_type ConntrackAttr) {
	C.nfct_copy_attr((*C.struct_nf_conntrack)(ct1), (*C.struct_nf_conntrack)(ct2), C.enum_nf_conntrack_attr(attr_type))
}


// Kernel-space filtering for events

// nfct_filter_create - create a filter
//
// struct nfct_filter *nfct_filter_create(void)
func FilterCreate() (*Filter, error) {
	ret, err := C.nfct_filter_create()
	return (*Filter)(ret), err
}
func NewFilter() (*Filter, error) { return FilterCreate() }

// nfct_filter_destroy - destroy a filter
//
// void nfct_filter_destroy(struct nfct_filter *filter)
func FilterDestroy(filter *Filter) {
	C.nfct_filter_destroy((*C.struct_nfct_filter)(filter))
}

// nfct_filter_add_attr - add a filter attribute of the filter object
//
// void nfct_filter_add_attr(struct nfct_filter *filter,
//			     const enum nfct_filter_attr type,
//			     const void *value)
func FilterAddAttr(filter *Filter, attr_type FilterAttr, value unsafe.Pointer) error {
	if attr_type >= NFCT_FILTER_MAX {
		return syscall.EINVAL
	}
	C.nfct_filter_add_attr((*C.struct_nfct_filter)(filter), C.enum_nfct_filter_attr(attr_type), value)
	return nil
}
func FilterAddAttrPtr(filter *Filter, attr_type FilterAttr, value interface{}) error {
	v := reflect.ValueOf(value)
	if v.Kind() != reflect.Ptr {
		panic("pointer required for value")
	}
	return FilterAddAttr(filter, attr_type, unsafe.Pointer(v.Pointer()))
}

// nfct_filter_add_attr_u32 - add an u32 filter attribute of the filter object
//
// void nfct_filter_add_attr_u32(struct nfct_filter *filter,
//				 const enum nfct_filter_attr attr,
//				 const u_int32_t value);
func FilterAddAttrU32(filter *Filter, attr FilterAttr, value uint32) error {
	if attr >= NFCT_FILTER_MAX {
		return syscall.EINVAL
	}
	C.nfct_filter_add_attr_u32((*C.struct_nfct_filter)(filter), C.enum_nfct_filter_attr(attr), C.u_int32_t(value))
	return nil
}

// nfct_filter_set_logic - set the filter logic for an attribute type
//
// int nfct_filter_set_logic(struct nfct_filter *filter,
//			     const enum nfct_filter_attr attr,
//			     const enum nfct_filter_logic logic);
func FilterSetLogic(filter *Filter, attr FilterAttr, logic FilterLogic) (int, error) {
	ret, err := C.nfct_filter_set_logic((*C.struct_nfct_filter)(filter), C.enum_nfct_filter_attr(attr), C.enum_nfct_filter_logic(logic))
	return int(ret), err
}

// nfct_filter_attach - attach a filter to a socket descriptor
//
// int nfct_filter_attach(int fd, struct nfct_filter *filter);
func FilterAttach(fd int, filter *Filter) (int, error) {
	ret, err := C.nfct_filter_attach(C.int(fd), (*C.struct_nfct_filter)(filter))
	return int(ret), err
}

// nfct_filter_detach - detach an existing filter
//
// int nfct_filter_detach(int fd);
func FilterDetach(fd int) (int, error) {
	ret, err := C.nfct_filter_detach(C.int(fd))
	return int(ret), err
}


// dump filtering

// nfct_filter_dump_create - create a dump filter
//
// struct nfct_filter_dump *nfct_filter_dump_create(void);
func FilterDumpCreate() (*FilterDump, error) {
	ret, err := C.nfct_filter_dump_create()
	return (*FilterDump)(ret), err
}
func NewFilterDump() (*FilterDump, error) { return FilterDumpCreate() }

// nfct_filter_dump_destroy - destroy a dump filter
//
// void nfct_filter_dump_destroy(struct nfct_filter_dump *filter);
func FilterDumpDestroy(filter *FilterDump) {
	C.nfct_filter_dump_destroy((*C.struct_nfct_filter_dump)(filter))
}

// nfct_filter_dump_attr_set - set filter attribute
//
// void nfct_filter_dump_set_attr(struct nfct_filter_dump *filter_dump,
//				  const enum nfct_filter_dump_attr type,
//			          const void *data);
func FilterDumpSetAttr(filter_dump *FilterDump, attr_type FilterDumpAttr, data unsafe.Pointer) error {
	if attr_type >= NFCT_FILTER_DUMP_MAX {
		return syscall.EINVAL
	}
	C.nfct_filter_dump_set_attr((*C.struct_nfct_filter_dump)(filter_dump), C.enum_nfct_filter_dump_attr(attr_type), data)
	return nil
}
func FilterDumpSetAttrPtr(filter_dump *FilterDump, attr_type FilterDumpAttr, data interface{}) error {
	v := reflect.ValueOf(data)
	if v.Kind() != reflect.Ptr {
		panic("pointer required for value")
	}
	return FilterDumpSetAttr(filter_dump, attr_type, unsafe.Pointer(v.Pointer()))
}

// nfct_filter_dump_attr_set_u8 - set u8 dump filter attribute
//
// void nfct_filter_dump_set_attr_u8(struct nfct_filter_dump *filter_dump,
//				     const enum nfct_filter_dump_attr type,
//				     u_int8_t data);
func FilterDumpSetAttrU8(filter_dump *FilterDump, attr_type FilterDumpAttr, data uint8) error {
	if attr_type >= NFCT_FILTER_DUMP_MAX {
		return syscall.EINVAL
	}
	C.nfct_filter_dump_set_attr_u8((*C.struct_nfct_filter_dump)(filter_dump), C.enum_nfct_filter_dump_attr(attr_type), C.u_int8_t(data))
	return nil
}

// Conntrack labels

// nfct_labelmap_get_name - get name of the label bit
//
// const char *nfct_labelmap_get_name(struct nfct_labelmap *m, unsigned int bit)
func LabelmapGetName(m *Labelmap, bit uint) string {
	return C.GoString(C.nfct_labelmap_get_name((*C.struct_nfct_labelmap)(m), C.uint(bit)))
}

// nfct_labelmap_get_bit - get bit associated with the name
//
// int nfct_labelmap_get_bit(struct nfct_labelmap *m, const char *name)
func LabelmapGetBit(m *Labelmap, name string) int {
	cstr := C.CString(name)
	defer C.free(unsafe.Pointer(cstr))
	return int(C.nfct_labelmap_get_bit((*C.struct_nfct_labelmap)(m), cstr))
}

// nfct_labelmap_new - create a new label map
//
// struct nfct_labelmap *nfct_labelmap_new(const char *mapfile)
func LabelmapNew(mapfile string) (*Labelmap, error) {
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
func NewLabelmap(mapfile string) (*Labelmap, error) { return LabelmapNew(mapfile) }

// nfct_labelmap_destroy - destroy nfct_labelmap object
//
// void nfct_labelmap_destroy(struct nfct_labelmap *map)
func LabelmapDestroy(labelmap *Labelmap) {
	C.nfct_labelmap_destroy((*C.struct_nfct_labelmap)(labelmap))
}


// bitmask object

// nfct_bitmask_new - allocate a new bitmask
//
// struct nfct_bitmask *nfct_bitmask_new(unsigned int max)
func BitmaskNew(max uint) (*Bitmask, error) {
	ret, err := C.nfct_bitmask_new(C.uint(max))
	return (*Bitmask)(ret), err
}
func NewBitmask(max uint) (*Bitmask, error) { return BitmaskNew(max) }

// nfct_bitmask_clone - duplicate a bitmask object
//
// struct nfct_bitmask *nfct_bitmask_clone(const struct nfct_bitmask *b)
func BitmaskClone(b *Bitmask) (*Bitmask, error) {
	ret, err := C.nfct_bitmask_clone((*C.struct_nfct_bitmask)(b))
	return (*Bitmask)(ret), err
}

// nfct_bitmask_set_bit - set bit in the bitmask
//
// void nfct_bitmask_set_bit(struct nfct_bitmask *b, unsigned int bit)
func BitmaskSetBit(b *Bitmask, bit uint) {
	C.nfct_bitmask_set_bit((*C.struct_nfct_bitmask)(b), C.uint(bit))
}

// nfct_bitmask_test_bit - test if a bit in the bitmask is set
//
// int nfct_bitmask_test_bit(const struct nfct_bitmask *b, unsigned int bit)
func BitmaskTestBit(b *Bitmask, bit uint) int {
	return int(C.nfct_bitmask_test_bit((*C.struct_nfct_bitmask)(b), C.uint(bit)))
}

// nfct_bitmask_unset_bit - unset bit in the bitmask
//
// void nfct_bitmask_unset_bit(struct nfct_bitmask *b, unsigned int bit)
func BitmaskUnsetBit(b *Bitmask, bit uint) {
	C.nfct_bitmask_unset_bit((*C.struct_nfct_bitmask)(b), C.uint(bit))
}

// nfct_bitmask_maxbit - return highest bit that may be set/unset
//
// unsigned int nfct_bitmask_maxbit(const struct nfct_bitmask *b)
func BitmaskMaxbit(b *Bitmask) uint {
	return uint(C.nfct_bitmask_maxbit((*C.struct_nfct_bitmask)(b)))
}

// nfct_bitmask_destroy - destroy bitmask object
//
// void nfct_bitmask_destroy(struct nfct_bitmask *b)
func BitmaskDestroy(b *Bitmask) {
	C.nfct_bitmask_destroy((*C.struct_nfct_bitmask)(b))
}

// New low level API: netlink functions

// nfct_nlmsg_build - build a netlink message from a conntrack object
//
// int nfct_nlmsg_build(struct nlmsghdr *nlh, const struct nf_conntrack *ct);
func ConntrackNlmsgBuild(nlh *mnl.Nlmsghdr, ct *Conntrack) (int, error) {
	ret, err := C.nfct_nlmsg_build((*C.struct_nlmsghdr)(unsafe.Pointer(nlh)), (*C.struct_nf_conntrack)(ct))
	return int(ret), err
}

// nfct_nlmsg_parse - translate a netlink message to a conntrack object
//
// int nfct_nlmsg_parse(const struct nlmsghdr *nlh, struct nf_conntrack *ct);
func ConntrackNlmsgParse(nlh *mnl.Nlmsghdr, ct *Conntrack) (int, error) {
	ret, err := C.nfct_nlmsg_parse((*C.struct_nlmsghdr)(unsafe.Pointer(nlh)), (*C.struct_nf_conntrack)(ct))
	return int(ret), err
}

// nfct_payload_parse - translate a ... to a conntrack object
//
// int nfct_payload_parse(const void *payload, size_t payload_len, uint16_t l3num, struct nf_conntrack *ct);
func ConntrackPayloadParse(payload unsafe.Pointer, payload_len Size_t, l3num uint16, ct *Conntrack) (int, error) {
	ret, err := C.nfct_payload_parse(payload, C.size_t(payload_len), C.uint16_t(l3num), (*C.struct_nf_conntrack)(ct))
	return int(ret), err
}
func ConntrackPayloadParseBytes(payload []byte, l3num uint16, ct *Conntrack) (int, error) {
	ret, err := C.nfct_payload_parse(unsafe.Pointer(&payload[0]), C.size_t(len(payload)), C.uint16_t(l3num), (*C.struct_nf_conntrack)(ct))
	return int(ret), err
}

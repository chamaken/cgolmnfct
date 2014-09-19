package cgolmnfct_test

import (
	nfct "github.com/chamaken/cgolmnfct"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// almost just calling them
var _ = Describe("Cpylmnfct Expect", func() {
	fmt.Fprintf(os.Stdout, "Hello, expect tester!\n")

	Context("Construct and Destruct", func() {
		It("should success", func() {
			exp, err := nfct.NewExpect()
			defer exp.Destroy()
			Expect(err).To(BeNil())
		})
	})
	Context("Clone", func() {
		It("should have different addr", func() {
			exp, _ := nfct.NewExpect()
			defer exp.Destroy()
			clone, err := exp.Clone()
			Expect(err).To(BeNil())
			defer clone.Destroy()
			Expect(exp == clone).To(BeFalse())
		})
		It("should have same attr value", func() {
			exp, _ := nfct.NewExpect()
			defer exp.Destroy()
			exp.SetAttrU32(nfct.ATTR_EXP_TIMEOUT, 0x12345678)
			clone, err := exp.Clone()
			Expect(err).To(BeNil())
			defer clone.Destroy()
			v, _ := clone.AttrU32(nfct.ATTR_EXP_TIMEOUT)
			Expect(v).To(Equal(uint32(0x12345678)))
		})
	})
	Context("cmp", func() {
		It("shoule work with NFCT_CMP_STRING flag (XXX: no NFCT_CMP_MASK)", func() {
			s := "abcdefghijklmn"
			exp1, _ := nfct.NewExpect()
			defer exp1.Destroy()
			exp1.SetAttrU32(nfct.ATTR_EXP_TIMEOUT, 0x12345678)
			exp1.SetAttrU16(nfct.ATTR_EXP_ZONE, 0x4321)
			exp1.SetAttrU32(nfct.ATTR_EXP_FLAGS, 0x77777777)
			exp1.SetAttr(nfct.ATTR_EXP_FN, unsafe.Pointer(&s))

			exp2, _ := nfct.NewExpect()
			defer exp2.Destroy()
			exp2.SetAttrU32(nfct.ATTR_EXP_TIMEOUT, 0x12345678)
			exp2.SetAttrU16(nfct.ATTR_EXP_ZONE, 0x4321)
			exp2.SetAttrU32(nfct.ATTR_EXP_FLAGS, 0x55555555)
			exp2.SetAttrPtr(nfct.ATTR_EXP_FN, &s)

			Expect(exp1.Cmp(exp2, nfct.NFCT_CMP_STRICT)).To(BeZero())
			exp2.SetAttrU32(nfct.ATTR_EXP_FLAGS, 0x77777777)
			Expect(exp1.Cmp(exp2, nfct.NFCT_CMP_STRICT)).To(Equal(1))
		})
	})
	Context("attr set/get", func() {
		It("should set/get with raw value", func() {
			v1 := uint32(0x87654321)
			v2 := uint32(0x33333333)
			exp, _ := nfct.NewExpect()
			defer exp.Destroy()
			err := exp.SetAttr(nfct.ATTR_EXP_CLASS, unsafe.Pointer(&v1))
			Expect(err).To(BeNil())
			ret, err := exp.Attr(nfct.ATTR_EXP_CLASS)
			Expect(*((*uint32)(ret))).To(Equal(v1))
			err = exp.SetAttrPtr(nfct.ATTR_EXP_CLASS, &v2)
			Expect(err).To(BeNil())
			ret, err = exp.Attr(nfct.ATTR_EXP_CLASS)
			Expect(*((*uint32)(ret))).To(Equal(v2))

			err = exp.SetAttrPtr(nfct.ATTR_EXP_MAX, &v1)
			Expect(err).To(Equal(syscall.EINVAL))
			_, err = exp.Attr(nfct.ATTR_EXP_MAX)
			Expect(err).To(Equal(syscall.EINVAL))
		})
		It("should set/get with u8", func() {
			exp, _ := nfct.NewExpect()
			defer exp.Destroy()
			err := exp.SetAttrU8(nfct.ATTR_EXP_NAT_DIR, 127)
			Expect(err).To(BeNil())
			ret, err := exp.AttrU8(nfct.ATTR_EXP_NAT_DIR)
			Expect(err).To(BeNil())
			Expect(ret).To(Equal(uint8(127)))

			err = exp.SetAttrU8(nfct.ATTR_EXP_MAX, 127)
			Expect(err).To(Equal(syscall.EINVAL))
			_, err = exp.AttrU8(nfct.ATTR_EXP_MAX)
			Expect(err).To(Equal(syscall.EINVAL))
		})
		It("should set/get u16", func() {
			exp, _ := nfct.NewExpect()
			defer exp.Destroy()
			err := exp.SetAttrU16(nfct.ATTR_EXP_ZONE, 0x3333)
			Expect(err).To(BeNil())
			ret, err := exp.AttrU16(nfct.ATTR_EXP_ZONE)
			Expect(err).To(BeNil())
			Expect(ret).To(Equal(uint16(0x3333)))

			err = exp.SetAttrU16(nfct.ATTR_EXP_MAX, 0x3333)
			Expect(err).To(Equal(syscall.EINVAL))
			_, err = exp.AttrU16(nfct.ATTR_EXP_MAX)
			Expect(err).To(Equal(syscall.EINVAL))
		})
		It("should set/get u32", func() {
			exp, _ := nfct.NewExpect()
			defer exp.Destroy()
			err := exp.SetAttrU32(nfct.ATTR_EXP_CLASS, 0x13135757)
			Expect(err).To(BeNil())
			ret, err := exp.AttrU32(nfct.ATTR_EXP_CLASS)
			Expect(err).To(BeNil())
			Expect(ret).To(Equal(uint32(0x13135757)))

			err = exp.SetAttrU32(nfct.ATTR_EXP_MAX, 0x13135757)
			Expect(err).To(Equal(syscall.EINVAL))
			_, err = exp.AttrU32(nfct.ATTR_EXP_MAX)
			Expect(err).To(Equal(syscall.EINVAL))
		})
	})
	Context("attr set/unset", func() {
		It("should set/unset attrs", func() {
			exp, _ := nfct.NewExpect()
			exp.SetAttrU32(nfct.ATTR_EXP_TIMEOUT, 0x12345678)
			exp.SetAttrU16(nfct.ATTR_EXP_ZONE, 0x4321)
			ret, err := exp.AttrIsSet(nfct.ATTR_EXP_TIMEOUT)
			Expect(err).To(BeNil())
			Expect(ret).To(BeTrue())
			ret, err = exp.AttrIsSet(nfct.ATTR_EXP_ZONE)
			Expect(err).To(BeNil())
			Expect(ret).To(BeTrue())
			err = exp.AttrUnset(nfct.ATTR_EXP_TIMEOUT)
			Expect(err).To(BeNil())
			ret, err = exp.AttrIsSet(nfct.ATTR_EXP_TIMEOUT)
			Expect(err).To(BeNil())
			Expect(ret).To(BeFalse())
			ret, err = exp.AttrIsSet(nfct.ATTR_EXP_ZONE)
			Expect(err).To(BeNil())
			Expect(ret).To(BeTrue())

			err = exp.AttrUnset(nfct.ATTR_EXP_MAX)
			Expect(err).To(Equal(syscall.EINVAL))
			ret, err = exp.AttrIsSet(nfct.ATTR_EXP_MAX)
			Expect(err).To(Equal(syscall.EINVAL))
			Expect(ret).To(BeFalse())
		})
	})

	// XXX: Expect.snprintf
	// XXX: Expect.nlmsg_build
	// XXX: Expect.nlmsg_parse
})

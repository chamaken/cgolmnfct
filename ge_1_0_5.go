// +build ge_1_0_5

package cgolmnfct

/*
#cgo CFLAGS: -I./include
#cgo LDFLAGS: -lnetfilter_conntrack
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
*/
import "C"

// void nfct_bitmask_clear(struct nfct_bitmask *b)
func bitmaskClear(b *Bitmask) {
	C.nfct_bitmask_clear((*C.struct_nfct_bitmask)(b))
}

// bool nfct_bitmask_equal(const struct nfct_bitmask *b1, const struct nfct_bitmask *b2)
func bitmaskEqual(b1, b2 *Bitmask) bool {
	return (bool)(C.nfct_bitmask_equal((*C.struct_nfct_bitmask)(b1), (*C.struct_nfct_bitmask)(b2)))
}

// clear a bitmask object
func (b *Bitmask) Clear() {
	bitmaskClear(b)
}

// compare two bitmask objects
func (b *Bitmask) Equal(b2 *Bitmask) bool {
	return bitmaskEqual(b, b2)
}

// +build ge_1_0_6

package cgolmnfct

/*
#cgo CFLAGS: -I./include
#cgo LDFLAGS: -lnetfilter_conntrack
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
*/
import "C"

// const char *nfct_labels_get_path(void)
func LabelsGetPath() string {
	return C.GoString(C.nfct_labels_get_path())
}

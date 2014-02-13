package cgolmnfct_test

import (
	nfct "cgolmnfct"
	. "cgolmnfct/testlib"
	mnl "cgolmnl"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// almost just calling them
var _ = Describe("Cpylmnfct Conntrack", func() {
	fmt.Fprintf(os.Stdout, "Hello, conntrack tester!\n")
	var (
		nlmsgbuf10 []byte
		nlmsgbuf11 []byte
		nlmsgbuf20 []byte
		nlmsgbuf21 []byte
	)

	BeforeEach(func() {
		nlmsgbuf10 = []byte {
						// ----------------	------------------
			0xc4, 0x00, 0x00, 0x00,	// |  0000000196  |	| message length |
			0x02, 0x01, 0x00, 0x00,	// | 00258 | ---- |	|  type | flags  |	IPCTNL_MSG_CT_DELETE
			0x00, 0x00, 0x00, 0x00,	// |  0000000000  |	| sequence number|
			0x00, 0x00, 0x00, 0x00,	// |  0000000000  |	|     port ID    |
						// ----------------	------------------
			0x02, 0x00, 0x00, 0x00,	// | 02 00 00 00  |	|  extra header  |
			0x34, 0x00, 0x01, 0x80,	// |00052|N-|00001|	|len |flags| type|	+ CTA_TUPLE_ORIG
			0x14, 0x00, 0x01, 0x80,	// |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
			0x08, 0x00, 0x01, 0x00,	// |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
			0x01, 0x02, 0x03, 0x04,	// | 01 02 03 04  |	|      data      |
			0x08, 0x00, 0x02, 0x00,	// |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
			0xff, 0xfe, 0xfd, 0xfc,	// | ff fe fd fc  |	|      data      |
			0x1c, 0x00, 0x02, 0x80,	// |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
			0x05, 0x00, 0x01, 0x00,	// |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
			0x11, 0x00, 0x00, 0x00,	// | 11 00 00 00  |	|      data      |
			0x06, 0x00, 0x02, 0x00,	// |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
			0xf8, 0x8f, 0x00, 0x00,	// | f8 8f 00 00  |	|      data      |
			0x06, 0x00, 0x03, 0x00,	// |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
			0x00, 0x35, 0x00, 0x00,	// | 00 35 00 00  |	|      data      |
			0x34, 0x00, 0x02, 0x80,	// |00052|N-|00002|	|len |flags| type|	+ CTA_TUPLE_REPLY
			0x14, 0x00, 0x01, 0x80,	// |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
			0x08, 0x00, 0x01, 0x00,	// |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
			0xff, 0xfe, 0xfd, 0xfc,	// | ff fe fd fc  |	|      data      |
			0x08, 0x00, 0x02, 0x00,	// |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
			0x01, 0x02, 0x03, 0x04,	// | 01 02 03 04  |	|      data      |
			0x1c, 0x00, 0x02, 0x80,	// |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
			0x05, 0x00, 0x01, 0x00,	// |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
			0x11, 0x00, 0x00, 0x00,	// | 11 00 00 00  |	|      data      |
			0x06, 0x00, 0x02, 0x00,	// |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
			0x00, 0x35, 0x00, 0x00,	// | 00 35 00 00  |	|      data      |
			0x06, 0x00, 0x03, 0x00,	// |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
			0xf8, 0x8f, 0x00, 0x00,	// | f8 8f 00 00  |	|      data      |
			0x08, 0x00, 0x0c, 0x00,	// |00008|--|00012|	|len |flags| type|	CTA_ID *
			0x17, 0x6d, 0x0d, 0x78,	// | 17 6d 0d 78  |	|      data      |
			0x08, 0x00, 0x03, 0x00,	// |00008|--|00003|	|len |flags| type|	CTA_STATUS
			0x00, 0x00, 0x00, 0x08,	// | 00 00 00 08  |	|      data      |	  IPS_CONFIRMED
			0x1c, 0x00, 0x09, 0x80,	// |00028|N-|00009|	|len |flags| type|	+ CTA_COUNTERS_ORIG *
			0x0c, 0x00, 0x01, 0x00,	// |00012|--|00001|	|len |flags| type|	  CTA_COUNTERS_PACKETS
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x0c, 0x00, 0x02, 0x00,	// |00012|--|00002|	|len |flags| type|	  CTA_CONTERS_BYTES
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x1c, 0x00, 0x0a, 0x80,	// |00028|N-|00010|	|len |flags| type|	+ CTA_COUNTERS_REPLY *
			0x0c, 0x00, 0x01, 0x00,	// |00012|--|00001|	|len |flags| type|	  CTA_COUNTERS_PACKETS
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x0c, 0x00, 0x02, 0x00,	// |00012|--|00002|	|len |flags| type|	  CTA_CONTERS_BYTES
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
                }        	 		// ----------------	------------------

		nlmsgbuf11 = []byte {
						// ----------------	------------------
			0x84, 0x00, 0x00, 0x00,	// |  0000000132  |	| message length |
			0x02, 0x01, 0x00, 0x00,	// | 00258 | ---- |	|  type | flags  |	IPCTNL_MSG_CT_DELETE
			0x00, 0x00, 0x00, 0x00,	// |  0000000000  |	| sequence number|
			0x00, 0x00, 0x00, 0x00,	// |  0000000000  |	|     port ID    |
						// ----------------	------------------
			0x02, 0x00, 0x00, 0x00,	// | 02 00 00 00  |	|  extra header  |
			0x34, 0x00, 0x01, 0x80,	// |00052|N-|00001|	|len |flags| type|	+ CTA_TUPLE_ORIG
			0x14, 0x00, 0x01, 0x80,	// |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
			0x08, 0x00, 0x01, 0x00,	// |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
			0x01, 0x02, 0x03, 0x04,	// | 01 02 03 04  |	|      data      |
			0x08, 0x00, 0x02, 0x00,	// |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
			0xff, 0xfe, 0xfd, 0xfc,	// | ff fe fd fc  |	|      data      |
			0x1c, 0x00, 0x02, 0x80,	// |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
			0x05, 0x00, 0x01, 0x00,	// |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
			0x11, 0x00, 0x00, 0x00,	// | 11 00 00 00  |	|      data      |
			0x06, 0x00, 0x02, 0x00,	// |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
			0xf8, 0x8f, 0x00, 0x00,	// | f8 8f 00 00  |	|      data      |
			0x06, 0x00, 0x03, 0x00,	// |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
			0x00, 0x35, 0x00, 0x00,	// | 00 35 00 00  |	|      data      |
			0x34, 0x00, 0x02, 0x80,	// |00052|N-|00002|	|len |flags| type|	+ CTA_TUPLE_REPLY
			0x14, 0x00, 0x01, 0x80,	// |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
			0x08, 0x00, 0x01, 0x00,	// |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
			0xff, 0xfe, 0xfd, 0xfc,	// | ff fe fd fc  |	|      data      |
			0x08, 0x00, 0x02, 0x00,	// |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
			0x01, 0x02, 0x03, 0x04,	// | 01 02 03 04  |	|      data      |
			0x1c, 0x00, 0x02, 0x80,	// |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
			0x05, 0x00, 0x01, 0x00,	// |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
			0x11, 0x00, 0x00, 0x00,	// | 11 00 00 00  |	|      data      |
			0x06, 0x00, 0x02, 0x00,	// |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
			0x00, 0x35, 0x00, 0x00,	// | 00 35 00 00  |	|      data      |
			0x06, 0x00, 0x03, 0x00,	// |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
			0xf8, 0x8f, 0x00, 0x00,	// | f8 8f 00 00  |	|      data      |
			0x08, 0x00, 0x03, 0x00,	// |00008|--|00003|	|len |flags| type|	CTA_STATUS
			0x00, 0x00, 0x00, 0x08,	// | 00 00 00 08  |	|      data      |	  IPS_CONFIRMED
                }        	 		// ----------------	------------------

		nlmsgbuf20 = []byte{
						// ----------------	------------------
			0xdc, 0x00, 0x00, 0x00,	// |  0000000220  |	| message length |
			0x00, 0x01, 0x02, 0x00,	// | 00256 | -M-- |	|  type | flags  |
			0x00, 0x00, 0x00, 0x00,	// |  0000000000  |	| sequence number|
			0xca, 0x24, 0x00, 0x00,	// |  0000009418  |	|     port ID    |
						// ----------------	------------------
			0x02, 0x00, 0x00, 0x00,	// | 02 00 00 00  |	|  extra header  |
			0x34, 0x00, 0x01, 0x80,	// |00052|N-|00001|	|len |flags| type|	+ CTA_TUPLE_ORIG
			0x14, 0x00, 0x01, 0x80,	// |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
			0x08, 0x00, 0x01, 0x00,	// |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
			0x01, 0x01, 0x01, 0x01,	// | 01 01 01 01  |	|      data      |
			0x08, 0x00, 0x02, 0x00,	// |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
			0x02, 0x02, 0x02, 0x02,	// | 02 02 02 02  |	|      data      |
			0x1c, 0x00, 0x02, 0x80,	// |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
			0x05, 0x00, 0x01, 0x00,	// |00005|--|00001|	|len |flags| type|	    CTA_PTOTO_NUM
			0x11, 0x00, 0x00, 0x00,	// | 11 00 00 00  |	|      data      |
			0x06, 0x00, 0x02, 0x00,	// |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
			0x04, 0x64, 0x00, 0x00,	// | 04 64 00 00  |	|      data      |
			0x06, 0x00, 0x03, 0x00,	// |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
			0x00, 0xa1, 0x00, 0x00,	// | 00 a1 00 00  |	|      data      |
			0x34, 0x00, 0x02, 0x80,	// |00052|N-|00002|	|len |flags| type|	+ CTA_TUPLE_REPLY
			0x14, 0x00, 0x01, 0x80,	// |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
			0x08, 0x00, 0x01, 0x00,	// |00008|--|00001|	|len |flags| type|	    CTA_TUPLE_V4_SRC
			0x01, 0x01, 0x01, 0x01,	// | 01 01 01 01  |	|      data      |
			0x08, 0x00, 0x02, 0x00,	// |00008|--|00002|	|len |flags| type|	    CTA_TUP+E_V4_DST
			0x02, 0x02, 0x02, 0x02,	// | 02 02 02 02  |	|      data      |
			0x1c, 0x00, 0x02, 0x80,	// |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
			0x05, 0x00, 0x01, 0x00,	// |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
			0x11, 0x00, 0x00, 0x00,	// | 11 00 00 00  |	|      data      |
			0x06, 0x00, 0x02, 0x00,	// |00006|--|00002|	|len |flags| type|	    CTA_TUPLE_SRC_PORT
			0x00, 0xa1, 0x00, 0x00,	// | 00 a1 00 00  |	|      data      |
			0x06, 0x00, 0x03, 0x00,	// |00006|--|00003|	|len |flags| type|	    CTA_TUPLE_DST_PORT
			0x04, 0x64, 0x00, 0x00,	// | 04 64 00 00  |	|      data      |
			0x08, 0x00, 0x03, 0x00,	// |00008|--|00003|	|len |flags| type|	CTA_TUPLE_STATUS
			0x00, 0x00, 0x00, 0x0e,	// | 00 00 00 0e  |	|      data      |	  IPS_EXPECTED|SEEN_REPLY|ASSURED|CONFIRMED
			0x08, 0x00, 0x07, 0x00,	// |00008|--|00007|	|len |flags| type|	CTA_TIMEOUT
			0x00, 0x00, 0x00, 0x99,	// | 00 00 00 99  |	|      data      |
			0x1c, 0x00, 0x09, 0x80,	// |00028|N-|00009|	|len |flags| type|	+ CTA_COUNTERS_ORIG *
			0x0c, 0x00, 0x01, 0x00,	// |00012|--|00001|	|len |flags| type|	  CTA_COUNTERS_PACKETS
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x0c, 0x00, 0x02, 0x00,	// |00012|--|00002|	|len |flags| type|	  CTA_COUNTERS_BYTES
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x1c, 0x00, 0x0a, 0x80,	// |00028|N-|00010|	|len |flags| type|	+ CTA_COUNTERS_REPLY *
			0x0c, 0x00, 0x01, 0x00,	// |00012|--|00001|	|len |flags| type|	  CTA_COUNTERS_PACKETS
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x0c, 0x00, 0x02, 0x00,	// |00012|--|00002|	|len |flags| type|	  CTA_COUNTERS_BYTES
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x08, 0x00, 0x08, 0x00,	// |00008|--|00008|	|len |flags| type|	CTA_MARK
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x08, 0x00, 0x0c, 0x00,	// |00008|--|00012|	|len |flags| type|	CTA_ID *
			0x15, 0x50, 0xb8, 0xb8,	// | 15 50 b8 b8  |	|      data      |
			0x08, 0x00, 0x0b, 0x00,	// |00008|--|00011|	|len |flags| type|	CTA_USE
			0x00, 0x00, 0x00, 0x01,	// | 00 00 00 01  |	|      data      |
                				// ----------------	------------------
						// ----------------	------------------
			0x0c, 0x01, 0x00, 0x00,	// |  0000000268  |	| message length |
			0x00, 0x01, 0x02, 0x00,	// | 00256 | -M-- |	|  type | flags  |
			0x00, 0x00, 0x00, 0x00,	// |  0000000000  |	| sequence number|
			0xca, 0x24, 0x00, 0x00,	// |  0000009418  |	|     port ID    |
						// ----------------	------------------
			0x02, 0x00, 0x00, 0x00,	// | 02 00 00 00  |	|  extra header  |
			0x34, 0x00, 0x01, 0x80,	// |00052|N-|00001|	|len |flags| type|	+ CTA_TUPLE_ORIG
			0x14, 0x00, 0x01, 0x80,	// |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
			0x08, 0x00, 0x01, 0x00,	// |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
			0x03, 0x05, 0x05, 0x05,	// | 03 03 03 03  |	|      data      |
			0x08, 0x00, 0x02, 0x00,	// |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
			0x06, 0x06, 0x06, 0x06,	// | 04 04 04 04  |	|      data      |
			0x1c, 0x00, 0x02, 0x80,	// |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
			0x05, 0x00, 0x01, 0x00,	// |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
			0x06, 0x00, 0x00, 0x00,	// | 06 00 00 00  |	|      data      |
			0x06, 0x00, 0x02, 0x00,	// |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
			0xc1, 0x79, 0x00, 0x00,	// | c1 79 00 00  |	|      data      |
			0x06, 0x00, 0x03, 0x00,	// |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
			0x01, 0xbd, 0x00, 0x00,	// | 01 bd 00 00  |	|      data      |
			0x34, 0x00, 0x02, 0x80,	// |00052|N-|00002|	|len |flags| type|	  + CTA_TUPLE_REPLY
			0x14, 0x00, 0x01, 0x80,	// |00020|N-|00001|	|len |flags| type|	    + CTA_TUPLE_IP
			0x06, 0x06, 0x06, 0x06,	// |00008|--|00001|	|len |flags| type|	      CTA_IP_V4_SRC
			0x04, 0x04, 0x04, 0x04,	// | 04 04 04 04  |	|      data      |
			0x05, 0x05, 0x05, 0x05,	// |00008|--|00002|	|len |flags| type|	      CTA_IP_V4_DST
			0x03, 0x03, 0x03, 0x03,	// | 03 03 03 03  |	|      data      |
			0x1c, 0x00, 0x02, 0x80,	// |00028|N-|00002|	|len |flags| type|	    + CTA_TUPLE_PROTO
			0x05, 0x00, 0x01, 0x00,	// |00005|--|00001|	|len |flags| type|	      CTA_PROTO_NUM
			0x06, 0x00, 0x00, 0x00,	// | 06 00 00 00  |	|      data      |
			0x06, 0x00, 0x02, 0x00,	// |00006|--|00002|	|len |flags| type|	      CTA_PROTO_SRC_PORT
			0x01, 0xbd, 0x00, 0x00,	// | 01 bd 00 00  |	|      data      |
			0x06, 0x00, 0x03, 0x00,	// |00006|--|00003|	|len |flags| type|	      CTA_PROTO_DST_PORT
			0xc1, 0x79, 0x00, 0x00,	// | c1 79 00 00  |	|      data      |
			0x08, 0x00, 0x03, 0x00,	// |00008|--|00003|	|len |flags| type|	CTA_TUPLE_STATUS
			0x00, 0x00, 0x00, 0x0e,	// | 00 00 00 0e  |	|      data      |	  IPS_EXPECTED|SEEN_REPLY|ASSURED|CONFIRMED
			0x08, 0x00, 0x07, 0x00,	// |00008|--|00007|	|len |flags| type|	CTA_TIMEOUT
			0x00, 0x06, 0x97, 0x65,	// | 00 06 97 65  |	|      data      |
			0x1c, 0x00, 0x09, 0x80,	// |00028|N-|00009|	|len |flags| type|	+ CTA_COUNTERS_ORIG *
			0x0c, 0x00, 0x01, 0x00,	// |00012|--|00001|	|len |flags| type|	  CTA_COUNTERS_PACKETS
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x0c, 0x00, 0x02, 0x00,	// |00012|--|00002|	|len |flags| type|	  CTA_COUNTERS_BYTES
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x1c, 0x00, 0x0a, 0x80,	// |00028|N-|00010|	|len |flags| type|	+ CTA_COUNTERS_REPLY *
			0x0c, 0x00, 0x01, 0x00,	// |00012|--|00001|	|len |flags| type|	  CTA_COUNTERS_PACKETS
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x0c, 0x00, 0x02, 0x00,	// |00012|--|00002|	|len |flags| type|	  CTA_COUNTERS_BYTES
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x30, 0x00, 0x04, 0x80,	// |00048|N-|00004|	|len |flags| type|	+ CTA_PROTOINFO
			0x2c, 0x00, 0x01, 0x80,	// |00044|N-|00001|	|len |flags| type|	  + CTA_PROTOINFO_TCP
			0x05, 0x00, 0x01, 0x00,	// |00005|--|00001|	|len |flags| type|	    CTA_PROTOINFO_TCP_STATE
			0x03, 0x00, 0x00, 0x00,	// | 03 00 00 00  |	|      data      |
			0x05, 0x00, 0x02, 0x00,	// |00005|--|00002|	|len |flags| type|	    CTA_PROTOINFO_TCP_WSCALE_ORIGINAL
			0x02, 0x00, 0x00, 0x00,	// | 02 00 00 00  |	|      data      |
			0x05, 0x00, 0x03, 0x00,	// |00005|--|00003|	|len |flags| type|	    CTA_PROTOINFO_TCP_WSCALE_REPLY
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x06, 0x00, 0x04, 0x00,	// |00006|--|00004|	|len |flags| type|	    CTA_PROTOINFO_TCP_FLAGS_ORIGINAL
			0x23, 0x00, 0x00, 0x00,	// | 23 00 00 00  |	|      data      |
			0x06, 0x00, 0x05, 0x00,	// |00006|--|00005|	|len |flags| type|	    CTA_PROTOINFO_TCP_FLAGS_REPLY
			0x23, 0x00, 0x00, 0x00,	// | 23 00 00 00  |	|      data      |
			0x08, 0x00, 0x08, 0x00,	// |00008|--|00008|	|len |flags| type|	CTA_MARK
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x08, 0x00, 0x0c, 0x00,	// |00008|--|00012|	|len |flags| type|	CTA_ID *
			0x14, 0xcc, 0x56, 0x58,	// | 14 cc 56 58  |	|      data      |
			0x08, 0x00, 0x0b, 0x00,	// |00008|--|00011|	|len |flags| type|	CTA_USE
			0x00, 0x00, 0x00, 0x01,	// | 00 00 00 01  |	|      data      |
						// ----------------	------------------
						// ----------------	------------------
			0xdc, 0x00, 0x00, 0x00,	// |  0000000220  |	| message length |
			0x00, 0x01, 0x02, 0x00,	// | 00256 | -M-- |	|  type | flags  |
			0x00, 0x00, 0x00, 0x00,	// |  0000000000  |	| sequence number|
			0xca, 0x24, 0x00, 0x00,	// |  0000009418  |	|     port ID    |
						// ----------------	------------------
			0x02, 0x00, 0x00, 0x00,	// | 02 00 00 00  |	|  extra header  |
			0x34, 0x00, 0x01, 0x80,	// |00052|N-|00001|	|len |flags| type|	+ CTA_TUPLE_ORIG
			0x14, 0x00, 0x01, 0x80,	// |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
			0x08, 0x00, 0x01, 0x00,	// |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
			0x55, 0x55, 0x55, 0x55,	// | 55 55 55 55  |	|      data      |
			0x08, 0x00, 0x02, 0x00,	// |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
			0x66, 0x66, 0x66, 0x66,	// | 66 66 66 66  |	|      data      |
			0x1c, 0x00, 0x02, 0x80,	// |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
			0x05, 0x00, 0x01, 0x00,	// |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
			0x11, 0x00, 0x00, 0x00,	// | 11 00 00 00  |	|      data      |
			0x06, 0x00, 0x02, 0x00,	// |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
			0xca, 0xda, 0x00, 0x00,	// | ca da 00 00  |	|      data      |
			0x06, 0x00, 0x03, 0x00,	// |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
			0x02, 0x02, 0x00, 0x00,	// | 02 02 00 00  |	|      data      |
			0x34, 0x00, 0x02, 0x80,	// |00052|N-|00002|	|len |flags| type|	  + CTA_TUPLE_REPLY
			0x14, 0x00, 0x01, 0x80,	// |00020|N-|00001|	|len |flags| type|	    + CTA_TUPLE_IP
			0x08, 0x00, 0x01, 0x00,	// |00008|--|00001|	|len |flags| type|	      CTA_IP_V4_SRC
			0x66, 0x66, 0x66, 0x66,	// | 66 66 66 66  |	|      data      |
			0x08, 0x00, 0x02, 0x00,	// |00008|--|00002|	|len |flags| type|	      CTA_IP_V4_DST
			0x55, 0x55, 0x55, 0x55,	// | 55 55 55 55  |	|      data      |
			0x1c, 0x00, 0x02, 0x80,	// |00028|N-|00002|	|len |flags| type|	    + CTA_TUPLE_PROTO
			0x05, 0x00, 0x01, 0x00,	// |00005|--|00001|	|len |flags| type|	      CTA_PROTO_NUM
			0x11, 0x00, 0x00, 0x00,	// | 11 00 00 00  |	|      data      |
			0x06, 0x00, 0x02, 0x00,	// |00006|--|00002|	|len |flags| type|	      CTA_PROTO_SRC_PORT
			0x02, 0x02, 0x00, 0x00,	// | 02 02 00 00  |	|      data      |
			0x06, 0x00, 0x03, 0x00,	// |00006|--|00003|	|len |flags| type|	      CTA_PROTO_DST_PORT
			0xca, 0xda, 0x00, 0x00,	// | ca da 00 00  |	|      data      |
			0x08, 0x00, 0x03, 0x00,	// |00008|--|00003|	|len |flags| type|	CTA_TUPLE_STATUS
			0x00, 0x00, 0x00, 0x08,	// | 00 00 00 08  |	|      data      |	  IPS_CONFIRMED
			0x08, 0x00, 0x07, 0x00,	// |00008|--|00007|	|len |flags| type|	CTA_TIMEOUT
			0x00, 0x00, 0x00, 0x13,	// | 00 00 00 13  |	|      data      |
			0x1c, 0x00, 0x09, 0x80,	// |00028|N-|00009|	|len |flags| type|	+ CTA_COUNTERS_ORIG *
			0x0c, 0x00, 0x01, 0x00,	// |00012|--|00001|	|len |flags| type|	  CTA_COUNTERS_PACKETS
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x0c, 0x00, 0x02, 0x00,	// |00012|--|00002|	|len |flags| type|	  CTA_COUNTERS_BYTES
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x1c, 0x00, 0x0a, 0x80,	// |00028|N-|00010|	|len |flags| type|	+ CTA_COUNTERS_REPLY *
			0x0c, 0x00, 0x01, 0x00,	// |00012|--|00001|	|len |flags| type|	  CTA_COUNTERS_PACKETS
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |	  CTA_COUNTERS_BYTES
			0x0c, 0x00, 0x02, 0x00,	// |00012|--|00002|	|len |flags| type|
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x08, 0x00, 0x08, 0x00,	// |00008|--|00008|	|len |flags| type|	CTA_MARK
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x08, 0x00, 0x0c, 0x00,	// |00008|--|00012|	|len |flags| type|	CTA_ID *
			0x12, 0xd5, 0x69, 0xe8,	// | 12 d5 69 e8  |	|      data      |
			0x08, 0x00, 0x0b, 0x00,	// |00008|--|00011|	|len |flags| type|	CTA_USE
			0x00, 0x00, 0x00, 0x01,	// | 00 00 00 01  |	|      data      |
		}				// ----------------	------------------

		nlmsgbuf21 = []byte{
						// ----------------	------------------
			0x9c, 0x00, 0x00, 0x00,	// |  0000000156  |	| message length |
			0x00, 0x01, 0x02, 0x00,	// | 00256 | -M-- |	|  type | flags  |
			0x00, 0x00, 0x00, 0x00,	// |  0000000000  |	| sequence number|
			0xca, 0x24, 0x00, 0x00,	// |  0000009418  |	|     port ID    |
						// ----------------	------------------
			0x02, 0x00, 0x00, 0x00,	// | 02 00 00 00  |	|  extra header  |
			0x34, 0x00, 0x01, 0x80,	// |00052|N-|00001|	|len |flags| type|	+ CTA_TUPLE_ORIG
			0x14, 0x00, 0x01, 0x80,	// |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
			0x08, 0x00, 0x01, 0x00,	// |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
			0x01, 0x01, 0x01, 0x01,	// | 01 01 01 01  |	|      data      |
			0x08, 0x00, 0x02, 0x00,	// |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
			0x02, 0x02, 0x02, 0x02,	// | 02 02 02 02  |	|      data      |
			0x1c, 0x00, 0x02, 0x80,	// |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
			0x05, 0x00, 0x01, 0x00,	// |00005|--|00001|	|len |flags| type|	    CTA_PTOTO_NUM
			0x11, 0x00, 0x00, 0x00,	// | 11 00 00 00  |	|      data      |
			0x06, 0x00, 0x02, 0x00,	// |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
			0x04, 0x64, 0x00, 0x00,	// | 04 64 00 00  |	|      data      |
			0x06, 0x00, 0x03, 0x00,	// |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
			0x00, 0xa1, 0x00, 0x00,	// | 00 a1 00 00  |	|      data      |
			0x34, 0x00, 0x02, 0x80,	// |00052|N-|00002|	|len |flags| type|	+ CTA_TUPLE_REPLY
			0x14, 0x00, 0x01, 0x80,	// |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
			0x08, 0x00, 0x01, 0x00,	// |00008|--|00001|	|len |flags| type|	    CTA_TUPLE_V4_SRC
			0x01, 0x01, 0x01, 0x01,	// | 01 01 01 01  |	|      data      |
			0x08, 0x00, 0x02, 0x00,	// |00008|--|00002|	|len |flags| type|	    CTA_TUP+E_V4_DST
			0x02, 0x02, 0x02, 0x02,	// | 02 02 02 02  |	|      data      |
			0x1c, 0x00, 0x02, 0x80,	// |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
			0x05, 0x00, 0x01, 0x00,	// |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
			0x11, 0x00, 0x00, 0x00,	// | 11 00 00 00  |	|      data      |
			0x06, 0x00, 0x02, 0x00,	// |00006|--|00002|	|len |flags| type|	    CTA_TUPLE_SRC_PORT
			0x00, 0xa1, 0x00, 0x00,	// | 00 a1 00 00  |	|      data      |
			0x06, 0x00, 0x03, 0x00,	// |00006|--|00003|	|len |flags| type|	    CTA_TUPLE_DST_PORT
			0x04, 0x64, 0x00, 0x00,	// | 04 64 00 00  |	|      data      |
			0x08, 0x00, 0x03, 0x00,	// |00008|--|00003|	|len |flags| type|	CTA_TUPLE_STATUS
			0x00, 0x00, 0x00, 0x0e,	// | 00 00 00 0e  |	|      data      |	  IPS_EXPECTED|SEEN_REPLY|ASSURED|CONFIRMED
			0x08, 0x00, 0x07, 0x00,	// |00008|--|00007|	|len |flags| type|	CTA_TIMEOUT
			0x00, 0x00, 0x00, 0x99,	// | 00 00 00 99  |	|      data      |
			0x08, 0x00, 0x08, 0x00,	// |00008|--|00008|	|len |flags| type|	CTA_MARK
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x08, 0x00, 0x0b, 0x00,	// |00008|--|00011|	|len |flags| type|	CTA_USE
			0x00, 0x00, 0x00, 0x01,	// | 00 00 00 01  |	|      data      |
                				// ----------------	------------------
						// ----------------	------------------
			0xcc, 0x00, 0x00, 0x00,	// |  0000000204  |	| message length |
			0x00, 0x01, 0x02, 0x00,	// | 00256 | -M-- |	|  type | flags  |
			0x00, 0x00, 0x00, 0x00,	// |  0000000000  |	| sequence number|
			0xca, 0x24, 0x00, 0x00,	// |  0000009418  |	|     port ID    |
						// ----------------	------------------
			0x02, 0x00, 0x00, 0x00,	// | 02 00 00 00  |	|  extra header  |
			0x34, 0x00, 0x01, 0x80,	// |00052|N-|00001|	|len |flags| type|	+ CTA_TUPLE_ORIG
			0x14, 0x00, 0x01, 0x80,	// |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
			0x08, 0x00, 0x01, 0x00,	// |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
			0x03, 0x05, 0x05, 0x05,	// | 03 03 03 03  |	|      data      |
			0x08, 0x00, 0x02, 0x00,	// |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
			0x06, 0x06, 0x06, 0x06,	// | 04 04 04 04  |	|      data      |
			0x1c, 0x00, 0x02, 0x80,	// |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
			0x05, 0x00, 0x01, 0x00,	// |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
			0x06, 0x00, 0x00, 0x00,	// | 06 00 00 00  |	|      data      |
			0x06, 0x00, 0x02, 0x00,	// |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
			0xc1, 0x79, 0x00, 0x00,	// | c1 79 00 00  |	|      data      |
			0x06, 0x00, 0x03, 0x00,	// |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
			0x01, 0xbd, 0x00, 0x00,	// | 01 bd 00 00  |	|      data      |
			0x34, 0x00, 0x02, 0x80,	// |00052|N-|00002|	|len |flags| type|	  + CTA_TUPLE_REPLY
			0x14, 0x00, 0x01, 0x80,	// |00020|N-|00001|	|len |flags| type|	    + CTA_TUPLE_IP
			0x06, 0x06, 0x06, 0x06,	// |00008|--|00001|	|len |flags| type|	      CTA_IP_V4_SRC
			0x04, 0x04, 0x04, 0x04,	// | 04 04 04 04  |	|      data      |
			0x05, 0x05, 0x05, 0x05,	// |00008|--|00002|	|len |flags| type|	      CTA_IP_V4_DST
			0x03, 0x03, 0x03, 0x03,	// | 03 03 03 03  |	|      data      |
			0x1c, 0x00, 0x02, 0x80,	// |00028|N-|00002|	|len |flags| type|	    + CTA_TUPLE_PROTO
			0x05, 0x00, 0x01, 0x00,	// |00005|--|00001|	|len |flags| type|	      CTA_PROTO_NUM
			0x06, 0x00, 0x00, 0x00,	// | 06 00 00 00  |	|      data      |
			0x06, 0x00, 0x02, 0x00,	// |00006|--|00002|	|len |flags| type|	      CTA_PROTO_SRC_PORT
			0x01, 0xbd, 0x00, 0x00,	// | 01 bd 00 00  |	|      data      |
			0x06, 0x00, 0x03, 0x00,	// |00006|--|00003|	|len |flags| type|	      CTA_PROTO_DST_PORT
			0xc1, 0x79, 0x00, 0x00,	// | c1 79 00 00  |	|      data      |
			0x08, 0x00, 0x03, 0x00,	// |00008|--|00003|	|len |flags| type|	CTA_TUPLE_STATUS
			0x00, 0x00, 0x00, 0x0e,	// | 00 00 00 0e  |	|      data      |	  IPS_EXPECTED|SEEN_REPLY|ASSURED|CONFIRMED
			0x08, 0x00, 0x07, 0x00,	// |00008|--|00007|	|len |flags| type|	CTA_TIMEOUT
			0x00, 0x06, 0x97, 0x65,	// | 00 06 97 65  |	|      data      |
			0x30, 0x00, 0x04, 0x80,	// |00048|N-|00004|	|len |flags| type|	+ CTA_PROTOINFO
			0x2c, 0x00, 0x01, 0x80,	// |00044|N-|00001|	|len |flags| type|	  + CTA_PROTOINFO_TCP
			0x05, 0x00, 0x01, 0x00,	// |00005|--|00001|	|len |flags| type|	    CTA_PROTOINFO_TCP_STATE
			0x03, 0x00, 0x00, 0x00,	// | 03 00 00 00  |	|      data      |
			0x05, 0x00, 0x02, 0x00,	// |00005|--|00002|	|len |flags| type|	    CTA_PROTOINFO_TCP_WSCALE_ORIGINAL
			0x02, 0x00, 0x00, 0x00,	// | 02 00 00 00  |	|      data      |
			0x05, 0x00, 0x03, 0x00,	// |00005|--|00003|	|len |flags| type|	    CTA_PROTOINFO_TCP_WSCALE_REPLY
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x06, 0x00, 0x04, 0x00,	// |00006|--|00004|	|len |flags| type|	    CTA_PROTOINFO_TCP_FLAGS_ORIGINAL
			0x23, 0x00, 0x00, 0x00,	// | 23 00 00 00  |	|      data      |
			0x06, 0x00, 0x05, 0x00,	// |00006|--|00005|	|len |flags| type|	    CTA_PROTOINFO_TCP_FLAGS_REPLY
			0x23, 0x00, 0x00, 0x00,	// | 23 00 00 00  |	|      data      |
			0x08, 0x00, 0x08, 0x00,	// |00008|--|00008|	|len |flags| type|	CTA_MARK
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x08, 0x00, 0x0b, 0x00,	// |00008|--|00011|	|len |flags| type|	CTA_USE
			0x00, 0x00, 0x00, 0x01,	// | 00 00 00 01  |	|      data      |
						// ----------------	------------------
						// ----------------	------------------
			0x9c, 0x00, 0x00, 0x00,	// |  0000000156  |	| message length |
			0x00, 0x01, 0x02, 0x00,	// | 00256 | -M-- |	|  type | flags  |
			0x00, 0x00, 0x00, 0x00,	// |  0000000000  |	| sequence number|
			0xca, 0x24, 0x00, 0x00,	// |  0000009418  |	|     port ID    |
						// ----------------	------------------
			0x02, 0x00, 0x00, 0x00,	// | 02 00 00 00  |	|  extra header  |
			0x34, 0x00, 0x01, 0x80,	// |00052|N-|00001|	|len |flags| type|	+ CTA_TUPLE_ORIG
			0x14, 0x00, 0x01, 0x80,	// |00020|N-|00001|	|len |flags| type|	  + CTA_TUPLE_IP
			0x08, 0x00, 0x01, 0x00,	// |00008|--|00001|	|len |flags| type|	    CTA_IP_V4_SRC
			0x55, 0x55, 0x55, 0x55,	// | 55 55 55 55  |	|      data      |
			0x08, 0x00, 0x02, 0x00,	// |00008|--|00002|	|len |flags| type|	    CTA_IP_V4_DST
			0x66, 0x66, 0x66, 0x66,	// | 66 66 66 66  |	|      data      |
			0x1c, 0x00, 0x02, 0x80,	// |00028|N-|00002|	|len |flags| type|	  + CTA_TUPLE_PROTO
			0x05, 0x00, 0x01, 0x00,	// |00005|--|00001|	|len |flags| type|	    CTA_PROTO_NUM
			0x11, 0x00, 0x00, 0x00,	// | 11 00 00 00  |	|      data      |
			0x06, 0x00, 0x02, 0x00,	// |00006|--|00002|	|len |flags| type|	    CTA_PROTO_SRC_PORT
			0xca, 0xda, 0x00, 0x00,	// | ca da 00 00  |	|      data      |
			0x06, 0x00, 0x03, 0x00,	// |00006|--|00003|	|len |flags| type|	    CTA_PROTO_DST_PORT
			0x02, 0x02, 0x00, 0x00,	// | 02 02 00 00  |	|      data      |
			0x34, 0x00, 0x02, 0x80,	// |00052|N-|00002|	|len |flags| type|	  + CTA_TUPLE_REPLY
			0x14, 0x00, 0x01, 0x80,	// |00020|N-|00001|	|len |flags| type|	    + CTA_TUPLE_IP
			0x08, 0x00, 0x01, 0x00,	// |00008|--|00001|	|len |flags| type|	      CTA_IP_V4_SRC
			0x66, 0x66, 0x66, 0x66,	// | 66 66 66 66  |	|      data      |
			0x08, 0x00, 0x02, 0x00,	// |00008|--|00002|	|len |flags| type|	      CTA_IP_V4_DST
			0x55, 0x55, 0x55, 0x55,	// | 55 55 55 55  |	|      data      |
			0x1c, 0x00, 0x02, 0x80,	// |00028|N-|00002|	|len |flags| type|	    + CTA_TUPLE_PROTO
			0x05, 0x00, 0x01, 0x00,	// |00005|--|00001|	|len |flags| type|	      CTA_PROTO_NUM
			0x11, 0x00, 0x00, 0x00,	// | 11 00 00 00  |	|      data      |
			0x06, 0x00, 0x02, 0x00,	// |00006|--|00002|	|len |flags| type|	      CTA_PROTO_SRC_PORT
			0x02, 0x02, 0x00, 0x00,	// | 02 02 00 00  |	|      data      |
			0x06, 0x00, 0x03, 0x00,	// |00006|--|00003|	|len |flags| type|	      CTA_PROTO_DST_PORT
			0xca, 0xda, 0x00, 0x00,	// | ca da 00 00  |	|      data      |
			0x08, 0x00, 0x03, 0x00,	// |00008|--|00003|	|len |flags| type|	CTA_TUPLE_STATUS
			0x00, 0x00, 0x00, 0x08,	// | 00 00 00 08  |	|      data      |	  IPS_CONFIRMED
			0x08, 0x00, 0x07, 0x00,	// |00008|--|00007|	|len |flags| type|	CTA_TIMEOUT
			0x00, 0x00, 0x00, 0x13,	// | 00 00 00 13  |	|      data      |
			0x08, 0x00, 0x08, 0x00,	// |00008|--|00008|	|len |flags| type|	CTA_MARK
			0x00, 0x00, 0x00, 0x00,	// | 00 00 00 00  |	|      data      |
			0x08, 0x00, 0x0b, 0x00,	// |00008|--|00011|	|len |flags| type|	CTA_USE
			0x00, 0x00, 0x00, 0x01,	// | 00 00 00 01  |	|      data      |
		}				// ----------------	------------------
	})

	Context("Construct and Destruct", func() {
		It("should success", func() {
			ct, err := nfct.NewConntrack()
			defer ct.Destroy()
			Expect(err).To(BeNil())
		})
	})

	Context("Clone", func() {
		It("should have different addr", func() {
			ct, _ := nfct.NewConntrack()
			defer ct.Destroy()
			clone, err := ct.Clone()
			Expect(err).To(BeNil())
			defer clone.Destroy()
			Expect(ct == clone).To(BeFalse())
		})
		It("should have same attr value", func() {
			ct, _ := nfct.NewConntrack()
			defer ct.Destroy()
			ct.SetAttrU8(nfct.ATTR_ORIG_L3PROTO, 11)
			clone, err := ct.Clone()
			Expect(err).To(BeNil())
			defer clone.Destroy()
			v, _ := clone.AttrU8(nfct.ATTR_ORIG_L3PROTO)
			Expect(v).To(Equal(uint8(11)))
		})
	})
	Context("Objopt", func() {
		It("should same - set/get", func() {
			ct, _ := nfct.NewConntrack()
			defer ct.Destroy()
			// ct.SetAttrU32(nfct.ATTR_STATUS, IPS_SRC_NAT_DONE)
			ct.SetAttrU32(nfct.ATTR_REPL_IPV4_DST, 1)
			opt, err := ct.Objopt(nfct.NFCT_GOPT_IS_SNAT)
			Expect(err).To(BeNil())
			Expect(opt).To(Equal(1))

			err = ct.Setobjopt(nfct.NFCT_SOPT_UNDO_SNAT)
			Expect(err).To(BeNil())

			opt, err = ct.Objopt(nfct.NFCT_GOPT_IS_SNAT)
			Expect(err).To(BeNil())
			Expect(opt).To(Equal(0))
		})
	})
	Context("Attr", func() {
		It("should have set by set_l", func() {
			var attr1, attr2 uint32
			attr1 = 0x12345678
			ct, _ := nfct.NewConntrack()
			defer ct.Destroy()
			err := ct.SetAttrL(nfct.ATTR_ORIG_IPV4_SRC, unsafe.Pointer(&attr1), 4)
			Expect(err).To(BeNil())
			p, _ := ct.Attr(nfct.ATTR_ORIG_IPV4_SRC)
			attr2 = *((*uint32)(p))
			// attr2, _ = ct.AttrU32(nfct.ATTR_ORIG_IPV4_SRC)
			Expect(attr2).To(Equal(attr1))

			attr1 = 0x9abcdef0
			err = ct.SetAttrLPtr(nfct.ATTR_ORIG_IPV4_SRC, &attr1)
			Expect(err).To(BeNil())
			p, _ = ct.Attr(nfct.ATTR_ORIG_IPV4_SRC)
			attr2 = *((*uint32)(p))
			// attr2, _ = ct.AttrU32(nfct.ATTR_ORIG_IPV4_SRC)
			Expect(attr2).To(Equal(attr1))
		})
		It("should set/get by simple set/get", func() {
			var attr1, attr2 uint32
			attr1 = 0x12345678
			ct, _ := nfct.NewConntrack()
			defer ct.Destroy()
			err := ct.SetAttr(nfct.ATTR_ORIG_IPV4_SRC, unsafe.Pointer(&attr1))
			Expect(err).To(BeNil())
			p, err := ct.Attr(nfct.ATTR_ORIG_IPV4_SRC)
			Expect(err).To(BeNil())
			attr2 = *((*uint32)(p))
			Expect(attr2).To(Equal(attr1))

			attr1 = 0x9abcdef0
			err = ct.SetAttrPtr(nfct.ATTR_ORIG_IPV4_SRC, &attr1)
			Expect(err).To(BeNil())
			p, _ = ct.Attr(nfct.ATTR_ORIG_IPV4_SRC)
			attr2 = *((*uint32)(p))
			Expect(attr2).To(Equal(attr1))
		})
		It("should set/get u8", func() {
			ct, _ := nfct.NewConntrack()
			defer ct.Destroy()
			err := ct.SetAttrU8(nfct.ATTR_ORIG_L3PROTO, 123)
			Expect(err).To(BeNil())
			ret, err := ct.AttrU8(nfct.ATTR_ORIG_L3PROTO)
			Expect(err).To(BeNil())
			Expect(ret).To(Equal(uint8(123)))
		})
		It("should set/get u16", func() {
			ct, _ := nfct.NewConntrack()
			defer ct.Destroy()
			err := ct.SetAttrU16(nfct.ATTR_ORIG_PORT_SRC, 0x1234)
			Expect(err).To(BeNil())
			ret, err := ct.AttrU16(nfct.ATTR_ORIG_PORT_SRC)
			Expect(err).To(BeNil())
			Expect(ret).To(Equal(uint16(0x1234)))
		})
		It("should set/get u32", func() {
			ct, _ := nfct.NewConntrack()
			defer ct.Destroy()
			err := ct.SetAttrU32(nfct.ATTR_ORIG_IPV4_DST, 0x12345678)
			Expect(err).To(BeNil())
			ret, err := ct.AttrU32(nfct.ATTR_ORIG_IPV4_DST)
			Expect(err).To(BeNil())
			Expect(ret).To(Equal(uint32(0x12345678)))
		})
		It("should set/get u64", func() {
			ct, _ := nfct.NewConntrack()
			defer ct.Destroy()
			err := ct.SetAttrU64(nfct.ATTR_DCCP_HANDSHAKE_SEQ, 0x123456789abcdef0)
			Expect(err).To(BeNil())
			ret, err := ct.AttrU64(nfct.ATTR_DCCP_HANDSHAKE_SEQ)
			Expect(err).To(BeNil())
			Expect(ret).To(Equal(uint64(0x123456789abcdef0)))
		})
		It("should true set attr", func() {
			ct, _ := nfct.NewConntrack()
			defer ct.Destroy()
			ct.SetAttrU64(nfct.ATTR_DCCP_HANDSHAKE_SEQ, 0x123456789abcdef0)
			ret, err := ct.AttrIsSet(nfct.ATTR_DCCP_HANDSHAKE_SEQ)
			Expect(err).To(BeNil())
			Expect(ret).To(BeTrue())
			ret, err = ct.AttrIsSet(nfct.ATTR_ORIG_COUNTER_PACKETS)
			Expect(err).To(BeNil())
			Expect(ret).To(BeFalse())
		})
		It("should true set attrs", func() {
			ct, _ := nfct.NewConntrack()
			defer ct.Destroy()
			a := []nfct.ConntrackAttr{nfct.ATTR_ORIG_L3PROTO, nfct.ATTR_ORIG_PORT_SRC,
				nfct.ATTR_ORIG_IPV4_DST, nfct.ATTR_ORIG_COUNTER_PACKETS}
			ct.SetAttrU8(nfct.ATTR_ORIG_L3PROTO, 123)
			ct.SetAttrU16(nfct.ATTR_ORIG_PORT_SRC, 0x1234)
			ct.SetAttrU32(nfct.ATTR_ORIG_IPV4_DST, 0x12345678)
			ret, err := ct.AttrIsSetArray(a[:3])
			Expect(err).To(BeNil())
			Expect(ret).To(BeTrue())
			ret, err = ct.AttrIsSetArray(a)
			Expect(err).To(BeNil())
			Expect(ret).To(BeFalse())
		})
		It("should unset", func() {
			ct, _ := nfct.NewConntrack()
			ct.Destroy()
			ct.SetAttrU8(nfct.ATTR_ORIG_L3PROTO, 123)
			ret, _ := ct.AttrIsSet(nfct.ATTR_ORIG_L3PROTO)
			Expect(ret).To(BeTrue())
			err := ct.AttrUnset(nfct.ATTR_ORIG_L3PROTO)
			Expect(err).To(BeNil())
			ret, _ = ct.AttrIsSet(nfct.ATTR_ORIG_L3PROTO)
			Expect(ret).To(BeFalse())
		})
	})
	Context("Attr group", func() {
		var grp1, grp2 *nfct.AttrGrpIpv4
		BeforeEach(func () {
			grp1 = &nfct.AttrGrpIpv4{Src: 0x12345678, Dst: 0x9abcdef0}
			grp2 = &nfct.AttrGrpIpv4{}
		})
		It("shoule set/get group", func() {
			ct, _ := nfct.NewConntrack()
			defer ct.Destroy()
			err := ct.SetAttrGrp(nfct.ATTR_GRP_ORIG_IPV4, unsafe.Pointer(grp1))
			Expect(err).To(BeNil())
			err = ct.AttrGrp(nfct.ATTR_GRP_ORIG_IPV4, unsafe.Pointer(grp2))
			Expect(err).To(BeNil())
			Expect(*grp2).To(Equal(*grp1))

			err = ct.SetAttrGrpPtr(nfct.ATTR_GRP_REPL_IPV4, grp1)
			Expect(err).To(BeNil())
			err = ct.AttrGrpPtr(nfct.ATTR_GRP_REPL_IPV4, grp2)
			Expect(err).To(BeNil())
			Expect(*grp2).To(Equal(*grp1))
		})
		It("should be able to unset", func() {
			ct, _ := nfct.NewConntrack()
			defer ct.Destroy()
			err := ct.SetAttrGrp(nfct.ATTR_GRP_ORIG_IPV4, unsafe.Pointer(grp1))
			Expect(err).To(BeNil())
			ret, err := ct.AttrGrpIsSet(nfct.ATTR_GRP_ORIG_IPV4)
			Expect(err).To(BeNil())
			Expect(ret).To(BeTrue())
			err = ct.AttrGrpUnset(nfct.ATTR_GRP_ORIG_IPV4)
			Expect(err).To(BeNil())
			ret, err = ct.AttrGrpIsSet(nfct.ATTR_GRP_ORIG_IPV4)
			Expect(err).To(BeNil())
			Expect(ret).To(BeFalse())
		})
	})
	Context("cmp", func() {
		It("shoule work with NFCT_CMP_ALL and STRICT flag", func() {
			ct1, _ := nfct.NewConntrack()
			defer ct1.Destroy()
			ct2, _ := nfct.NewConntrack()
			defer ct2.Destroy()
			grp := &nfct.AttrGrpIpv4{Src: 0x12345678, Dst: 0x9abcdef0}

			ct1.SetAttrGrpPtr(nfct.ATTR_GRP_ORIG_IPV4, grp)
			ct1.SetAttrU8(nfct.ATTR_ORIG_L3PROTO, 123)
			ct1.SetAttrU16(nfct.ATTR_ORIG_PORT_SRC, 0x1234)
			ct1.SetAttrU32(nfct.ATTR_ORIG_IPV4_DST, 0x12345678)
			ct1.SetAttrU64(nfct.ATTR_ID, 0xabcdef) // STRICT is only for meta

			ct2.SetAttrGrpPtr(nfct.ATTR_GRP_ORIG_IPV4, grp)
			ct2.SetAttrU8(nfct.ATTR_ORIG_L3PROTO, 123)
			ct2.SetAttrU16(nfct.ATTR_ORIG_PORT_SRC, 0x1234)
			ct2.SetAttrU32(nfct.ATTR_ORIG_IPV4_DST, 0x87654321)

			Expect(ct1.Cmp(ct2, nfct.NFCT_CMP_ALL)).To(BeZero())
			ct2.SetAttrU32(nfct.ATTR_ORIG_IPV4_DST, 0x12345678)
			Expect(ct1.Cmp(ct2, nfct.NFCT_CMP_ALL)).To(Equal(1))

			Expect(ct1.Cmp(ct2, nfct.NFCT_CMP_STRICT)).To(BeZero())
			ct2.SetAttrU64(nfct.ATTR_ID, 0xabcdef)
			Expect(ct1.Cmp(ct2, nfct.NFCT_CMP_STRICT)).To(Equal(1))
		})
	})
	Context("copy", func() {
		It("should have same attrs", func() {
			ct1, _ := nfct.NewConntrack()
			defer ct1.Destroy()
			ct2, _ := nfct.NewConntrack()
			defer ct2.Destroy()

			ct1.SetAttrU8(nfct.ATTR_ORIG_L3PROTO, 123)
			ct1.SetAttrU16(nfct.ATTR_ORIG_PORT_SRC, 0x1234)
			ct1.Copy(ct2, nfct.NFCT_CP_ALL)
			ret8, _ := ct2.AttrU8(nfct.ATTR_ORIG_L3PROTO)
			Expect(ret8).To(Equal(uint8(123)))
			ret16, _ := ct2.AttrU16(nfct.ATTR_ORIG_PORT_SRC)
			Expect(ret16).To(Equal(uint16(0x1234)))
		})
		It("shoule copy only specified attr", func() {
			ct1, _ := nfct.NewConntrack()
			defer ct1.Destroy()
			ct2, _ := nfct.NewConntrack()
			defer ct2.Destroy()

			ct1.SetAttrU8(nfct.ATTR_ORIG_L3PROTO, 123)
			ct1.SetAttrU16(nfct.ATTR_ORIG_PORT_SRC, 0x1234)
			ct1.CopyAttr(ct2, nfct.ATTR_ORIG_L3PROTO)

			ret8, _ := ct2.AttrU8(nfct.ATTR_ORIG_L3PROTO)
			Expect(ret8).To(Equal(uint8(123)))
			_, err := ct2.AttrU16(nfct.ATTR_ORIG_PORT_SRC)
			Expect(err).To(Equal(syscall.ENODATA))
		})
	})
	Context("parse and build", func() {
		It("should have same value", func() {
			ct, _ := nfct.NewConntrack()
			defer ct.Destroy()
			nlh := mnl.NlmsghdrBytes(nlmsgbuf10)
			ret, err := ct.NlmsgParse(nlh)
			Expect(ret).To(Equal(0))
			Expect(err).To(BeNil())

			nlh, _ = mnl.PutNewNlmsghdr(1024)
			nlh.Type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE
			nlh.Flags = 0
			nlh.Seq = 0
			nlh.Pid = 0
			nfh := (*Nfgenmsg)(nlh.PutExtraHeader(SizeofNfgenmsg))
			nfh.Nfgen_family = AF_INET
			nfh.Version = NFNETLINK_V0
			nfh.Res_id = 0

			ret, err = ct.NlmsgBuild(nlh)
			Expect(ret).To(Equal(0))
			Expect(err).To(BeNil())
			b, _ := nlh.MarshalBinary()
			Expect(b).To(Equal(nlmsgbuf11))
		})
	})
})

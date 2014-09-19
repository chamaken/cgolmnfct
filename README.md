cgolmnfct
=========

Go wrapper of libnetfilter_conntrack subset using cgo, under heavy development


sample
------

see examples


installation
------------

Need running ``mktypes.sh'' before build.

Need delete tesglib/types_linux.go or comment out the lines on testing
I do not know how to avoid this...


requires
--------

  * libmnl, libnetfilter_conntrack

  * cgolmnl (https://github.com/chamaken/cgolmnl)


links
-----

* libmnl: http://netfilter.org/projects/libmnl/

* libnetfilter_conntrack: http://netfilter.org/projects/libnetfilter_conntrack/



struct
------

All of internal structs are opaque as...
* struct nf_conntrack / Conntrack
* struct nf_expect / Expect
* struct nfct_bitmask / Bitmask
* struct nfct_labelmap / Labelmap
* struct nfct_filter / Filter



comparison
----------

| original				| cgolmnfct			| remarks			|
| ------------------------------------- | ----------------------------- | ----------------------------- |
| nfct_open				| (Not implemented)		|				|
| nfct_open_nfnl			| (Not implemented)		|				|
| nfct_close				| (Not implemented)		|				|
| nfct_fd				| (Not implemented)		|				|
| nfct_nfnlh				| (Not implemented)		|				|
| nfct_new				| NewConntrack			|				|
| nfct_destroy				| Conntrack.Destroy		|				|
| nfct_clone				| Conntrack.Clone		|				|
| nfct_sizeof				| (Not implemented)		|				|
| nfct_maxsize				| (Not implemented)		|				|
| nfct_setobjopt			| Conntrack.Setobjopt		|				|
| nfct_getobjopt			| Conntrack.Getobjopt		|				|
| nfct_callback_register		| (Not implemented)		|				|
| nfct_callback_unregister		| (Not implemented)		|				|
| nfct_callback_register2		| (Not implemented)		|				|
| nfct_callback_unregister2		| (Not implemented)		|				|
| nfct_bitmask_new			| NewBitmask			|				|
| nfct_bitmask_clone			| Bitmask.Clone			|				|
| nfct_bitmask_maxbit			| Bitmask.Maxbit		|				|
| nfct_bitmask_test_bit			| Bitmask.TestBit		|				|
| nfct_bitmask_unset_bit		| Bitmask.UnsetBit		|				|
| nfct_bitmask_destroy			| Bitmask.Destroy		|				|
| nfct_bitmask_clear			| Bitmask.Clear			|				|
| nfct_bitmask_equal			| Bitmask.Equal			|				|
| nfct_labelmap_new			| NewLabelmap			|				|
| nfct_labelmap_destroy			| Labelmap.Destroy		|				|
| nfct_labelmap_get_name		| Labelmap.GetName		|				|
| nfct_labelmap_get_bit			| Labelmap.GetBit		|				|
| nfct_set_attr				| Conntrack.SetAttr		| data is unsafe.Pointer	|
| (add)					| Conntrack.SetAttrPtr		| data is Ptr			|
| nfct_set_attr_u8			| Conntrack.SetAttrU8		|				|
| nfct_set_attr_u16			| Conntrack.SetAttrU16		|				|
| nfct_set_attr_u32			| Conntrack.SetAttrU32		|				|
| nfct_set_attr_u64			| Conntrack.SetAttrU64		|				|
| nfct_set_attr_l			| Conntrack.SetAttrL		|				|
| (add)					| Conntrack.SetAttrLPtr		|				|
| nfct_get_attr				| Conntrack.GetAttr		|				|
| nfct_get_attr_u8			| Conntrack.GetAttrU8		|				|
| nfct_get_attr_u16			| Conntrack.GetAttrU16		|				|
| nfct_get_attr_u32			| Conntrack.GetAttrU32		|				|
| nfct_get_attr_u64			| Conntrack.GetAttrU64		|				|
| nfct_attr_is_set			| Conntrack.AttrIsSet		|				|
| nfct_attr_is_set_array		| Conntrack.AttrIsSetArray	|				|
| nfct_attr_unset			| Conntrack.AttrUnset		|				|
| nfct_set_attr_grp			| Conntrack.SetAttrGrp		|				|
| (add)					| Conntrack.SetAttrGrpPtr	|				|
| nfct_get_attr_grp			| Conntrack.SetAttrGrp		|				|
| (add)					| Conntrack.SetAttrGrpPtr	|				|
| nfct_attr_grp_is_set			| Conntrack.AttrGrpIsSet	|				|
| nfct_attr_grp_unset			| Conntrack.AttrGrpUnset	|				|
| nfct_snprintf				| Conntrack.Snprintf		|				|
| nfct_snprintf_labels			| Conntrack.SnprintfLabels	|				|
| nfct_compare				| Conntrack.Compare		|				|
| nfct_cmp				| Conntrack.Cmp			|				|
| nfct_query				| (Not implemented)		|				|
| nfct_send				| (Not implemented)		|				|
| nfct_catch				| (Not implemented)		|				|
| nfct_copy				| Conntrack.Copy		|				|
| nfct_copy_attr			| Conntrack.CopyAttr		|				|
| ------------------------------------- | ----------------------------- | ----------------------------- | 
| nfct_filter_create			| NewFilter			|				|
| nfct_filter_destroy			| Filter.Destroy		|				|
| nfct_filter_add_attr			| Filter.AddAttr		|				|
| (add)					| Filter.AddAttrPtr		|				|
| nfct_filter_add_attr_u32		| Filter.AddAttrU32		|				|
| nfct_filter_set_logic			| Filter.SetLogic		|				|
| nfct_filter_attach			| Filter.Attach			|				|
| nfct_filter_detach			| Filter.Detach			|				|
| ------------------------------------- | ----------------------------- | ----------------------------- | 
| nfct_filter_dump_create		| (Not implemented)		|				|
| nfct_filter_dump_destroy		| (Not implemented)		|				|
| nfct_filter_dump_set_attr		| (Not implemented)		|				|
| nfct_filter_dump_set_attr_u8		| (Not implemented)		|				|
| ------------------------------------- | ----------------------------- | ----------------------------- | 
| nfct_build_conntrack			| (Not implemented)		|				|
| nfct_parse_conntrack			| (Not implemented)		|				|
| nfct_build_query			| (Not implemented)		|				|
| nfct_nlmsg_build			| Conntrack.NlmsgBuild		|				|
| nfct_nlmsg_parse			| Conntrack.NlmsgParse		|				|
| nfct_payload_parse			| Conntrack.PayloadParse	|				|
| (add)					| Conntrack.PayloadParseBytes	|				|
| ------------------------------------- | ----------------------------- | ----------------------------- | 
| nfexp_new				| NewExpect			|				|
| nfexp_destroy				| Expect.Destroy		|				|
| nfexp_clone				| Expect.Clone			|				|
| nfexp_sizeof				| (Not implemented)		|				|
| nfexp_maxsize				| (Not implemented)		|				|
| nfexp_callback_register		| (Not implemented)		|				|
| nfexp_callback_unregister		| (Not implemented)		|				|
| nfexp_callback_register2		| (Not implemented)		|				|
| nfexp_callback_unregister2		| (Not implemented)		|				|
| nfexp_set_attr			| Expect.SetAttr		|				|
| (add)					| Expect.SetAttrPtr		|				|
| nfexp_set_attr_u8			| Expect.SetAttrU8		|				|
| nfexp_set_attr_u16			| Expect.SetAttrU16		|				|
| nfexp_set_attr_u32			| Expect.SetAttrU32		|				|
| nfexp_get_attr			| Expect.GetAttr		|				|
| nfexp_get_attr_u8			| Expect.GetAttrU8		|				|
| nfexp_get_attr_u16			| Expect.GetAttrU16		|				|
| nfexp_get_attr_u32			| Expect.GetAttrU32		|				|
| nfexp_attr_is_set			| Expect.AttrIsSet		|				|
| nfexp_attr_unset			| Expect.AttrUnset		|				|
| nfexp_query				| (Not implemented)		|				|
| nfexp_snprintf			| Expect.Snprintf		|				|
| nfexp_cmp				| Expect.Cmp			|				|
| nfexp_send				| (Not implemented)		|				|
| nfexp_catch				| (Not implemented)		|				|
| nfexp_build_expect			| (Not implemented)		|				|
| nfexp_parse_expect			| (Not implemented)		|				|
| nfexp_build_query			| (Not implemented)		|				|
| nfexp_nlmsg_build			| Expect.NlmsgBuild		|				|
| nfexp_nlmsg_parse			| Expect.NlmsgParse		|				|
| ------------------------------------- | ----------------------------- | ----------------------------- | 

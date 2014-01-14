cgolmnfct
=========

Go wrapper of libnetfilter_conntrack subset using cgo, under heavy development


sample
------

see examples


installation
------------

Need running ``mktypes.sh'' before build.


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
* struct nfct_filter_dump / FilterDump



comparison
----------

| original				| cgolmnfct			| remarks			|
| ------------------------------------- | ----------------------------- | ----------------------------- |
| nfct_open				| (Not implemented)		|				|
| nfct_open_nfnl			| (Not implemented)		|				|
| nfct_close				| (Not implemented)		|				|
| nfct_fd				| (Not implemented)		|				|
| nfct_nfnlh				| (Not implemented)		|				|
| nfct_new				| ConntrackNew			|				|
| nfct_destroy				| ConntrackDestroy		|				|
| nfct_clone				| ConntrackClone		|				|
| nfct_sizeof				| (Not implemented)		|				|
| nfct_maxsize				| (Not implemented)		|				|
| nfct_setobjopt			| ConntrackSetobjopt		|				|
| nfct_getobjopt			| ConntrackGetobjopt		|				|
| nfct_callback_register		| (Not implemented)		|				|
| nfct_callback_unregister		| (Not implemented)		|				|
| nfct_callback_register2		| (Not implemented)		|				|
| nfct_callback_unregister2		| (Not implemented)		|				|
| nfct_bitmask_new			| BitmaskNew			|				|
| nfct_bitmask_clone			| BitmaskClone			|				|
| nfct_bitmask_maxbit			| BitmaskMaxbit			|				|
| nfct_bitmask_test_bit			| BitmaskTestBit		|				|
| nfct_bitmask_unset_bit		| BitmaskUnsetBit		|				|
| nfct_bitmask_destroy			| BitmaskDestroy		|				|
| nfct_labelmap_new			| LabelmapNew			|				|
| nfct_labelmap_destroy			| LabelmapDestroy		|				|
| nfct_labelmap_get_name		| LabelmapGetName		|				|
| nfct_labelmap_get_bit			| LabelmapGetBit		|				|
| nfct_set_attr				| ConntrackSetAttr		| data is unsafe.Pointer	|
| (add)					| ConntrackSetAttrPtr		| data is Ptr			|
| nfct_set_attr_u8			| ConntrackSetAttrU8		|				|
| nfct_set_attr_u16			| ConntrackSetAttrU16		|				|
| nfct_set_attr_u32			| ConntrackSetAttrU32		|				|
| nfct_set_attr_u64			| ConntrackSetAttrU64		|				|
| nfct_set_attr_l			| ConntrackSetAttrL		|				|
| (add)					| ConntrackSetAttrLPtr		|				|
| nfct_get_attr				| ConntrackGetAttr		|				|
| nfct_get_attr_u8			| ConntrackGetAttrU8		|				|
| nfct_get_attr_u16			| ConntrackGetAttrU16		|				|
| nfct_get_attr_u32			| ConntrackGetAttrU32		|				|
| nfct_get_attr_u64			| ConntrackGetAttrU64		|				|
| nfct_attr_is_set			| ConntrackAttrIsSet		|				|
| nfct_attr_is_set_array		| ConntrackAttrIsSetArray	|				|
| nfct_attr_unset			| ConntrackAttrUnset		|				|
| nfct_set_attr_grp			| ConntrackSetAttrGrp		|				|
| (add)					| ConntrackSetAttrGrpPtr	|				|
| nfct_attr_grp_is_set			| ConntrackAttrGrpIsSet		|				|
| nfct_attr_grp_unset			| ConntrackAttrGrpUnset		|				|
| nfct_snprintf				| ConntrackSnprintf		|				|
| nfct_snprintf_labels			| ConntrackSnprintfLabels	|				|
| nfct_compare				| ConntrackCompare		|				|
| nfct_cmp				| ConntrackCmp			|				|
| nfct_query				| (Not implemented)		|				|
| nfct_send				| (Not implemented)		|				|
| nfct_catch				| (Not implemented)		|				|
| nfct_copy				| ConntrackCopy			|				|
| nfct_copy_attr			| ConntrackCopyAttr		|				|
| ------------------------------------- | ----------------------------- | ----------------------------- | 
| nfct_filter_create			| FilterCreate			|				|
| nfct_filter_destroy			| FilterDestroy			|				|
| nfct_filter_add_attr			| FilterAddAttr			|				|
| (add)					| FilterAddAttrPtr		|				|
| nfct_filter_add_attr_u32		| FilterAddAttrU32		|				|
| nfct_filter_set_logic			| FilterSetLogic		|				|
| nfct_filter_attach			| FilterAttach			|				|
| nfct_filter_detach			| FilterDetach			|				|
| ------------------------------------- | ----------------------------- | ----------------------------- | 
| nfct_filter_dump_create		| FilterDumpCreate		|				|
| nfct_filter_dump_destroy		| FilterDumpDestroy		|				|
| nfct_filter_dump_set_attr		| FilterDumpSetAttr		|				|
| (add)					| FilterDumpSetAttrPtr		|				|
| nfct_filter_dump_set_attr_u8		| FilterDumpSetAttrU8		|				|
| ------------------------------------- | ----------------------------- | ----------------------------- | 
| nfct_build_conntrack			| (Not implemented)		|				|
| nfct_parse_conntrack			| (Not implemented)		|				|
| nfct_build_query			| (Not implemented)		|				|
| nfct_nlmsg_build			| ConntrackNlmsgBuild		|				|
| nfct_nlmsg_parse			| ConntrackNlmsgParse		|				|
| nfct_payload_parse			| ConntrackPayloadParse		|				|
| (add)					| ConntrackPayloadParseBytes	|				|
| ------------------------------------- | ----------------------------- | ----------------------------- | 
| nfexp_new				| ExpectNew			|				|
| nfexp_destroy				| ExpectDestroy			|				|
| nfexp_clone				| ExpectClone			|				|
| nfexp_sizeof				| (Not implemented)		|				|
| nfexp_maxsize				| (Not implemented)		|				|
| nfexp_callback_register		| (Not implemented)		|				|
| nfexp_callback_unregister		| (Not implemented)		|				|
| nfexp_callback_register2		| (Not implemented)		|				|
| nfexp_callback_unregister2		| (Not implemented)		|				|
| nfexp_set_attr			| ExpectSetAttr			|				|
| (add)					| ExpectSetAttrPtr		|				|
| nfexp_set_attr_u8			| ExpectSetAttrU8		|				|
| nfexp_set_attr_u16			| ExpectSetAttrU16		|				|
| nfexp_set_attr_u32			| ExpectSetAttrU32		|				|
| nfexp_get_attr			| ExpectGetAttr			|				|
| nfexp_get_attr_u8			| ExpectGetAttrU8		|				|
| nfexp_get_attr_u16			| ExpectGetAttrU16		|				|
| nfexp_get_attr_u32			| ExpectGetAttrU32		|				|
| nfexp_attr_is_set			| ExpectAttrIsSet		|				|
| nfexp_attr_unset			| ExpectAttrUnset		|				|
| nfexp_query				| (Not implemented)		|				|
| nfexp_snprintf			| ExpectSnprintf		|				|
| nfexp_cmp				| ExpectCmp			|				|
| nfexp_send				| (Not implemented)		|				|
| nfexp_catch				| (Not implemented)		|				|
| nfexp_build_expect			| (Not implemented)		|				|
| nfexp_parse_expect			| (Not implemented)		|				|
| nfexp_build_query			| (Not implemented)		|				|
| nfexp_nlmsg_build			| ExpectNlmsgBuild		|				|
| nfexp_nlmsg_parse			| ExpectNlmsgParse		|				|
| ------------------------------------- | ----------------------------- | ----------------------------- | 







































#ifndef FLAG_H
#define FLAG_H

/* all the XTaint record flag definition here */

/* Mark */
#define INSN_MARK		 		"32"

#define CALL_INSN           	"14"
#define CALL_INSN_SEC       	"15"
#define CALL_INSN_FF2       	"1a"
#define CALL_INSN_FF2_SEC   	"1b"

#define RET_INSN            	"18"
#define RET_INSN_SEC        	"19"	

#define GROUP_START             100
#define GROUP_MIDDLE            101
#define GROUP_END               102

/* Qemu IR */

#define TCG_QEMU_LD         	"52"
#define TCG_QEMU_LD_POINTER 	"56"
#define TCG_QEMU_ST         	"5a"
#define TCG_QEMU_ST_POINTER 	"5e"

// #define TCG_ADD             	"3b"
// #define TCG_XOR             	"47"
// #define TCG_DEPOSIT		   	"4a"

/* as hex */
#define TCG_SHL_i32				0x36
#define TCG_SHR_i32				0x37
#define TCG_SAR_i32				0x38
#define TCG_ROTL_i32			0x39
#define TCG_ROTR_i32			0x3a

#define TCG_ADD_i32 			0x3b
#define TCG_SUB_i32 			0x3c
#define TCG_MUL_i32 			0x3d
#define TCG_DIV_i32 			0x3e
#define TCG_DIVU_i32 			0x3f
#define TCG_REM_i32 			0x40
#define TCG_REMU_i32 			0x41
#define TCG_MUL2_i32 			0x42
#define TCG_DIV2_i32 			0x43
#define TCG_DIVU2_i32 			0x44

#define TCG_AND_i32 			0x45
#define TCG_OR_i32 				0x46
#define TCG_XOR_i32 			0x47
#define TCG_NOT_i32 			0x48
#define TCG_NEG_i32 			0x49

#define TCG_EXT8S_i32 			0x4a
#define TCG_EXT16S_i32 			0x4b
#define TCG_EXT8U_i32 			0x4c
#define TCG_EXT16U_i32 			0x4d
#define TCG_BSWAP16_i32 		0x4e
#define TCG_BSWAP32_i32 		0x4f

#define TCG_DEPOSIT_i32 		0x50
#define TCG_MOV_i32 			0x51

#define TCG_LD_i32				0x52
#define TCG_LD_POINTER_i32		0x56
#define TCG_ST_i32				0x5a
#define TCG_ST_POINTER_i32		0x5e

#define TCG_SETCOND_i32 		0x62

#define TCG_LD_MIN				0x52
#define TCG_ST_MAX				0x61

/* Qemu reg (global) temp */
#define G_TEMP_UNKNOWN        	0xfff0
#define G_TEMP_ENV            	0xfff1
#define G_TEMP_CC_OP          	0xfff2
#define G_TEMP_CC_SRC         	0xfff3
#define G_TEMP_CC_DST         	0xfff4
#define G_TEMP_CC_TMP         	0xfff5
#define G_TEMP_EAX            	0xfff6
#define G_TEMP_ECX            	0xfff7
#define G_TEMP_EDX            	0xfff8
#define G_TEMP_EBX            	0xfff9
#define G_TEMP_ESP            	0xfffa
#define G_TEMP_EBP            	0xfffb
#define G_TEMP_ESI            	0xfffc
#define G_TEMP_EDI            	0xfffd	

#endif

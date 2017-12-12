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

/* Qemu IR */
#define TCG_DEPOSIT		   		"4a"

#define TCG_QEMU_LD         	"52"
#define TCG_QEMU_LD_POINTER 	"56"
#define TCG_QEMU_ST         	"5a"
#define TCG_QEMU_ST_POINTER 	"5e"

#define TCG_ADD             	"3b"
#define TCG_XOR             	"47"

#define NUM_TCG_LD				0x52
#define NUM_TCG_LD_POINTER		0x56
#define NUM_TCG_ST				0x5a
#define NUM_TCG_ST_POINTER		0x5e

#define NUM_TCG_LD_MIN			0x52
#define NUM_TCG_ST_MAX			0x61

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
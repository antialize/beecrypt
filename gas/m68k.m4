ifelse(substr(ASM_OS,0,5),linux,`
undefine(`C_FUNCTION_BEGIN')
define(C_FUNCTION_BEGIN,`
	TEXTSEG
	GLOBL SYMNAME($1)
	.type SYMNAME($1),@function
SYMNAME($1):
')
undefine(`C_FUNCTION_END')
define(C_FUNCTION_END,`
LOCAL($1)_size:
	.size SYMNAME($1), LOCAL($1)_size - SYMNAME($1)
')
')

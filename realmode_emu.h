#ifndef _REALMODE_EMU_
#define _REALMODE_EMU_

#include "regs.h"

#define EMU_SUCCESS 1
#define EMU_ERROR 0

extern uint8_t test[];

int exec_instruction(GUEST_REGS * regs, uint8_t ** p_eip);

#endif
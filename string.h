#ifndef _STRING_
#define _STRING_

#include <stdarg.h>
#include "lib_uefi.h"

int strlen(const char * str);
int printf(const char * format, ...);
int sprintf(char * str, const char * format, ...);
int vsprintf(char * str, const char * format, va_list params);

#endif
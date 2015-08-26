#include <stdbool.h>
#include "string.h"

int sprint_uintx(char * str, uint64_t n){
    char num_str[256] = {0};

    int i = 255, digit;
    if(n == 0){
        *str = '0';
        return 1;
    }
    while(n > 0){
        --i;
        digit = n % 16;
        if(digit < 10){
            num_str[i] = digit + '0';
        }
        else{
            num_str[i] = digit - 10 + 'A';
        }
        n /= 16;
    }
    char * num = num_str + i;
    int len = strlen(num);
    CopyMem(str, num, len);

    return len;
}

int sprint_uint(char * str, uint64_t n, int base){
    char num_str[256] = {0};

    if(base == 16){
    	return sprint_uintx(str, n);
    }

    int i = 255;
    if(n == 0){
        *str = '0';
        return 1;
    }
    while(n > 0){
        --i;
        num_str[i] = (n % base) + '0';
        n /= base;
    }
    
    char * num = num_str + i;
    int len = strlen(num);
    CopyMem(str, num, len);

    return len;
}

int strlen(const char * str){
	int len = 0;
	while(*str++){
		++len;
	}

	return len;
}

int printf(const char * format, ...){
	int ret;
	char str[256];
	CHAR16 wstr[256];
	va_list params;
	va_start(params, format);
	
	ret = vsprintf(str, format, params);
	str2wstr(wstr, str, 256);
	print(wstr);

	va_end(params);
	return ret;
}

int sprintf(char * str, const char * format, ...){
	int ret;
	va_list params;
	va_start(params, format);
	
	ret = vsprintf(str, format, params);

	va_end(params);
	return ret;
}

int vsprintf(char * str, const char * format, va_list params){
	int written = 0;
	int amount;
	bool rejected_bad_specifier = false;
	int base = 0;

	while(*format != 0){
		if(*format != '%'){
		print_c:
			amount = 1;
			while(format[amount] && format[amount] != '%'){
				++amount;
			}
			CopyMem(str, format, amount);
			format += amount;
			str += amount;
			written += amount;
			continue;
		}

		const char * format_start_at = format;

		if(*(++format) == '%'){
			goto print_c;
		}

		if(rejected_bad_specifier){
		bad_conversion:
			rejected_bad_specifier = true;
			format = format_start_at;
			goto print_c;
		}

		switch(*format){
			case 'c': {
				++format;
				char c = (char)va_arg(params, int);
				CopyMem(str, &c, sizeof(c));
				++str;
				++written;
				break;
			}
			case 's': {
				++format;
				const char * s = va_arg(params, const char*);
				int len = strlen(s);
				CopyMem(str, s, len);
				str += len;
				written += len;
				break;
			}
			case 'x':
				base += 6;
			case 'u':
				base += 8;
			case 'b':
				base += 2;
				
				++format;
				uint64_t n = va_arg(params, uint64_t);
				int len = sprint_uint(str, n, base);
				str += len;
				written += len;
				break;
			default:
				goto bad_conversion;
		}
	}

	*str = 0;
	return written;
}
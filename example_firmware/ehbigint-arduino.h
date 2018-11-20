/*
 * Copyright (C) 2012 Eric Herman <eric@freesa.org>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef EHBIGINT_ARDUINO_H
#define EHBIGINT_ARDUINO_H

#define CHAR_BIT 8
#define EBA_CHAR_BIT CHAR_BIT
#define EBA_SKIP_LIBC 1
#define EBA_DIY_MEMCPY 1
#define EBA_DIY_MEMSET 1
#define EBA_SKIP_NEW 1
#define EBA_SKIP_STRUCT_NULL_CHECK 1
#define EBA_SKIP_STRUCT_BITS_NULL_CHECK 1

#define strnlen ehstrnlen
#define NEED_EH_STRLEN
#define SKIP_STDIO_H

#define LONGBITS (4 * CHAR_BIT)

#include "eh-printf.h"

#define Ehbi_log_error0(format) \
 eh_printf("\r\nError: %s:%d: ", __FILE__, __LINE__); \
 eh_printf(format); \
 eh_printf("\r\n")

#define Ehbi_log_error1(format, arg) \
 eh_printf("\r\nError: %s:%d: ", __FILE__, __LINE__); \
 eh_printf(format, arg); \
 eh_printf("\r\n")

#define Ehbi_log_error2(format, arg1, arg2) \
 eh_printf("\r\nError: %s:%d: ", __FILE__, __LINE__); \
 eh_printf(format, arg1, arg2); \
 eh_printf("\r\n")

#define Ehbi_log_error3(format, arg1, arg2, arg3) \
 eh_printf("\r\nError: %s:%d: ", __FILE__, __LINE__); \
 eh_printf(format, arg1, arg2, arg3); \
 eh_printf("\r\n")

#ifndef EHBI_SKIP_IS_PROBABLY_PRIME
#define ehbi_random_bytes totally_bogus_random_bytes

#ifdef __cplusplus
extern "C" {
#endif

	int totally_bogus_random_bytes(unsigned char *buf, size_t len);

#ifdef __cplusplus
}
#endif
#endif				/* EHBI_SKIP_IS_PROBABLY_PRIME */
/*
#ifdef __cplusplus
extern "C" {
#endif

extern int ehbi_eba_err;

#ifdef __cplusplus
}
#endif

#define Eba_log_error0 Ehbi_log_error0
#define Eba_log_error1 Ehbi_log_error1
#define Eba_log_error2 Ehbi_log_error2
#define Eba_log_error3 Ehbi_log_error3

#define Eba_stack_alloc ehbi_stack_alloc
#define Eba_stack_free ehbi_stack_free

#define Eba_crash() do { \
        Ehbi_log_error0("EBA CRASH!\n"); \
        ehbi_eba_err = EHBI_EBA_CRASH; \
        return; \
        } while(0)

#define Eba_crash_uc() do { \
        Ehbi_log_error0("EBA CRASH UC!\n"); \
        ehbi_eba_err = EHBI_EBA_CRASH; \
        return 0; \
        } while(0)
*/
#include "ehbigint.h"
#endif				/* EHBIGINT_ARDUINO_H */

/*
ehbigint-eba.c: shim for eba code
Copyright (C) 2016 Eric Herman <eric@freesa.org>

This work is free software: you can redistribute it and/or modify it
under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at
your option) any later version.

This work is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
License for more details.
*/
#ifndef EHBIGINT_EBA_H
#define EHBIGINT_EBA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ehbigint-log.h"
#include "ehbigint-util.h"

#define EBA_SKIP_EBA_NEW
#define EBA_SKIP_STRUCT_NULL_CHECK
/*
#define EBA_SKIP_ARRAY_INDEX_OVERRUN_SAFETY
#define EBA_SKIP_ENDIAN
#define EBA_SKIP_SHIFTS
#define EBA_SKIP_STRUCT_BITS_NULL_CHECK
#define EBA_DIY_MEMCPY
#define Eba_memcpy
#define Eba_alloc
#define Eba_alloc_str
#define Eba_free
*/

extern int ehbi_eba_err;
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

#define Eba_log_error0 Ehbi_log_error0
#define Eba_log_error1 Ehbi_log_error1
#define Eba_log_error2 Ehbi_log_error2
#define Eba_log_error3 Ehbi_log_error3

#define Eba_stack_alloc ehbi_stack_alloc
#define Eba_stack_free ehbi_stack_free

#include "eba.h"

#ifdef __cplusplus
}
#endif

#endif /* EHBIGINT_EBA_H */

/*
ehbigint-priv.c: private functions for ehbigint.c
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
#ifndef EHBIGINT_PRIV_H
#define EHBIGINT_PRIV_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ehbigint.h"		/* struct ehbigint */

#define Ehbi_stack_alloc_struct(tmp, size, err) \
	do { \
		tmp.bytes = NULL; \
		tmp.bytes_len = 0; \
		tmp.bytes_used = 0; \
		tmp.sign = 0; \
		tmp.bytes = (unsigned char *)ehbi_stack_alloc(size); \
		if (!tmp.bytes) { \
			Ehbi_log_error2("Could not %s(%lu) bytes", \
					ehbi_stack_alloc_str, \
					(unsigned long)(size)); \
			err = EHBI_STACK_TOO_SMALL; \
		} else { \
			tmp.bytes_len = size; \
			tmp.bytes[size-1] = 0x00; \
			tmp.bytes_used = 1; \
		} \
	} while (0)

#define Ehbi_stack_alloc_struct_j(tmp, size, err, err_jmp_label) \
	do { \
		Ehbi_stack_alloc_struct(tmp, size, err); \
		if (err) { \
			goto err_jmp_label; \
		} \
	} while (0)

void ehbi_unsafe_zero(struct ehbigint *bi);
void ehbi_unsafe_clear_null_struct(struct ehbigint *bi);
void ehbi_unsafe_reset_bytes_used(struct ehbigint *bi);

#ifdef __cplusplus
}
#endif

#endif /* EHBIGINT_PRIV_H */

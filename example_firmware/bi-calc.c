/*
bi-calc.c: a demo utility to show using the ehbigint library
Copyright (C) 2016, 2017 Eric Herman <eric@freesa.org>

This work is free software: you can redistribute it and/or modify it
under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at
your option) any later version.

This work is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
License for more details.
*/

#include "bi-calc.h"
#include "ehbigint.h"
#include "eh-printf.h"

int bi_calc(const char *a, char op, const char *b, char *result, size_t len, int verbose)
{
	size_t a_len = 1 + eh_strlen(a);
	size_t b_len = 1 + eh_strlen(b);
	size_t buflen = 10 + a_len + b_len;
	char buf[buflen];
	unsigned char bbuf1[a_len];
	unsigned char bbuf2[b_len];
	unsigned char bbuf3[a_len + b_len];
	unsigned char bbuf4[a_len + b_len];
	struct ehbigint bigint_1;
	struct ehbigint bigint_2;
	struct ehbigint bigint_3;
	struct ehbigint bigint_4;
	int err;

	bigint_1.bytes = bbuf1;
	bigint_1.bytes_len = a_len;

	bigint_2.bytes = bbuf2;
	bigint_2.bytes_len = b_len;

	bigint_3.bytes = bbuf3;
	bigint_3.bytes_len = a_len + b_len;

	bigint_4.bytes = bbuf4;
	bigint_4.bytes_len = a_len + b_len;

	err = ehbi_set_decimal_string(&bigint_1, a, eh_strlen(a));
	err = err || ehbi_set_decimal_string(&bigint_2, b, eh_strlen(b));
	if (err) {
		return err;
	}

	switch (op) {
	case '+':
		err = ehbi_add(&bigint_3, &bigint_1, &bigint_2);
		break;
	case '-':
		err = ehbi_subtract(&bigint_3, &bigint_1, &bigint_2);
		break;
	case '*':
		err = ehbi_mul(&bigint_3, &bigint_1, &bigint_2);
		break;
	case '/':
		err = ehbi_div(&bigint_3, &bigint_4, &bigint_1, &bigint_2);
		break;
	case '%':
		err = ehbi_div(&bigint_4, &bigint_3, &bigint_1, &bigint_2);
		break;
	default:
		eh_printf("\r\nError: operator '%c' not supported.\r\n", op);
		err = -1;
	}

	ehbi_to_decimal_string(&bigint_3, result, len, &err);

	if (verbose && !err) {
		eh_printf("\r\n");
		buf[0] = '\0';
		ehbi_to_decimal_string(&bigint_1, buf, buflen, &err);
		if (!err) {
			eh_printf("   %40s\r\n", buf);
			ehbi_to_decimal_string(&bigint_2, buf, buflen, &err);
		}
		if (!err) {
			eh_printf(" %c %40s\r\n", op, buf);
			eh_printf(" = %40s\r\n", result);
		}
		eh_printf("\r\n");
	}

	return err;
}

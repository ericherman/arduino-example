/*
ehbigint.c: slow Big Int library hopefully somewhat suitable for 8bit CPUs
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

#include "ehbigint.h"
#include "ehbigint-log.h"
#include "ehbigint-util.h"
#include "ehbigint-eba.h"
#include "ehbigint-priv.h"

static int ehbi_bytes_shift_right(struct ehbigint *bi, size_t num_bytes);
static int ehbi_bytes_shift_left(struct ehbigint *bi, size_t num_bytes);

int ehbi_init(struct ehbigint *bi, unsigned char *bytes, size_t len)
{
	size_t i;

	if (bi == NULL) {
		Ehbi_log_error0("Null struct");
		return EHBI_NULL_STRUCT;
	}

	bi->bytes = NULL;
	bi->bytes_len = 0;
	bi->bytes_used = 0;
	bi->sign = 0;

	if (bytes == NULL) {
		Ehbi_log_error0("Null bytes[]");
		return EHBI_NULL_BYTES;
	}

	for (i = 0; i < len; ++i) {
		bytes[i] = 0x00;
	}

	bi->bytes = bytes;
	bi->bytes_len = len;
	bi->bytes_used = 1;

	return EHBI_SUCCESS;
}

int ehbi_zero(struct ehbigint *bi)
{
	Trace_bi(6, bi);

	Ehbi_struct_is_not_null(6, bi);

	ehbi_unsafe_zero(bi);

	Trace_msg_s_bi(6, "end", bi);
	Return_i(6, EHBI_SUCCESS);
}

int ehbi_set_l(struct ehbigint *bi, long val)
{
	int err;

	Trace_bi_l(6, bi, val);

	Ehbi_struct_is_not_null(6, bi);

	ehbi_unsafe_zero(bi);

	err = ehbi_inc_l(bi, val);

	Trace_msg_s_bi(4, "end", bi);
	Return_i(6, err);
}

int ehbi_set(struct ehbigint *bi, const struct ehbigint *val)
{
	size_t i;
	unsigned char byte;

	Trace_bi_bi(6, bi, val);

	Ehbi_struct_is_not_null(6, bi);
	Ehbi_struct_is_not_null(6, val);

	ehbi_unsafe_zero(bi);

	bi->sign = val->sign;
	bi->bytes_used = 0;
	for (i = 0; i < val->bytes_used; ++i) {
		if (bi->bytes_used >= bi->bytes_len) {
			ehbi_unsafe_zero(bi);
			Ehbi_log_error0("Result byte[] too small");
			Return_i(6, EHBI_BYTES_TOO_SMALL);
		}
		byte = val->bytes[val->bytes_len - 1 - i];
		bi->bytes[bi->bytes_len - 1 - i] = byte;
		++bi->bytes_used;
	}

	for (i = 0; i < (bi->bytes_len - bi->bytes_used); ++i) {
		bi->bytes[i] = 0x00;
	}

	ehbi_unsafe_reset_bytes_used(bi);

	Trace_msg_s_bi(6, "end", bi);
	Return_i(6, EHBI_SUCCESS);
}

int ehbi_add(struct ehbigint *res, const struct ehbigint *bi1,
	     const struct ehbigint *bi2)
{
	size_t i, size;
	unsigned char a, b, c;
	const struct ehbigint *swp;
	struct ehbigint tmp;
	int err;

	Trace_bi_bi_bi(2, res, bi1, bi2);

	ehbi_unsafe_clear_null_struct(&tmp);

	Ehbi_struct_is_not_null(2, res);
	Ehbi_struct_is_not_null(2, bi1);
	Ehbi_struct_is_not_null(2, bi2);

	err = EHBI_SUCCESS;

	/* adding zero */
	if (bi2->bytes_used == 1 && bi2->bytes[bi2->bytes_len - 1] == 0x00) {
		err = ehbi_set(res, bi1);
		Return_i(2, err);
	}

	/* adding to zero */
	if (bi1->bytes_used == 1 && bi1->bytes[bi1->bytes_len - 1] == 0x00) {
		err = ehbi_set(res, bi2);
		Return_i(2, err);
	}

	if (bi1->sign != bi2->sign) {
		size = bi2->bytes_len;
		Ehbi_stack_alloc_struct(tmp, size, err);
		if (err) {
			Return_i(2, err);
		}
		err = ehbi_set(&tmp, bi2);
		err = err || ehbi_negate(&tmp);
		err = err || ehbi_subtract(res, bi1, &tmp);
		ehbi_stack_free(tmp.bytes, size);
		if (err) {
			ehbi_unsafe_zero(res);
		}
		Return_i(2, err);
	}
	res->sign = bi1->sign;

	if (bi1->bytes_used < bi2->bytes_used) {
		swp = bi1;
		bi1 = bi2;
		bi2 = swp;
	}

	res->bytes_used = 0;
	c = 0;
	for (i = 1; i <= bi1->bytes_used; ++i) {
		a = bi1->bytes[bi1->bytes_len - i];
		b = (bi2->bytes_used < i) ? 0 : bi2->bytes[bi2->bytes_len - i];
		c = c + a + b;

		if (i > res->bytes_len) {
			Ehbi_log_error0("Result byte[] too small");
			Return_i(2, EHBI_BYTES_TOO_SMALL);
		}
		res->bytes[res->bytes_len - i] = c;
		res->bytes_used++;

		c = (c < a) || (c == a && b != 0) ? 1 : 0;
	}
	if (c) {
		if (i > res->bytes_len) {
			Ehbi_log_error0("Result byte[] too small for carry");
			Return_i(2, EHBI_BYTES_TOO_SMALL_FOR_CARRY);
		}
		res->bytes[res->bytes_len - i] = c;
		res->bytes_used++;
		if (c == 0xFF) {
			if (res->bytes_used == res->bytes_len) {
				Ehbi_log_error0
				    ("Result byte[] too small for carry");
				Return_i(2, EHBI_BYTES_TOO_SMALL_FOR_CARRY);
			}
			res->bytes_used++;
		}
	}

	if ((res->bytes_used == 1) && (res->bytes[res->bytes_len - 1] == 0x00)) {
		res->sign = 0;
	}

	Trace_msg_s_bi(2, "end", res);
	Return_i(2, EHBI_SUCCESS);
}

int ehbi_mul(struct ehbigint *res, const struct ehbigint *bi1,
	     const struct ehbigint *bi2)
{
	size_t size, i, j;
	int err;
	const struct ehbigint *t;
	unsigned int a, b, r;
	struct ehbigint tmp;

	Trace_bi_bi_bi(2, res, bi1, bi2);

	ehbi_unsafe_clear_null_struct(&tmp);

	Ehbi_struct_is_not_null(2, res);
	Ehbi_struct_is_not_null(2, bi1);
	Ehbi_struct_is_not_null(2, bi2);

	err = 0;
	if (bi1->bytes_used < bi2->bytes_used) {
		t = bi1;
		bi1 = bi2;
		bi2 = t;
	}

	size = res->bytes_len;
	Ehbi_stack_alloc_struct_j(tmp, size, err, ehbi_mul_end);
	ehbi_unsafe_zero(&tmp);
	ehbi_unsafe_zero(res);

	for (i = 0; i < bi2->bytes_used; ++i) {
		for (j = 0; j < bi1->bytes_used; ++j) {
			a = bi2->bytes[(bi2->bytes_len - 1) - i];
			b = bi1->bytes[(bi1->bytes_len - 1) - j];
			r = (a * b);
			err = err || ehbi_set_l(&tmp, r);
			err = err || ehbi_bytes_shift_left(&tmp, i);
			err = err || ehbi_bytes_shift_left(&tmp, j);
			err = err || ehbi_inc(res, &tmp);
			if (err) {
				goto ehbi_mul_end;
			}
		}
	}

ehbi_mul_end:
	if (err) {
		ehbi_zero(res);
	} else {
		if (bi1->sign != bi2->sign) {
			res->sign = 1;
		}
	}
	if (tmp.bytes) {
		ehbi_stack_free(tmp.bytes, size);
	}

	Trace_msg_s_bi(2, "end", res);
	Return_i(2, err);
}

int ehbi_div(struct ehbigint *quotient, struct ehbigint *remainder,
	     const struct ehbigint *numerator,
	     const struct ehbigint *denominator)
{
	int err;
	size_t i, size, num_idx;
	struct ehbigint s_abs_numer;
	struct ehbigint s_abs_denom;
	const struct ehbigint *abs_numer;
	const struct ehbigint *abs_denom;

	Trace_bi_bi_bi_bi(2, quotient, remainder, numerator, denominator);

	ehbi_unsafe_clear_null_struct(&s_abs_numer);
	ehbi_unsafe_clear_null_struct(&s_abs_denom);

	Ehbi_struct_is_not_null(2, quotient);
	Ehbi_struct_is_not_null(2, remainder);
	Ehbi_struct_is_not_null(2, numerator);
	Ehbi_struct_is_not_null(2, denominator);

	if (remainder->bytes_len < numerator->bytes_used) {
		Ehbi_log_error2("byte[] too small;"
				" remainder->bytes_len < numerator->bytes_used"
				" (%lu < %lu)",
				(unsigned long)remainder->bytes_len,
				(unsigned long)numerator->bytes_used);
		Return_i(2, EHBI_BYTES_TOO_SMALL);
	}

	err = EHBI_SUCCESS;

	if (numerator->sign == 0) {
		abs_numer = numerator;
	} else {
		s_abs_numer.bytes_used = 0;
		s_abs_numer.bytes_len = 0;
		s_abs_numer.sign = 0;
		size = numerator->bytes_used;
		Ehbi_stack_alloc_struct_j(s_abs_numer, size, err, ehbi_div_end);
		err = ehbi_set(&s_abs_numer, numerator);
		err = err || ehbi_negate(&s_abs_numer);
		if (err) {
			goto ehbi_div_end;
		}
		abs_numer = &s_abs_numer;
	}

	if (denominator->sign == 0) {
		abs_denom = denominator;
	} else {
		s_abs_denom.bytes_used = 0;
		s_abs_denom.bytes_len = 0;
		s_abs_denom.sign = 0;
		size = numerator->bytes_used;
		Ehbi_stack_alloc_struct_j(s_abs_denom, size, err, ehbi_div_end);
		err = ehbi_set(&s_abs_denom, denominator);
		err = err || ehbi_negate(&s_abs_denom);
		if (err) {
			goto ehbi_div_end;
		}
		abs_denom = &s_abs_denom;
	}

	/* just early return if abs_denom is bigger than abs_numer */
	if (ehbi_greater_than(abs_denom, abs_numer, &err)) {
		ehbi_unsafe_zero(quotient);
		err = ehbi_set(remainder, abs_numer);
		goto ehbi_div_end;
	}
	if (err) {
		goto ehbi_div_end;
	}

	/* base 256 "long division" */
	ehbi_unsafe_zero(quotient);
	ehbi_unsafe_zero(remainder);

	if (ehbi_equals(abs_denom, quotient, &err)) {
		Ehbi_log_error0("denominator == 0");
		err = EHBI_DIVIDE_BY_ZERO;
		goto ehbi_div_end;
	}
	if (err) {
		goto ehbi_div_end;
	}

	num_idx = abs_numer->bytes_len - abs_numer->bytes_used;
	for (i = 0; i < abs_denom->bytes_used; ++i) {
		if ((remainder->bytes_used > 1)
		    || (remainder->bytes[remainder->bytes_len - 1] != 0x00)) {
			err = ehbi_bytes_shift_left(remainder, 1);
			if (err) {
				goto ehbi_div_end;
			}
		}
		ehbi_inc_l(remainder, abs_numer->bytes[num_idx++]);
	}
	if (ehbi_greater_than(abs_denom, remainder, &err)) {
		err = ehbi_bytes_shift_left(remainder, 1);
		if (err) {
			goto ehbi_div_end;
		}
		ehbi_inc_l(remainder, abs_numer->bytes[num_idx++]);
	}
	if (err) {
		goto ehbi_div_end;
	}

	i = 0;
	while (ehbi_greater_than(remainder, abs_denom, &err)
	       || ehbi_equals(remainder, abs_denom, &err)) {
		if (err) {
			goto ehbi_div_end;
		}
		err = ehbi_inc_l(quotient, 1);
		if (err) {
			goto ehbi_div_end;
		}
		err = ehbi_dec(remainder, abs_denom);
		if (err) {
			goto ehbi_div_end;
		}
		while (ehbi_less_than(remainder, abs_denom, &err)
		       && (num_idx < abs_numer->bytes_len)) {
			err = ehbi_bytes_shift_left(quotient, 1);
			if (err) {
				goto ehbi_div_end;
			}

			err = ehbi_bytes_shift_left(remainder, 1);
			if (err) {
				goto ehbi_div_end;
			}
			remainder->bytes[remainder->bytes_len - 1] =
			    abs_numer->bytes[num_idx++];
		}
		if (err) {
			goto ehbi_div_end;
		}
	}

ehbi_div_end:
	if (s_abs_denom.bytes) {
		ehbi_stack_free(s_abs_denom.bytes, s_abs_denom.bytes_len);
	}
	if (s_abs_numer.bytes) {
		ehbi_stack_free(s_abs_numer.bytes, s_abs_numer.bytes_len);
	}
	/* if error, let's not return garbage or 1/2 an answer */
	if (err) {
		ehbi_zero(quotient);
		ehbi_zero(remainder);
	} else {
		if (numerator->sign != denominator->sign) {
			quotient->sign = 1;
		}
	}
	Trace_msg_s_bi(2, "end quotient", quotient);
	Trace_msg_s_bi(2, "end remainder", remainder);
	Return_i(2, err);
}

int ehbi_exp(struct ehbigint *result, const struct ehbigint *base,
	     const struct ehbigint *exponent)
{
	int err;
	struct ehbigint loop, tmp;

	Trace_bi_bi_bi(2, result, base, exponent);

	ehbi_unsafe_clear_null_struct(&loop);

	err = EHBI_SUCCESS;

	Ehbi_stack_alloc_struct_j(loop, exponent->bytes_used, err,
				  ehbi_exp_end);
	Ehbi_stack_alloc_struct_j(tmp, result->bytes_len, err, ehbi_exp_end);

	err = ehbi_zero(&loop);
	err = err || ehbi_set_l(result, 1);

	while (ehbi_less_than(&loop, exponent, &err)) {
		err = err || ehbi_mul(&tmp, result, base);
		err = err || ehbi_set(result, &tmp);
		ehbi_inc_l(&loop, 1);
	}

ehbi_exp_end:
	if (loop.bytes) {
		ehbi_stack_free(loop.bytes, loop.bytes_len);
	}
	if (tmp.bytes) {
		ehbi_stack_free(tmp.bytes, tmp.bytes_len);
	}
	if (err) {
		ehbi_zero(result);
	}
	return err;
}

int ehbi_exp_mod(struct ehbigint *result, const struct ehbigint *base,
		 const struct ehbigint *exponent,
		 const struct ehbigint *modulus)
{
	int err;
	size_t size;
	struct ehbigint zero, tmp1, tjunk, texp, tbase;
	unsigned char zero_bytes[2];

	Trace_bi_bi_bi_bi(2, result, base, exponent, modulus);

	ehbi_unsafe_clear_null_struct(&zero);
	ehbi_unsafe_clear_null_struct(&tmp1);
	ehbi_unsafe_clear_null_struct(&tbase);
	ehbi_unsafe_clear_null_struct(&texp);
	ehbi_unsafe_clear_null_struct(&tjunk);

	Ehbi_struct_is_not_null(2, result);
	Ehbi_struct_is_not_null(2, base);
	Ehbi_struct_is_not_null(2, exponent);
	Ehbi_struct_is_not_null(2, modulus);

	ehbi_init(&zero, zero_bytes, 2);

	err = EHBI_SUCCESS;

	size = 4 + (2 * base->bytes_used) + (2 * exponent->bytes_used);

	Ehbi_stack_alloc_struct_j(tmp1, size, err, ehbi_mod_exp_end);
	Ehbi_stack_alloc_struct_j(tbase, size, err, ehbi_mod_exp_end);
	Ehbi_stack_alloc_struct_j(texp, size, err, ehbi_mod_exp_end);
	Ehbi_stack_alloc_struct_j(tjunk, size, err, ehbi_mod_exp_end);

	/* prevent divide by zero */
	ehbi_unsafe_zero(&tmp1);
	if (ehbi_equals(modulus, &tmp1, &err)) {
		Ehbi_log_error0("modulus == 0");
		err = EHBI_DIVIDE_BY_ZERO;
		goto ehbi_mod_exp_end;
	}

	/* prevent negative eponent */
	if (ehbi_is_negative(exponent, &err)) {
		Ehbi_log_error0("exponent < 0");
		err = EHBI_BAD_DATA;
		goto ehbi_mod_exp_end;
	}

	/*
	   The following is an example in pseudocode based on Applied
	   Cryptography: Protocols, Algorithms, and Source Code in C,
	   Second Edition (2nd ed.), page 244.
	   Schneier, Bruce (1996). Wiley. ISBN 978-0-471-11709-4.

	   function modular_pow(base, exponent, modulus)
	   if modulus = 1 then return 0
	   Assert :: (modulus - 1) * (modulus - 1) does not overflow base
	   result := 1
	   base := base mod modulus
	   while exponent > 0
	   if (exponent mod 2 == 1):
	   result := (result * base) mod modulus
	   exponent := exponent >> 1
	   base := (base * base) mod modulus
	   return result

	   See Also:
	   https://en.wikipedia.org/wiki/Modular_exponentiation#Right-to-left_binary_method
	 */

	/* if modulus == 1 then return 0 */
	err = ehbi_set_l(&tmp1, 1);
	if (!err && ehbi_equals(modulus, &tmp1, &err)) {
		ehbi_unsafe_zero(result);
		goto ehbi_mod_exp_end;
	}

	err = err || ehbi_set(&tbase, base);
	err = err || ehbi_set(&texp, exponent);

	/* result := 1 */
	err = err || ehbi_set_l(result, 1);
	if (err) {
		goto ehbi_mod_exp_end;
	}

	/* base := base mod modulus */
	err = err || ehbi_div(&tjunk, &tbase, base, modulus);

	/* while exponent > 0 */
	while (ehbi_greater_than(&texp, &zero, &err)) {
		if (err) {
			goto ehbi_mod_exp_end;
		}

		/* if (exponent mod 2 == 1): */
		if (ehbi_is_odd(&texp, &err)) {
			/* result := (result * base) mod modulus */
			err = err || ehbi_mul(&tmp1, result, &tbase);
			err = err || ehbi_div(&tjunk, result, &tmp1, modulus);
		}

		/* exponent := exponent >> 1 */
		err = err || ehbi_shift_right(&texp, 1);

		/* base := (base * base) mod modulus */
		err = err || ehbi_mul(&tmp1, &tbase, &tbase);
		err = err || ehbi_div(&tjunk, &tbase, &tmp1, modulus);

		if (err) {
			goto ehbi_mod_exp_end;
		}
	}

	/* return result */

ehbi_mod_exp_end:
	if (tmp1.bytes) {
		ehbi_stack_free(tmp1.bytes, tmp1.bytes_len);
	}
	if (tbase.bytes) {
		ehbi_stack_free(tbase.bytes, tbase.bytes_len);
	}
	if (texp.bytes) {
		ehbi_stack_free(texp.bytes, texp.bytes_len);
	}
	if (tjunk.bytes) {
		ehbi_stack_free(tjunk.bytes, tjunk.bytes_len);
	}
	if (err) {
		ehbi_zero(result);
	}

	Trace_msg_s_bi(2, "end", result);
	Return_i(2, err);
}

int ehbi_inc(struct ehbigint *bi, const struct ehbigint *val)
{
	size_t size;
	int err;
	struct ehbigint temp;

	Trace_bi_bi(4, bi, val);

	ehbi_unsafe_clear_null_struct(&temp);

	Ehbi_struct_is_not_null(4, bi);
	Ehbi_struct_is_not_null(4, val);

	if (val->bytes_used > bi->bytes_len) {
		Ehbi_log_error0("byte[] too small");
		Return_i(4, EHBI_BYTES_TOO_SMALL);
	}

	err = EHBI_SUCCESS;

	size = bi->bytes_used;

	Ehbi_stack_alloc_struct(temp, size, err);
	if (err) {
		Return_i(4, err);
	}
	err = ehbi_set(&temp, bi);
	err = err || ehbi_add(bi, &temp, val);
	ehbi_stack_free(temp.bytes, temp.bytes_len);

	Trace_msg_s_bi(4, "end", bi);
	Return_i(4, err);
}

int ehbi_inc_l(struct ehbigint *bi, long val)
{
	size_t i, j;
	unsigned long v;
	unsigned char c, val_negative;
	unsigned char bytes[sizeof(unsigned long)];
	struct ehbigint temp;
	int err;

	Trace_bi_l(4, bi, val);

	ehbi_unsafe_clear_null_struct(&temp);

	Ehbi_struct_is_not_null(4, bi);

	val_negative = (val < 0) ? 1 : 0;

	temp.bytes = bytes;
	temp.bytes_len = sizeof(unsigned long);
	temp.bytes_used = sizeof(unsigned long);
	temp.sign = 0;

	v = (val_negative) ? (unsigned long)(-val) : (unsigned long)val;

	for (i = 0; i < temp.bytes_used; ++i) {
		c = (v >> (8 * i));
		j = (temp.bytes_len - 1) - i;
		temp.bytes[j] = c;
	}
	for (i = 0; i < temp.bytes_len; ++i) {
		if (temp.bytes[i] != 0x00) {
			break;
		}
	}
	temp.bytes_used = temp.bytes_len - i;
	if (temp.bytes_used == 0) {
		++temp.bytes_used;
	}

	if (val_negative) {
		err = ehbi_dec(bi, &temp);
	} else {
		err = ehbi_inc(bi, &temp);
	}

	Trace_msg_s_bi(4, "end", bi);
	Return_i(4, err);
}

int ehbi_dec(struct ehbigint *bi, const struct ehbigint *val)
{
	size_t size;
	int err;
	struct ehbigint temp;

	Trace_bi_bi(4, bi, val);

	ehbi_unsafe_clear_null_struct(&temp);

	Ehbi_struct_is_not_null(4, bi);
	Ehbi_struct_is_not_null(4, val);

	err = EHBI_SUCCESS;

	size = bi->bytes_len;

	Ehbi_stack_alloc_struct(temp, size, err);
	if (err) {
		Return_i(4, err);
	}
	ehbi_unsafe_zero(&temp);

	err = err || ehbi_subtract(&temp, bi, val);
	err = err || ehbi_set(bi, &temp);

	ehbi_stack_free(temp.bytes, temp.bytes_len);

	Trace_msg_s_bi(4, "end", bi);
	Return_i(4, err);
}

int ehbi_subtract(struct ehbigint *res, const struct ehbigint *bi1,
		  const struct ehbigint *bi2)
{
	size_t i, j, size;
	unsigned char a, b, c, negate;
	const struct ehbigint *swp;
	struct ehbigint *bi1a;
	struct ehbigint tmp;
	int err;
	/* char buf[80]; */

	Trace_bi_bi_bi(2, res, bi1, bi2);

	ehbi_unsafe_clear_null_struct(&tmp);

	Ehbi_struct_is_not_null(2, res);
	Ehbi_struct_is_not_null(2, bi1);
	Ehbi_struct_is_not_null(2, bi2);

	err = EHBI_SUCCESS;

	/* subtract zero */
	if (bi2->bytes_used == 1 && bi2->bytes[bi2->bytes_len - 1] == 0x00) {
		err = ehbi_set(res, bi1);
		goto ehbi_subtract_end;
	}

	/* subtract from 0 */
	if (bi1->bytes_used == 1 && bi1->bytes[bi1->bytes_len - 1] == 0x00) {
		err = ehbi_set(res, bi2);
		err = err || ehbi_negate(res);
		goto ehbi_subtract_end;
	}

	/* subtracting a negative */
	if (bi1->sign == 0 && bi2->sign != 0) {
		size = bi2->bytes_len;
		Ehbi_stack_alloc_struct_j(tmp, size, err, ehbi_subtract_end);
		err = ehbi_set(&tmp, bi2);
		err = err || ehbi_negate(&tmp);
		err = err || ehbi_add(res, bi1, &tmp);
		goto ehbi_subtract_end;
	}

	/* negative subtracting a positive */
	if (bi1->sign != 0 && bi2->sign == 0) {
		size = bi1->bytes_len;
		Ehbi_stack_alloc_struct_j(tmp, size, err, ehbi_subtract_end);
		err = ehbi_set(&tmp, bi1);
		err = err || ehbi_negate(&tmp);
		err = err || ehbi_add(res, &tmp, bi2);
		err = err || ehbi_negate(res);
		goto ehbi_subtract_end;
	}

	if ((bi1->sign == 0 && bi2->sign == 0
	     && ehbi_greater_than(bi2, bi1, &err)) || (bi1->sign != 0
						       && bi2->sign != 0
						       && ehbi_less_than(bi2,
									 bi1,
									 &err)))
	{
		/* subtracting a bigger number */
		negate = 1;
		swp = bi1;
		bi1 = bi2;
		bi2 = swp;
	} else {
		/* subtracting normally */
		negate = 0;
	}
	if (err) {
		goto ehbi_subtract_end;
	}

	/* we don't wish to modify the real bi1, so use tmp */
	size = bi1->bytes_len;
	Ehbi_stack_alloc_struct_j(tmp, size, err, ehbi_subtract_end);
	err = ehbi_set(&tmp, bi1);
	if (err) {
		goto ehbi_subtract_end;
	}
	bi1a = &tmp;

	res->bytes_used = 0;
	c = 0;
	for (i = 1; i <= bi1a->bytes_used; ++i) {
		if (bi1a->bytes_used < i) {
			a = 0;
		} else {
			a = bi1a->bytes[bi1a->bytes_len - i];
		}
		if ((bi2->bytes_used < i) || (i > bi2->bytes_len)) {
			b = 0;
		} else {
			b = bi2->bytes[bi2->bytes_len - i];
		}
		c = (a - b);

		if (i > res->bytes_len) {
			Ehbi_log_error0("Result byte[] too small");
			goto ehbi_subtract_end;
		}
		res->bytes[res->bytes_len - i] = c;
		res->bytes_used++;

		/* need to borrow */
		if (b > a) {
			c = 0x01;
			j = i + 1;
			while (c == 0x01) {
				if (j > bi1a->bytes_used) {
					Ehbi_log_error0("bytes for borrow");
					err = EHBI_CORRUPT_DATA;
					goto ehbi_subtract_end;
				}
				c = (bi1a->bytes[bi1a->bytes_len - j] ==
				     0x00) ? 0x01 : 0x00;
				--(bi1a->bytes[bi1a->bytes_len - j]);
				++j;
			}
			ehbi_unsafe_reset_bytes_used(bi1a);
		}
	}

	res->sign = (negate) ? !(bi1->sign) : bi1->sign;

	if ((res->bytes_used == 1) && (res->bytes[res->bytes_len - 1] == 0x00)) {
		res->sign = 0;
	}
	ehbi_unsafe_reset_bytes_used(res);

ehbi_subtract_end:
	if (err && res) {
		ehbi_zero(res);
	}
	if (tmp.bytes) {
		ehbi_stack_free(tmp.bytes, tmp.bytes_len);
	}

	Trace_msg_s_bi(2, "end", res);
	Return_i(2, EHBI_SUCCESS);
}

static int ehbi_bytes_shift_left(struct ehbigint *bi, size_t num_bytes)
{
	size_t i;

	Trace_bi_l(2, bi, ((long)num_bytes));

	Ehbi_struct_is_not_null(2, bi);

	if (num_bytes == 0) {
		Trace_msg_s_bi(2, "end", bi);
		Return_i(2, EHBI_SUCCESS);
	}

	if (bi->bytes_len < (bi->bytes_used + num_bytes)) {
		Ehbi_log_error3("Result byte[] too small for shift"
				" (bi->bytes_len <"
				" (bi->bytes_used + num_bytes))"
				" (%lu < (%lu + %lu))",
				(unsigned long)bi->bytes_len,
				(unsigned long)bi->bytes_used,
				(unsigned long)num_bytes);
		Return_i(2, EHBI_BYTES_TOO_SMALL_FOR_CARRY);
	}

	bi->bytes_used += num_bytes;

	/* shift the value left by num_bytes bytes */
	for (i = 0; i < bi->bytes_len; ++i) {
		/* shift the value byte one byte */
		if (i + num_bytes >= bi->bytes_len) {
			/* set the zero/-1 value on the right */
			bi->bytes[i] = bi->bytes[0];
		} else {
			bi->bytes[i] = bi->bytes[i + num_bytes];
		}
	}

	/* make sure we keep "bytes_used" reasonable */
	while (bi->bytes_used > 1
	       && bi->bytes[bi->bytes_len - bi->bytes_used] == bi->bytes[0]
	       && bi->bytes[bi->bytes_len - (bi->bytes_used - 1)] < 0x80) {
		--(bi->bytes_used);
	}

	Trace_msg_s_bi(2, "end", bi);
	Return_i(2, EHBI_SUCCESS);
}

static int ehbi_bytes_shift_right(struct ehbigint *bi, size_t num_bytes)
{
	size_t i;

	Trace_bi_l(2, bi, ((long)num_bytes));

	Ehbi_struct_is_not_null(2, bi);

	if (num_bytes == 0) {
		Trace_msg_s_bi(2, "end", bi);
		Return_i(2, EHBI_SUCCESS);
	}

	if (bi->bytes_used <= num_bytes) {
		ehbi_unsafe_zero(bi);

		Trace_msg_s_bi(2, "end", bi);
		Return_i(2, EHBI_SUCCESS);
	}

	/* shift the value left by num_bytes bytes */
	for (i = bi->bytes_len; i > 0; --i) {
		if (i > num_bytes) {
			bi->bytes[i - 1] = bi->bytes[i - (1 + num_bytes)];
		} else {
			bi->bytes[i - 1] = 0x00;
		}
	}
	bi->bytes_used -= num_bytes;

	Trace_msg_s_bi(2, "end", bi);
	Return_i(2, EHBI_SUCCESS);
}

int ehbi_shift_right(struct ehbigint *bi, unsigned long num_bits)
{
	size_t bytes;
	int err;
	struct eba_s eba;

	Trace_bi_l(2, bi, ((long)num_bits));

#ifndef EBA_SKIP_ENDIAN
	eba.endian = eba_big_endian;
#endif
	eba.bits = NULL;
	eba.size_bytes = 0;

	Ehbi_struct_is_not_null(2, bi);

	if ((num_bits % 8UL) == 0) {
		bytes = (size_t)(num_bits / 8UL);
		err = ehbi_bytes_shift_right(bi, bytes);

		Trace_msg_s_bi(2, "end", bi);
		Return_i(2, err);
	}

	eba.bits = bi->bytes;
	eba.size_bytes = bi->bytes_len;

	ehbi_eba_err = EHBI_SUCCESS;
	eba_shift_right(&eba, num_bits);
	err = ehbi_eba_err;

	ehbi_unsafe_reset_bytes_used(bi);

	if (err) {
		ehbi_zero(bi);
	}

	Trace_msg_s_bi(2, "end", bi);
	Return_i(2, err);
}

int ehbi_shift_left(struct ehbigint *bi, unsigned long num_bits)
{
	size_t bytes;
	int err;
	struct eba_s eba;

	Trace_bi_l(2, bi, ((long)num_bits));

	Ehbi_struct_is_not_null(2, bi);

	if ((num_bits % 8UL) == 0) {
		bytes = (size_t)(num_bits / 8UL);
		err = ehbi_bytes_shift_left(bi, bytes);

		Trace_msg_s_bi(2, "end", bi);
		Return_i(2, err);
	}
#ifndef EBA_SKIP_ENDIAN
	eba.endian = eba_big_endian;
#endif
	eba.bits = bi->bytes;
	eba.size_bytes = bi->bytes_len;

	ehbi_eba_err = EHBI_SUCCESS;
	eba_shift_left(&eba, num_bits);
	err = ehbi_eba_err;

	ehbi_unsafe_reset_bytes_used(bi);

	if (err) {
		ehbi_zero(bi);
	}

	Trace_msg_s_bi(2, "end", bi);
	Return_i(2, err);
}

#ifndef EHBI_SKIP_IS_PROBABLY_PRIME

static const long SMALL_PRIMES[] = {
	2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
	71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
	149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
	227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
	307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383,
	389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
	467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569,
	571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647,
	653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743,
	751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839,
	853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
	947, 953, 967, 971, 977, 983, 991, 997,
	0			/* ZERO terminated */
};

int ehbi_is_probably_prime(const struct ehbigint *bi, unsigned int accuracy,
			   int *err)
{
	size_t i, j, trial_divs, max_rnd, shift, size;
	int is_probably_prime, stop;
	struct ehbigint zero, one, two;
	unsigned char z_bytes[4], o_bytes[4], t_bytes[4];
	struct ehbigint bimin1, a, r, d, x, y, c, max_witness;

	Trace_bi_l(2, bi, ((long)accuracy));

	ehbi_unsafe_clear_null_struct(&zero);
	ehbi_unsafe_clear_null_struct(&one);
	ehbi_unsafe_clear_null_struct(&two);
	ehbi_unsafe_clear_null_struct(&a);
	ehbi_unsafe_clear_null_struct(&r);
	ehbi_unsafe_clear_null_struct(&d);
	ehbi_unsafe_clear_null_struct(&x);
	ehbi_unsafe_clear_null_struct(&y);
	ehbi_unsafe_clear_null_struct(&max_witness);

	Ehbi_struct_is_not_null(2, bi);

	*err = EHBI_SUCCESS;
	is_probably_prime = 0;

	if (ehbi_is_negative(bi, err)) {
		Return_i(2, 0);
	}

	ehbi_init(&zero, z_bytes, 4);

	ehbi_init(&one, o_bytes, 4);
	ehbi_inc_l(&one, 1);

	ehbi_init(&two, t_bytes, 4);
	ehbi_inc_l(&two, 2);

	size = bi->bytes_used;
	if (size < 4) {
		size = 4;
	}
	Ehbi_stack_alloc_struct_j(bimin1, size, *err,
				  ehbi_is_probably_prime_end);

	Ehbi_stack_alloc_struct_j(max_witness, size, *err,
				  ehbi_is_probably_prime_end);

	size = 2 + (bi->bytes_len * 2);
	Ehbi_stack_alloc_struct_j(a, size, *err, ehbi_is_probably_prime_end);
	Ehbi_stack_alloc_struct_j(r, size, *err, ehbi_is_probably_prime_end);
	Ehbi_stack_alloc_struct_j(d, size, *err, ehbi_is_probably_prime_end);
	Ehbi_stack_alloc_struct_j(x, size, *err, ehbi_is_probably_prime_end);
	Ehbi_stack_alloc_struct_j(y, size, *err, ehbi_is_probably_prime_end);
	Ehbi_stack_alloc_struct_j(c, size, *err, ehbi_is_probably_prime_end);

	/* set d to 2, the first prime */
	*err = *err || ehbi_set_l(&d, SMALL_PRIMES[0]);
	if (*err || ehbi_less_than(bi, &d, err)) {
		is_probably_prime = 0;
		goto ehbi_is_probably_prime_end;
	}

	/* 2 is the only even prime */
	if (!ehbi_is_odd(bi, err)) {
		is_probably_prime = ehbi_equals(bi, &d, err);
		goto ehbi_is_probably_prime_end;
	}

	/* first some trial divsion */
	trial_divs = EHBI_NUM_SMALL_PRIMES_TO_TRIAL_DIVIDE;
	for (i = 1; SMALL_PRIMES[i] != 0 && i <= trial_divs; ++i) {
		*err = *err || ehbi_set_l(&d, SMALL_PRIMES[i]);
		if (ehbi_equals(bi, &d, err)) {
			is_probably_prime = 1;
			goto ehbi_is_probably_prime_end;
		}

		*err = *err || ehbi_div(&a, &r, bi, &d);
		if (*err || ehbi_equals(&r, &zero, err)) {
			is_probably_prime = 0;
			goto ehbi_is_probably_prime_end;
		}
	}

	is_probably_prime = 1;

	/*
	   write n-1 as 2^r * d;
	   with d odd by factoring powers of 2 from n-1
	 */
	ehbi_subtract(&d, bi, &one);
	/* d is now bi-1 */

	for (i = 0; *err == EHBI_SUCCESS; ++i) {
		if (ehbi_is_odd(&d, err)) {
			break;
		}
		*err = *err || ehbi_shift_right(&d, 1);
	}
	if (*err) {
		goto ehbi_is_probably_prime_end;
	}
	ehbi_set_l(&r, (long)i);
	/* (bi-1) == 2^(r) * d */

	if (accuracy < EHBI_MIN_TRIALS_FOR_IS_PROBABLY_PRIME) {
		accuracy = EHBI_DEFAULT_TRIALS_FOR_IS_PROBABLY_PRIME;
	}

	ehbi_set(&bimin1, bi);
	ehbi_dec(&bimin1, &one);

	/* we will set max_witness at n-2 */
	ehbi_set(&max_witness, bi);
	ehbi_dec(&max_witness, &two);

	/*
	   WitnessLoop: repeat k times:
	 */
	for (i = 0; i < accuracy; ++i) {
		if (*err) {
			goto ehbi_is_probably_prime_end;
		}

		j = 0;
		max_rnd = EHBI_MAX_TRIES_TO_GRAB_RANDOM_BYTES;
		/* pick a random integer a in the range [2, n-2] */
		do {
			*err = ehbi_random_bytes(a.bytes, a.bytes_len);
			a.bytes_used = a.bytes_len;
			shift = a.bytes_len - max_witness.bytes_used;
			*err = ehbi_bytes_shift_right(&a, shift);
			ehbi_unsafe_reset_bytes_used(&a);
		} while ((ehbi_greater_than(&a, &max_witness, err)
			  || ehbi_less_than(&a, &two, err)) && (j++ < max_rnd));
		if (ehbi_greater_than(&a, &max_witness, err)
		    || ehbi_less_than(&a, &two, err)) {
			/* but, too big, so do something totally bogus: */
			*err = *err || ehbi_set_l(&a, 2 + i);
		}
		/* still too big, we are done */
		if (ehbi_greater_than(&a, &max_witness, err)) {
			is_probably_prime = 1;
			goto ehbi_is_probably_prime_end;
		}

		/* x := a^d mod n */
		*err = ehbi_exp_mod(&x, &a, &d, bi);
		if (*err) {
			goto ehbi_is_probably_prime_end;
		}

		/* if x == 1 or x == n-1 then continue WitnessLoop */
		if (ehbi_equals(&x, &one, err)) {
			continue;
		}
		if (*err) {
			goto ehbi_is_probably_prime_end;
		}
		if (ehbi_equals(&x, &bimin1, err)) {
			continue;
		}
		if (*err) {
			goto ehbi_is_probably_prime_end;
		}

		/* repeat r-1 times: */
		*err = *err || ehbi_set(&c, &r);
		*err = *err || ehbi_dec(&c, &one);
		if (*err) {
			goto ehbi_is_probably_prime_end;
		}
		stop = 0;
		while (!stop && ehbi_greater_than(&c, &zero, err)) {
			*err = *err || ehbi_dec(&c, &one);

			/* x := x^2 mod n */
			*err = *err || ehbi_set(&y, &x);
			*err = *err || ehbi_exp_mod(&x, &y, &two, bi);

			/* if x == 1 then return composite */
			if (ehbi_equals(&x, &one, err)) {
				is_probably_prime = 0;
				goto ehbi_is_probably_prime_end;
			}

			/* if x == n-1 then continue WitnessLoop */
			if (ehbi_equals(&x, &bimin1, err)) {
				stop = 1;
				break;
			}
		}
		if (!stop) {
			/* Return_i(composite); */
			is_probably_prime = 0;
			goto ehbi_is_probably_prime_end;
		}
	}

	/* return probably prime */
	is_probably_prime = 1;

ehbi_is_probably_prime_end:
	if (*err) {
		Ehbi_log_error1("error %d, setting is_probably_prime = 0",
				*err);
		is_probably_prime = 0;
	}
	if (bimin1.bytes) {
		ehbi_stack_free(bimin1.bytes, bimin1.bytes_len);
	}
	if (a.bytes) {
		ehbi_stack_free(a.bytes, a.bytes_len);
	}
	if (r.bytes) {
		ehbi_stack_free(r.bytes, r.bytes_len);
	}
	if (d.bytes) {
		ehbi_stack_free(d.bytes, d.bytes_len);
	}
	if (x.bytes) {
		ehbi_stack_free(x.bytes, x.bytes_len);
	}
	if (y.bytes) {
		ehbi_stack_free(y.bytes, y.bytes_len);
	}
	if (c.bytes) {
		ehbi_stack_free(c.bytes, c.bytes_len);
	}
	if (max_witness.bytes) {
		ehbi_stack_free(max_witness.bytes, max_witness.bytes_len);
	}

	Return_i(2, is_probably_prime);
}

#endif /* EHBI_SKIP_IS_PROBABLY_PRIME */

int ehbi_negate(struct ehbigint *bi)
{
	int err;

	Trace_bi(6, bi);

	Ehbi_struct_is_not_null(6, bi);

	bi->sign = (bi->sign == 0) ? 1 : 0;

	err = EHBI_SUCCESS;

	ehbi_unsafe_reset_bytes_used(bi);

	Trace_msg_s_bi(6, "end", bi);
	Return_i(6, err);
}

int ehbi_is_negative(const struct ehbigint *bi, int *err)
{
	int rv;

	Trace_bi(8, bi);

	Ehbi_struct_is_not_null_e(8, bi, err);

	/* guard for negative zero? */
	if (bi->bytes_used == 0) {
		Return_i(8, 0);
	}
	if (bi->bytes_used == 1) {
		if (bi->bytes[bi->bytes_len - 1] == 0x00) {
			Return_i(8, 0);
		}
	}

	rv = (bi->sign == 0) ? 0 : 1;
	Return_i(8, rv);
}

int ehbi_compare(const struct ehbigint *bi1, const struct ehbigint *bi2,
		 int *err)
{
	size_t i;
	unsigned char a, b;
	int rv, b1_pos, b2_pos;

	Trace_bi_bi(8, bi1, bi2);

	Ehbi_struct_is_not_null_e(8, bi1, err);
	Ehbi_struct_is_not_null_e(8, bi2, err);

	*err = EHBI_SUCCESS;

	b1_pos = !ehbi_is_negative(bi1, err);
	b2_pos = !ehbi_is_negative(bi2, err);

	if (b1_pos != b2_pos) {
		rv = b1_pos ? 1 : -1;
		Return_i(8, rv);
	}

	if (bi1->bytes_used > bi2->bytes_used) {
		rv = b1_pos ? 1 : -1;
		Return_i(8, rv);
	} else if (bi1->bytes_used < bi2->bytes_used) {
		rv = b1_pos ? -1 : 1;
		Return_i(8, rv);
	}

	for (i = 0; i < bi1->bytes_used; ++i) {
		a = bi1->bytes[(bi1->bytes_len - bi1->bytes_used) + i];
		b = bi2->bytes[(bi2->bytes_len - bi2->bytes_used) + i];
		if (a > b) {
			rv = b1_pos ? 1 : -1;
			Return_i(8, rv);
		} else if (a < b) {
			rv = b1_pos ? -1 : 1;
			Return_i(8, rv);
		}
	}

	rv = 0;
	Return_i(8, rv);
}

int ehbi_equals(const struct ehbigint *bi1, const struct ehbigint *bi2,
		int *err)
{
	int rv, terr;

	Trace_bi_bi(8, bi1, bi2);

	Ehbi_struct_is_not_null_e(8, bi1, err);
	Ehbi_struct_is_not_null_e(8, bi2, err);

	err = (err != NULL) ? err : &terr;
	rv = ((ehbi_compare(bi1, bi2, err) == 0) && (*err == EHBI_SUCCESS));

	Return_i(8, rv);
}

int ehbi_less_than(const struct ehbigint *bi1, const struct ehbigint *bi2,
		   int *err)
{
	int rv, terr;

	Trace_bi_bi(8, bi1, bi2);

	Ehbi_struct_is_not_null_e(8, bi1, err);
	Ehbi_struct_is_not_null_e(8, bi2, err);

	err = (err != NULL) ? err : &terr;
	rv = ((ehbi_compare(bi1, bi2, err) < 0) && (*err == EHBI_SUCCESS));

	Return_i(8, rv);
}

int ehbi_greater_than(const struct ehbigint *bi1, const struct ehbigint *bi2,
		      int *err)
{
	int rv, terr;

	Trace_bi_bi(8, bi1, bi2);

	Ehbi_struct_is_not_null_e(8, bi1, err);
	Ehbi_struct_is_not_null_e(8, bi2, err);

	err = (err != NULL) ? err : &terr;
	rv = ((ehbi_compare(bi1, bi2, err) > 0) && (*err == EHBI_SUCCESS));

	Return_i(8, rv);
}

int ehbi_is_odd(const struct ehbigint *bi, int *err)
{
	unsigned char bit;
	int rv;

	Trace_bi(8, bi);

	Ehbi_struct_is_not_null_e(8, bi, err);

	bit = 0x01 & bi->bytes[bi->bytes_len - 1];
	rv = bit ? 1 : 0;

	Return_i(8, rv);
}

#undef Ehbi_stack_alloc_struct_j
#undef Ehbi_stack_alloc_struct

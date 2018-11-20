/*
ehbigint.c: slow Big Int library hopefully somewhat suitable for 8bit CPUs
Copyright (C) 2016, 2018 Eric Herman <eric@freesa.org>

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

#include <limits.h>              /* LONG_MAX */

static int ehbi_bytes_shift_right(struct ehbigint *bi, size_t num_bytes);
static int ehbi_bytes_shift_left(struct ehbigint *bi, size_t num_bytes);

static void ehbi_unsafe_struct_l(struct ehbigint *temp, long val)
{
	unsigned long v;
	unsigned char c;
	size_t i, j;

	temp->bytes_used = sizeof(unsigned long);

	v = (val < 0) ? (unsigned long)(-val) : (unsigned long)val;

	for (i = 0; i < temp->bytes_used; ++i) {
		c = (v >> (8 * i));
		j = (temp->bytes_len - 1) - i;
		temp->bytes[j] = c;
	}
	temp->sign = (val < 0);
	ehbi_unsafe_reset_bytes_used(temp);
}

int ehbi_init(struct ehbigint *bi, unsigned char *bytes, size_t len)
{
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

	Eba_memset(bytes, 0x00, len);

	bi->bytes = bytes;
	bi->bytes_len = len;
	bi->bytes_used = 1;

	return EHBI_SUCCESS;
}

int ehbi_init_l(struct ehbigint *bi, unsigned char *bytes, size_t len, long val)
{
	int err;
	err = ehbi_init(bi, bytes, len);
	if (!err) {
		err = ehbi_set_l(bi, val);
	}
	return err;
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
	size_t offset, voffset;

	Trace_bi_bi(6, bi, val);

	Ehbi_struct_is_not_null(6, bi);
	Ehbi_struct_is_not_null(6, val);

	if (val->bytes_used > bi->bytes_len) {
		ehbi_unsafe_zero(bi);
		Ehbi_log_error0("Result byte[] too small");
		Return_i(6, EHBI_BYTES_TOO_SMALL);
	}
	bi->sign = val->sign;
	bi->bytes_used = val->bytes_used;

	offset = bi->bytes_len - bi->bytes_used;
	if (offset) {
		Eba_memset(bi->bytes, 0x00, offset);
	}

	voffset = val->bytes_len - val->bytes_used;
	Eba_memcpy(bi->bytes + offset, val->bytes + voffset, val->bytes_used);

	/* see also ehbi_unsafe_reset_bytes_used */
	if (offset && (bi->bytes[offset] > 0x7F)) {
		++(bi->bytes_used);
	}

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
		if (!err) {
			err = ehbi_negate(&tmp);
		}
		if (!err) {
			err = ehbi_subtract(res, bi1, &tmp);
		}
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

int ehbi_add_l(struct ehbigint *res, const struct ehbigint *bi1, long v2)
{
	unsigned char bytes[sizeof(unsigned long)];
	struct ehbigint temp;
	int err;

	Trace_bi_bi_l(4, res, bi1, v2);

	ehbi_unsafe_clear_null_struct(&temp);

	Ehbi_struct_is_not_null(4, res);
	Ehbi_struct_is_not_null(4, bi1);

	temp.bytes = bytes;
	temp.bytes_len = sizeof(unsigned long);

	ehbi_unsafe_struct_l(&temp, v2);

	err = ehbi_add(res, bi1, &temp);

	Trace_msg_s_bi(4, "end", res);
	Return_i(4, err);
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
			if (!err) {
				err = ehbi_set_l(&tmp, r);
			}
			if (!err) {
				err = ehbi_bytes_shift_left(&tmp, i);
			}
			if (!err) {
				err = ehbi_bytes_shift_left(&tmp, j);
			}
			if (!err) {
				err = ehbi_inc(res, &tmp);
			}
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

int ehbi_mul_l(struct ehbigint *res, const struct ehbigint *bi1, long v2)
{
	unsigned char bytes[sizeof(unsigned long)];
	struct ehbigint temp;
	int err;

	Trace_bi_bi_l(4, res, bi1, v2);

	ehbi_unsafe_clear_null_struct(&temp);

	Ehbi_struct_is_not_null(4, res);
	Ehbi_struct_is_not_null(4, bi1);

	temp.bytes = bytes;
	temp.bytes_len = sizeof(unsigned long);

	ehbi_unsafe_struct_l(&temp, v2);

	err = ehbi_mul(res, bi1, &temp);

	Trace_msg_s_bi(4, "end", res);
	Return_i(4, err);
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
		if (!err) {
			err = ehbi_negate(&s_abs_numer);
		}
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
		if (!err) {
			err = ehbi_negate(&s_abs_denom);
		}
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
	while (!err && (ehbi_greater_than(remainder, abs_denom, &err)
			|| ehbi_equals(remainder, abs_denom, &err))) {
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
		while (!err && ehbi_less_than(remainder, abs_denom, &err)
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

int ehbi_div_l(struct ehbigint *quotient, struct ehbigint *remainder,
	       const struct ehbigint *numerator, long denominator)
{
	unsigned char bytes[sizeof(unsigned long)];
	struct ehbigint temp;
	int err;

	Trace_bi_bi_bi_l(4, quotient, remainder, numerator, denominator);

	ehbi_unsafe_clear_null_struct(&temp);

	Ehbi_struct_is_not_null(4, quotient);
	Ehbi_struct_is_not_null(4, remainder);
	Ehbi_struct_is_not_null(4, numerator);

	temp.bytes = bytes;
	temp.bytes_len = sizeof(unsigned long);

	ehbi_unsafe_struct_l(&temp, denominator);

	err = ehbi_div(quotient, remainder, numerator, &temp);

	Trace_msg_s_bi(4, "end", quotient);
	Return_i(4, err);
}

int ehbi_sqrt(struct ehbigint *result, struct ehbigint *remainder,
	      const struct ehbigint *val)
{
	int err;
	struct ehbigint zero, one, two;
	struct ehbigint guess, temp, junk;
	unsigned char zbytes[2];
	unsigned char obytes[2];
	unsigned char tbytes[2];
	size_t size;

	Trace_bi_bi_bi(2, result, remainder, val);

	ehbi_unsafe_clear_null_struct(&zero);
	ehbi_unsafe_clear_null_struct(&one);
	ehbi_unsafe_clear_null_struct(&two);

	ehbi_unsafe_clear_null_struct(&guess);
	ehbi_unsafe_clear_null_struct(&temp);
	ehbi_unsafe_clear_null_struct(&junk);

	zero.bytes = zbytes;
	zero.bytes_len = 2;
	ehbi_unsafe_zero(&zero);

	one.bytes = obytes;
	one.bytes_len = 2;
	ehbi_unsafe_zero(&one);
	ehbi_inc_l(&one, 1);

	two.bytes = tbytes;
	two.bytes_len = 2;
	ehbi_unsafe_zero(&two);
	ehbi_inc_l(&two, 2);

	Ehbi_struct_is_not_null(2, result);
	Ehbi_struct_is_not_null(2, remainder);
	Ehbi_struct_is_not_null(2, val);

	ehbi_unsafe_zero(result);
	ehbi_unsafe_zero(remainder);

	err = EHBI_SUCCESS;

	if (ehbi_less_than(val, &zero, &err)) {
		err = EHBI_SQRT_NEGATIVE;
		Ehbi_log_error0("square root of a negative would be complex");
		Return_i(2, err);
	}

	if (ehbi_equals(val, &zero, &err)) {
		Return_i(2, err);
	}

	size = 1 + val->bytes_used;
	Ehbi_stack_alloc_struct_j(guess, size, err, ehbi_sqrt_end);

	size = 1 + (val->bytes_used * 2);
	Ehbi_stack_alloc_struct_j(temp, size, err, ehbi_sqrt_end);
	Ehbi_stack_alloc_struct_j(junk, size, err, ehbi_sqrt_end);

	/* odd cases below square root of 4 */
	if (!err) {
		err = ehbi_set_l(&temp, 4);
	}
	if (ehbi_less_than(val, &temp, &err)) {
		if (!err) {
			err = ehbi_set_l(result, 1);
		}
		if (!err) {
			err = ehbi_subtract(remainder, val, result);
		}
		goto ehbi_sqrt_end;
	}

	/* Initial estimate, never low */
	/* result = (val / 2) + 1; */
	if (!err) {
		err = ehbi_div(result, &junk, val, &two);
	}
	if (!err) {
		err = ehbi_inc(result, &one);
	}

	/* guess = (result + (val / result)) / 2; */
	if (!err) {
		err = ehbi_div(&temp, &junk, val, result);
	}
	if (!err) {
		err = ehbi_inc(&temp, result);
	}
	if (!err) {
		err = ehbi_div(&guess, &junk, &temp, &two);
	}

	while (!err && ehbi_less_than(&guess, result, &err)) {
		/* result = guess; */
		if (!err) {
			err = ehbi_set(result, &guess);
		}
		/* guess = (result + (val / result)) / 2; */
		if (!err) {
			err = ehbi_div(&temp, &junk, val, result);
		}
		if (!err) {
			err = ehbi_inc(&temp, result);
		}
		if (!err) {
			err = ehbi_div(&guess, &junk, &temp, &two);
		}
	}
	if (!err) {
		err = ehbi_mul(&temp, result, result);
	}
	if (!err) {
		err = ehbi_subtract(remainder, val, &temp);
	}

ehbi_sqrt_end:
	if (guess.bytes) {
		ehbi_stack_free(guess.bytes, guess.bytes_len);
	}
	if (temp.bytes) {
		ehbi_stack_free(temp.bytes, temp.bytes_len);
	}
	if (junk.bytes) {
		ehbi_stack_free(junk.bytes, junk.bytes_len);
	}

	if (err) {
		ehbi_zero(result);
		ehbi_zero(remainder);
	}

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
	if (!err) {
		err = ehbi_set_l(result, 1);
	}

	while (!err && ehbi_less_than(&loop, exponent, &err)) {
		if (!err) {
			err = ehbi_mul(&tmp, result, base);
		}
		if (!err) {
			err = ehbi_set(result, &tmp);
		}
		if (!err) {
			err = ehbi_inc_l(&loop, 1);
		}
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

int ehbi_exp_l(struct ehbigint *result, const struct ehbigint *base, long exp)
{
	unsigned char bytes[sizeof(unsigned long)];
	struct ehbigint temp;
	int err;

	Trace_bi_bi_l(4, result, base, exp);

	ehbi_unsafe_clear_null_struct(&temp);

	Ehbi_struct_is_not_null(4, result);
	Ehbi_struct_is_not_null(4, base);

	temp.bytes = bytes;
	temp.bytes_len = sizeof(unsigned long);

	ehbi_unsafe_struct_l(&temp, exp);

	err = ehbi_exp(result, base, &temp);

	Trace_msg_s_bi(4, "end", result);
	Return_i(4, err);

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

	if (!err) {
		err = ehbi_set(&tbase, base);
	}
	if (!err) {
		err = ehbi_set(&texp, exponent);
	}

	/* result := 1 */
	if (!err) {
		err = ehbi_set_l(result, 1);
	}
	if (err) {
		goto ehbi_mod_exp_end;
	}

	/* base := base mod modulus */
	if (!err) {
		err = ehbi_div(&tjunk, &tbase, base, modulus);
	}

	/* while exponent > 0 */
	while (!err && ehbi_greater_than(&texp, &zero, &err)) {
		if (err) {
			goto ehbi_mod_exp_end;
		}

		/* if (exponent mod 2 == 1): */
		if (ehbi_is_odd(&texp, &err)) {
			/* result := (result * base) mod modulus */
			if (!err) {
				err = ehbi_mul(&tmp1, result, &tbase);
			}
			if (!err) {
				err = ehbi_div(&tjunk, result, &tmp1, modulus);
			}
		}

		/* exponent := exponent >> 1 */
		if (!err) {
			err = ehbi_shift_right(&texp, 1);
		}

		/* base := (base * base) mod modulus */
		if (!err) {
			err = ehbi_mul(&tmp1, &tbase, &tbase);
		}
		if (!err) {
			err = ehbi_div(&tjunk, &tbase, &tmp1, modulus);
		}

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

int ehbi_exp_mod_l(struct ehbigint *result, const struct ehbigint *base,
		   const struct ehbigint *exponent, long modulus)
{
	unsigned char bytes[sizeof(unsigned long)];
	struct ehbigint temp;
	int err;

	Trace_bi_bi_bi_l(4, result, base, exponent, modulus);

	ehbi_unsafe_clear_null_struct(&temp);

	Ehbi_struct_is_not_null(4, result);
	Ehbi_struct_is_not_null(4, base);
	Ehbi_struct_is_not_null(4, exponent);

	temp.bytes = bytes;
	temp.bytes_len = sizeof(unsigned long);

	ehbi_unsafe_struct_l(&temp, modulus);

	err = ehbi_exp_mod(result, base, exponent, &temp);

	Trace_msg_s_bi(4, "end", result);
	Return_i(4, err);
}

int ehbi_exp_mod_ll(struct ehbigint *result, const struct ehbigint *base,
		    long exponent, long modulus)
{
	unsigned char bytes1[sizeof(unsigned long)];
	struct ehbigint temp1;
	unsigned char bytes2[sizeof(unsigned long)];
	struct ehbigint temp2;
	int err;

	Trace_bi_bi_l_l(4, result, base, exponent, modulus);

	ehbi_unsafe_clear_null_struct(&temp1);
	ehbi_unsafe_clear_null_struct(&temp2);

	Ehbi_struct_is_not_null(4, result);
	Ehbi_struct_is_not_null(4, base);

	temp1.bytes = bytes1;
	temp1.bytes_len = sizeof(unsigned long);

	temp2.bytes = bytes2;
	temp2.bytes_len = sizeof(unsigned long);

	ehbi_unsafe_struct_l(&temp1, exponent);
	ehbi_unsafe_struct_l(&temp2, modulus);

	err = ehbi_exp_mod(result, base, &temp1, &temp2);

	Trace_msg_s_bi(4, "end", result);
	Return_i(4, err);
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
	if (!err) {
		err = ehbi_add(bi, &temp, val);
	}
	ehbi_stack_free(temp.bytes, temp.bytes_len);

	Trace_msg_s_bi(4, "end", bi);
	Return_i(4, err);
}

int ehbi_inc_l(struct ehbigint *bi, long val)
{
	unsigned char bytes[sizeof(unsigned long)];
	struct ehbigint temp;
	int err;

	Trace_bi_l(4, bi, val);

	ehbi_unsafe_clear_null_struct(&temp);

	Ehbi_struct_is_not_null(4, bi);

	temp.bytes = bytes;
	temp.bytes_len = sizeof(unsigned long);

	ehbi_unsafe_struct_l(&temp, val);

	err = ehbi_inc(bi, &temp);

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

	if (!err) {
		err = ehbi_subtract(&temp, bi, val);
	}
	if (!err) {
		err = ehbi_set(bi, &temp);
	}

	ehbi_stack_free(temp.bytes, temp.bytes_len);

	Trace_msg_s_bi(4, "end", bi);
	Return_i(4, err);
}

int ehbi_dec_l(struct ehbigint *bi, long val)
{
	unsigned char bytes[sizeof(unsigned long)];
	struct ehbigint temp;
	int err;

	Trace_bi_l(4, bi, val);

	ehbi_unsafe_clear_null_struct(&temp);

	Ehbi_struct_is_not_null(4, bi);

	temp.bytes = bytes;
	temp.bytes_len = sizeof(unsigned long);

	ehbi_unsafe_struct_l(&temp, val);

	err = ehbi_dec(bi, &temp);

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
		if (!err) {
			err = ehbi_negate(res);
		}
		goto ehbi_subtract_end;
	}

	/* subtracting a negative */
	if (bi1->sign == 0 && bi2->sign != 0) {
		size = bi2->bytes_len;
		Ehbi_stack_alloc_struct_j(tmp, size, err, ehbi_subtract_end);
		err = ehbi_set(&tmp, bi2);
		if (!err) {
			err = ehbi_negate(&tmp);
		}
		if (!err) {
			err = ehbi_add(res, bi1, &tmp);
		}
		goto ehbi_subtract_end;
	}

	/* negative subtracting a positive */
	if (bi1->sign != 0 && bi2->sign == 0) {
		size = bi1->bytes_len;
		Ehbi_stack_alloc_struct_j(tmp, size, err, ehbi_subtract_end);
		err = ehbi_set(&tmp, bi1);
		if (!err) {
			err = ehbi_negate(&tmp);
		}
		if (!err) {
			err = ehbi_add(res, &tmp, bi2);
		}
		if (!err) {
			err = ehbi_negate(res);
		}
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

int ehbi_subtract_l(struct ehbigint *res, const struct ehbigint *bi1, long v2)
{
	unsigned char bytes[sizeof(unsigned long)];
	struct ehbigint temp;
	int err;

	Trace_bi_bi_l(4, res, bi1, v2);

	ehbi_unsafe_clear_null_struct(&temp);

	Ehbi_struct_is_not_null(4, res);
	Ehbi_struct_is_not_null(4, bi1);

	temp.bytes = bytes;
	temp.bytes_len = sizeof(unsigned long);

	ehbi_unsafe_struct_l(&temp, v2);

	err = ehbi_subtract(res, bi1, &temp);

	Trace_msg_s_bi(4, "end", res);
	Return_i(4, err);
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

	eba.endian = eba_big_endian;
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
	eba.endian = eba_big_endian;
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

int ehbi_n_choose_k(struct ehbigint *result, const struct ehbigint *n,
		    const struct ehbigint *k)
{
	int err;
	size_t i, size;
	struct ehbigint sum_n, sum_k, tmp;

	Trace_bi_bi_bi(2, result, n, k);

	Ehbi_struct_is_not_null(2, result);
	Ehbi_struct_is_not_null(2, n);
	Ehbi_struct_is_not_null(2, k);

	err = 0;

	if ((!err && ehbi_greater_than(k, n, &err))
	    || (!err && ehbi_less_than_l(k, 0, &err))) {
		if (!err) {
			err = ehbi_set_l(result, 0);
		}
		goto ehbi_n_choose_k_end;
	}
	if ((!err && ehbi_equals_l(k, 0, &err))
	    || (!err && ehbi_equals(k, n, &err))) {
		if (!err) {
			err = ehbi_set_l(result, 1);
		}
		goto ehbi_n_choose_k_end;
	}
	if (!err && ehbi_equals_l(k, 1, &err)) {
		if (!err) {
			err = ehbi_set(result, n);
		}
		goto ehbi_n_choose_k_end;
	}
	if (!err && ehbi_greater_than_l(k, LONG_MAX, &err)) {
		Ehbi_log_error1("k larger than %ld", LONG_MAX);
		err = EHBI_BAD_DATA;
		goto ehbi_n_choose_k_end;
	}

	size = result->bytes_len;
	if (size < n->bytes_len) {
		size = n->bytes_len;
	}
	if (size < k->bytes_len) {
		size = k->bytes_len;
	}

	Ehbi_stack_alloc_struct(tmp, size, err);
	if (err) {
		Return_i(2, err);
	}
	Ehbi_stack_alloc_struct(sum_n, size, err);
	if (err) {
		Return_i(2, err);
	}
	Ehbi_stack_alloc_struct(sum_k, size, err);
	if (err) {
		Return_i(2, err);
	}

	if (!err) {
		err = ehbi_inc(&sum_n, n);
	}
	if (!err) {
		err = ehbi_inc(&sum_k, k);
	}
	for (i = 1; ((!err) && (ehbi_greater_than_l(k, i, &err))); ++i) {
		/* sum_n *= (n - i); */
		if (!err) {
			err = ehbi_set_l(&tmp, -((long)i));
		}
		if (!err) {
			err = ehbi_inc(&tmp, n);
		}
		if (!err) {
			err = ehbi_mul(result, &sum_n, &tmp);
		}
		if (!err) {
			err = ehbi_set(&sum_n, result);
		}

		/* sum_k *= (k - i) */ ;
		if (!err) {
			err = ehbi_set_l(&tmp, -((long)i));
		}
		if (!err) {
			err = ehbi_inc(&tmp, k);
		}
		if (!err) {
			err = ehbi_mul(result, &sum_k, &tmp);
		}
		if (!err) {
			err = ehbi_set(&sum_k, result);
		}
	}
	/* result = (sum_n / sum_k); */
	if (!err) {
		err = ehbi_div(result, &tmp, &sum_n, &sum_k);
	}

ehbi_n_choose_k_end:
	if (err) {
		Ehbi_log_error1("error %d, setting result = 0", err);
		ehbi_unsafe_zero(result);
	}
	if (tmp.bytes) {
		ehbi_stack_free(tmp.bytes, tmp.bytes_len);
	}
	if (sum_n.bytes) {
		ehbi_stack_free(sum_n.bytes, sum_n.bytes_len);
	}
	if (sum_k.bytes) {
		ehbi_stack_free(sum_k.bytes, sum_k.bytes_len);
	}

	Trace_msg_s_bi(2, "end", result);
	Return_i(2, err);
}

int ehbi_n_choose_k_l(struct ehbigint *result, const struct ehbigint *n, long k)
{
	unsigned char bytes[sizeof(unsigned long)];
	struct ehbigint temp;
	int err;

	Trace_bi_bi_l(4, result, n, k);

	ehbi_unsafe_clear_null_struct(&temp);

	Ehbi_struct_is_not_null(4, result);
	Ehbi_struct_is_not_null(4, n);

	temp.bytes = bytes;
	temp.bytes_len = sizeof(unsigned long);

	ehbi_unsafe_struct_l(&temp, k);

	err = ehbi_mul(result, n, &temp);

	Trace_msg_s_bi(4, "end", result);
	Return_i(4, err);
}

int ehbi_n_choose_k_ll(struct ehbigint *result, long n, long k)
{
	unsigned char n_bytes[sizeof(unsigned long)];
	struct ehbigint temp_n;
	unsigned char k_bytes[sizeof(unsigned long)];
	struct ehbigint temp_k;
	int err;

	Trace_bi_l_l(4, result, n, k);

	ehbi_unsafe_clear_null_struct(&temp_n);
	ehbi_unsafe_clear_null_struct(&temp_k);

	Ehbi_struct_is_not_null(4, result);

	temp_n.bytes = n_bytes;
	temp_n.bytes_len = sizeof(unsigned long);
	temp_k.bytes = k_bytes;
	temp_k.bytes_len = sizeof(unsigned long);

	ehbi_unsafe_struct_l(&temp_n, n);
	ehbi_unsafe_struct_l(&temp_k, k);

	err = ehbi_mul(result, &temp_n, &temp_k);

	Trace_msg_s_bi(4, "end", result);
	Return_i(4, err);
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

size_t SMALL_PRIMES_LEN = (sizeof(SMALL_PRIMES) / sizeof(long)) - 1;

static void ehbi_get_witness(size_t i, struct ehbigint *a,
			     struct ehbigint *max_witness, struct ehbigint *two,
			     int *err)
{
	size_t j, max_rnd, shift;
	if (i < EHBI_NUM_SMALL_PRIME_WITNESSES && i < SMALL_PRIMES_LEN) {
		*err = ehbi_set_l(a, SMALL_PRIMES[i]);
	} else {
		j = 0;
		max_rnd = EHBI_MAX_TRIES_TO_GRAB_RANDOM_BYTES;
		/* pick a random integer a in the range [2, n-2] */
		do {
			*err = ehbi_random_bytes(a->bytes, a->bytes_len);
			a->bytes_used = a->bytes_len;
			shift = a->bytes_len - max_witness->bytes_used;
			*err = ehbi_bytes_shift_right(a, shift);
			ehbi_unsafe_reset_bytes_used(a);
		} while ((ehbi_greater_than(a, max_witness, err)
			  || ehbi_less_than(a, two, err)) && (j++ < max_rnd));
	}
	if (ehbi_greater_than(a, max_witness, err)
	    || ehbi_less_than(a, two, err)) {
		if (!*err) {
			/* but, too big, so do something totally bogus: */
			*err = ehbi_set_l(a, 2 + i);
		}
	}
}

/*
   From:
   https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test

   The algorithm can be written in pseudocode as follows:

	Input #1: n > 3, an odd integer to be tested for primality;
	Input #2: k, a parameter that determines the accuracy of the test
	Output: composite if n is composite, otherwise probably prime

	write n-1 as (2^r)*d with d odd by factoring powers of 2 from n-1
	WitnessLoop: repeat k times:
		pick a random integer a in the range [2, n-2]
		x := (a^d) mod n
		if x = 1 or x = n-1 then
			continue WitnessLoop
		repeat r-1 times:
			x := (x^2) mod n
			if x = 1 then
				return composite
			if x = n-1 then
				continue WitnessLoop
		return composite
	return probably prime
*/
int ehbi_is_probably_prime(const struct ehbigint *bi, unsigned int accuracy,
			   int *err)
{
	size_t i, k, size;
	int is_probably_prime, stop, local_err;
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

	if (!err) {
		err = &local_err;
	}

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
	if (!*err) {
		*err = ehbi_set_l(&d, SMALL_PRIMES[0]);
	}
	if (*err) {
		goto ehbi_is_probably_prime_end;
	}
	if (ehbi_less_than(bi, &d, err)) {
		is_probably_prime = 0;
		goto ehbi_is_probably_prime_end;
	}

	/* 2 is the only even prime */
	if (!ehbi_is_odd(bi, err)) {
		is_probably_prime = ehbi_equals(bi, &d, err);
		goto ehbi_is_probably_prime_end;
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
		if (!*err) {
			*err = ehbi_shift_right(&d, 1);
		}
	}
	if (*err) {
		goto ehbi_is_probably_prime_end;
	}
	ehbi_set_l(&r, (long)i);
	/* (bi-1) == 2^(r) * d */

	ehbi_set(&bimin1, bi);
	ehbi_dec(&bimin1, &one);

	/* we will set max_witness at n-2 */
	ehbi_set(&max_witness, bi);
	ehbi_dec(&max_witness, &two);

	if (accuracy == 0) {
		k = EHBI_DEFAULT_TRIALS_FOR_IS_PROBABLY_PRIME;
	} else if (accuracy < EHBI_MIN_TRIALS_FOR_IS_PROBABLY_PRIME) {
		k = EHBI_MIN_TRIALS_FOR_IS_PROBABLY_PRIME;
	} else {
		k = accuracy;
	}
	/*
	   WitnessLoop: repeat k times:
	 */
	for (i = 0; i < k; ++i) {
		if (*err) {
			goto ehbi_is_probably_prime_end;
		}

		ehbi_get_witness(i, &a, &max_witness, &two, err);

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
		if (!*err) {
			*err = ehbi_set(&c, &r);
		}
		if (!*err) {
			*err = ehbi_dec(&c, &one);
		}
		if (*err) {
			goto ehbi_is_probably_prime_end;
		}
		stop = 0;
		while (!stop && ehbi_greater_than(&c, &zero, err)) {
			if (!*err) {
				*err = ehbi_dec(&c, &one);
			}

			/* x := x^2 mod n */
			if (!*err) {
				*err = ehbi_set(&y, &x);
			}
			if (!*err) {
				*err = ehbi_exp_mod(&x, &y, &two, bi);
			}
			if (*err) {
				goto ehbi_is_probably_prime_end;
			}

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
	int rv, local_err;

	Trace_bi(8, bi);
	if (!err) {
		err = &local_err;
	}

	Ehbi_struct_is_not_null_e(8, bi, err, 0);

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
	int rv, b1_pos, b2_pos, local_err;

	Trace_bi_bi(8, bi1, bi2);
	if (!err) {
		err = &local_err;
	}
	rv = 0;

	Ehbi_struct_is_not_null_e(8, bi1, err, rv);
	Ehbi_struct_is_not_null_e(8, bi2, err, rv);

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

	Return_i(8, rv);
}

int ehbi_compare_l(const struct ehbigint *bi1, long i2, int *err)
{
	int rv, local_err;
	struct ehbigint bi2;
	unsigned char bytes[sizeof(long)];

	Trace_bi_l(8, bi1, i2);

	ehbi_unsafe_clear_null_struct(&bi2);

	if (!err) {
		err = &local_err;
	}
	rv = 0;

	Ehbi_struct_is_not_null_e(8, bi1, err, rv);

	*err = ehbi_init(&bi2, bytes, sizeof(long));
	if (*err) {
		Return_i(8, rv);
	}
	*err = ehbi_inc_l(&bi2, i2);
	if (*err) {
		Return_i(8, rv);
	}

	rv = ehbi_compare(bi1, &bi2, err);
	Return_i(8, rv);
}

int ehbi_equals(const struct ehbigint *bi1, const struct ehbigint *bi2,
		int *err)
{
	int rv, local_err;

	Trace_bi_bi(8, bi1, bi2);
	if (!err) {
		err = &local_err;
	}
	rv = 0;

	Ehbi_struct_is_not_null_e(8, bi1, err, rv);
	Ehbi_struct_is_not_null_e(8, bi2, err, rv);

	rv = ((ehbi_compare(bi1, bi2, err) == 0) && (*err == EHBI_SUCCESS));

	Return_i(8, rv);
}

int ehbi_equals_l(const struct ehbigint *bi1, long i2, int *err)
{
	int rv, local_err;
	struct ehbigint bi2;
	unsigned char bytes[sizeof(long)];

	Trace_bi_l(8, bi1, i2);

	if (!err) {
		err = &local_err;
	}
	rv = 0;

	ehbi_unsafe_clear_null_struct(&bi2);

	Ehbi_struct_is_not_null_e(8, bi1, err, rv);

	*err = ehbi_init(&bi2, bytes, sizeof(long));
	if (*err) {
		Return_i(8, rv);
	}
	*err = ehbi_inc_l(&bi2, i2);
	if (*err) {
		Return_i(8, rv);
	}

	rv = ehbi_equals(bi1, &bi2, err);
	Return_i(8, rv);
}

int ehbi_less_than(const struct ehbigint *bi1, const struct ehbigint *bi2,
		   int *err)
{
	int rv, local_err;

	Trace_bi_bi(8, bi1, bi2);

	if (!err) {
		err = &local_err;
	}

	rv = 0;

	Ehbi_struct_is_not_null_e(8, bi1, err, rv);
	Ehbi_struct_is_not_null_e(8, bi2, err, rv);

	rv = ((ehbi_compare(bi1, bi2, err) < 0) && (*err == EHBI_SUCCESS));

	Return_i(8, rv);
}

int ehbi_less_than_l(const struct ehbigint *bi1, long i2, int *err)
{
	int rv, local_err;
	struct ehbigint bi2;
	unsigned char bytes[sizeof(long)];

	Trace_bi_l(8, bi1, i2);

	if (!err) {
		err = &local_err;
	}
	rv = 0;

	ehbi_unsafe_clear_null_struct(&bi2);

	Ehbi_struct_is_not_null_e(8, bi1, err, rv);

	*err = ehbi_init(&bi2, bytes, sizeof(long));
	if (*err) {
		Return_i(8, rv);
	}
	*err = ehbi_inc_l(&bi2, i2);
	if (*err) {
		Return_i(8, rv);
	}

	rv = ehbi_less_than(bi1, &bi2, err);
	Return_i(8, rv);
}

int ehbi_greater_than(const struct ehbigint *bi1, const struct ehbigint *bi2,
		      int *err)
{
	int rv, local_err;

	Trace_bi_bi(8, bi1, bi2);

	if (!err) {
		err = &local_err;
	}
	rv = 0;

	Ehbi_struct_is_not_null_e(8, bi1, err, rv);
	Ehbi_struct_is_not_null_e(8, bi2, err, rv);

	rv = ((ehbi_compare(bi1, bi2, err) > 0) && (*err == EHBI_SUCCESS));

	Return_i(8, rv);
}

int ehbi_greater_than_l(const struct ehbigint *bi1, long i2, int *err)
{
	int rv, local_err;
	struct ehbigint bi2;
	unsigned char bytes[sizeof(long)];

	Trace_bi_l(8, bi1, i2);

	if (!err) {
		err = &local_err;
	}
	rv = 0;

	ehbi_unsafe_clear_null_struct(&bi2);

	Ehbi_struct_is_not_null_e(8, bi1, err, rv);

	*err = ehbi_init(&bi2, bytes, sizeof(long));
	if (*err) {
		Return_i(8, rv);
	}
	*err = ehbi_inc_l(&bi2, i2);
	if (*err) {
		Return_i(8, rv);
	}

	rv = ehbi_greater_than(bi1, &bi2, err);
	Return_i(8, rv);
}

int ehbi_is_odd(const struct ehbigint *bi, int *err)
{
	unsigned char bit;
	int rv, local_err;

	Trace_bi(8, bi);

	if (!err) {
		err = &local_err;
	}
	rv = 0;

	Ehbi_struct_is_not_null_e(8, bi, err, rv);

	bit = 0x01 & bi->bytes[bi->bytes_len - 1];
	rv = bit ? 1 : 0;

	Return_i(8, rv);
}

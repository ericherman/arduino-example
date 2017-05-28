/*
ehbigint.h: slow Big Int library hopefully somewhat suitable for 8bit CPUs
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
#ifndef EHBIGINT_H
#define EHBIGINT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>		/* size_t */

struct ehbigint {
	unsigned char *bytes;
	size_t bytes_len;
	size_t bytes_used;
	unsigned char sign;
};

/*
   assignes the byte[] to the struct, sets to zero
   returns 0 on success or error_code on error
*/
int ehbi_init(struct ehbigint *bi, unsigned char *bytes, size_t len);

/*
   populates an ehbigint with a value of zero
   returns 0 on success or error_code on error
*/
int ehbi_zero(struct ehbigint *bi);

/*
   populates an ehbigint with a binary string value e.g. "0b0101010111110000"
   returns 0 on success or error_code on error
*/

int ehbi_set_binary_string(struct ehbigint *bi, const char *str, size_t len);

/*
   populates an ehbigint with a hex string value e.g. "0x4badc0de"
   returns 0 on success or error_code on error
*/
int ehbi_set_hex_string(struct ehbigint *bi, const char *str, size_t str_len);

/*
   populates an ehbigint with a decimal string value e.g. "1234567890123456789"
   returns 0 on success or error_code on error
*/
int ehbi_set_decimal_string(struct ehbigint *bi, const char *dec, size_t len);

/*
   populates an ehbigint with the value
   returns 0 on success or error_code on error
*/
int ehbi_set(struct ehbigint *bi, const struct ehbigint *val);

/*
   populates an ehbigint with the value
   returns 0 on success or error_code on error
*/
int ehbi_set_l(struct ehbigint *bi, long val);

/*
   populates the first ehbigint with the sum of the second and third
   returns 0 on success or error_code on error
*/
int ehbi_add(struct ehbigint *res, const struct ehbigint *bi1,
	     const struct ehbigint *bi2);

/*
   increments the first ehbigint by the value in the second parameter
   returns 0 on success or error_code on error
*/
int ehbi_inc(struct ehbigint *bi, const struct ehbigint *val);

/*
   increments the ehbigint by the value in the second parameter
   returns 0 on success or error_code on error
*/
int ehbi_inc_l(struct ehbigint *bi, long val);

/*
   decrements the first ehbigint by the value in the second parameter
   returns 0 on success or error_code on error
*/
int ehbi_dec(struct ehbigint *bi, const struct ehbigint *val);

/*
   populates the first ehbigint with the value of the second perameter minus
   the third
   returns 0 on success or error_code on error
*/
int ehbi_subtract(struct ehbigint *res, const struct ehbigint *bi1,
		  const struct ehbigint *bi2);

/*
   populates the first ehbigint with the sum of the second and third
   returns 0 on success or error_code on error
*/
int ehbi_mul(struct ehbigint *res, const struct ehbigint *bi1,
	     const struct ehbigint *bi2);

/*
   shifts the value of the ehbigint up by num_bits number of bits
   returns 0 on success or error_code on error
*/
int ehbi_shift_left(struct ehbigint *bi, unsigned long num_bits);

/*
   shifts the value of the ehbigint down by num_bits number of bits
   returns 0 on success or error_code on error
*/
int ehbi_shift_right(struct ehbigint *bi, unsigned long num_bits);

/*
   populates the first ehbigint quotient and remainder with the results
   of the numerator divided by the denominator
   returns 0 on success or error_code on error
*/
int ehbi_div(struct ehbigint *quotient, struct ehbigint *remainder,
	     const struct ehbigint *numerator,
	     const struct ehbigint *denominator);

/*
   populates the first ehbigint result with the value of the base
   raised to the power of the exponent
   returns 0 on success or error_code on error
*/
int ehbi_exp(struct ehbigint *result, const struct ehbigint *base,
	     const struct ehbigint *exponent);

/*
   populates the first ehbigint result with the value of the base
   raised to the power of the exponent mod the modulus
   returns 0 on success or error_code on error
*/
int ehbi_exp_mod(struct ehbigint *result, const struct ehbigint *base,
		 const struct ehbigint *exponent,
		 const struct ehbigint *modulus);

#ifndef EHBI_SKIP_IS_PROBABLY_PRIME

/* chance of incorrectly naming a non-prime as prime is 4^(-accuracy) */
#ifndef EHBI_DEFAULT_TRIALS_FOR_IS_PROBABLY_PRIME
/* 4^(-25) == 8.8817842e-16 */
#define EHBI_DEFAULT_TRIALS_FOR_IS_PROBABLY_PRIME 25U
#endif

#ifndef EHBI_MIN_TRIALS_FOR_IS_PROBABLY_PRIME
/* 4^(-25) == 9.53674316e-7 */
#define EHBI_MIN_TRIALS_FOR_IS_PROBABLY_PRIME 10U
#endif

#ifndef EHBI_NUM_SMALL_PRIMES_TO_TRIAL_DIVIDE
#define EHBI_NUM_SMALL_PRIMES_TO_TRIAL_DIVIDE 20U
#endif

/* used in ehbi_is_probably_prime */
#ifndef EHBI_MAX_TRIES_TO_GRAB_RANDOM_BYTES
#define EHBI_MAX_TRIES_TO_GRAB_RANDOM_BYTES 10U
#endif

/*
  returns 1 if the values is prime or probably prime
  returns 0 otherwise
  uses the second parameter (accuracy) to determine strength of the test
  populates the contents of err with 0 on success or error_code on error
*/
int ehbi_is_probably_prime(const struct ehbigint *bi,
			   unsigned int accuracy, int *err);

#endif /* EHBI_SKIP_IS_PROBABLY_PRIME */

/* sign inversion
   returns 0 on success or error_code on error
*/
int ehbi_negate(struct ehbigint *bi);

/*
   returns 1 if the values represented by the ehbigint arguments are equal
   returns 0 otherwise
   populates the contents of err with 0 on success or error_code on error
*/
int ehbi_equals(const struct ehbigint *bi1, const struct ehbigint *bi2,
		int *err);

/*
   returns 1 if the first parameter is less than the second
   returns 0 otherwise
   populates the contents of err with 0 on success or error_code on error
*/
int ehbi_less_than(const struct ehbigint *bi1, const struct ehbigint *bi2,
		   int *err);

/*
   returns 1 if the first parameter is greater than the second
   returns 0 otherwise
   populates the contents of err with 0 on success or error_code on error
*/
int ehbi_greater_than(const struct ehbigint *bi1, const struct ehbigint *bi2,
		      int *err);

/*
   returns 0 if the values represented by the ehbigint arguments are equal
   returns <0 if the first ehbigint is less than the second
   returns >0 if the first ehbigint is greater than the second
   populates the contents of err with 0 on success or error_code on error
*/
int ehbi_compare(const struct ehbigint *bi1, const struct ehbigint *bi2,
		 int *err);

/*
   returns 1 if negative
   returns 0 otherwise
   populates the contents of err with 0 on success or error_code on error
*/
int ehbi_is_negative(const struct ehbigint *bi, int *err);

/*
   returns 1 if odd
   returns 0 if even
   populates the contents of err with 0 on success or error_code on error
*/
int ehbi_is_odd(const struct ehbigint *bi, int *err);

/*
   populates the passed in buffer with a binary string representation
   of the ehbigint
   returns pointer to buf success or NULL on error and sets the value of
   err with error_code.
*/
char *ehbi_to_binary_string(const struct ehbigint *bi, char *buf,
			    size_t buf_len, int *err);

/*
   populates the passed in buffer with a hex string representation
   of the ehbigint
   returns pointer to buf success or NULL on error and sets the value of
   err with error_code.
*/
char *ehbi_to_hex_string(const struct ehbigint *bi, char *buf, size_t buf_len,
			 int *err);

/*
   populates the passed in buffer with a decimal string representation
   of the ehbigint
   returns pointer to buf success or NULL on error and sets the value of
   err with error_code.
*/
char *ehbi_to_decimal_string(const struct ehbigint *bi, char *buf,
			     size_t buf_len, int *err);

/* error codes */
enum {
	EHBI_SUCCESS = 0,
	EHBI_NULL_CHAR_PTR,
	EHBI_BAD_INPUT,
	EHBI_NOT_HEX,
	EHBI_BAD_HIGH_NIBBLE,
	EHBI_BAD_LOW_NIBBLE,
	EHBI_NULL_STRUCT,
	EHBI_NULL_STRING,
	EHBI_NULL_STRING_BUF,
	EHBI_NULL_ARGS,
	EHBI_ZERO_LEN_STRING,
	EHBI_STRING_BUF_TOO_SMALL,
	EHBI_STRING_BUF_TOO_SMALL_PARTIAL,
	EHBI_STRING_BUF_TOO_SMALL_NO_NULL,
	EHBI_NULL_BYTES,
	EHBI_BYTES_TOO_SMALL,
	EHBI_BYTES_TOO_SMALL_FOR_CARRY,
	EHBI_BYTES_TOO_SMALL_FOR_BORROW,
	EHBI_BAD_DATA,
	EHBI_CORRUPT_DATA,
	EHBI_STACK_TOO_SMALL,
	EHBI_DIVIDE_BY_ZERO,
	EHBI_EBA_CRASH,
	EHBI_FILE_ERROR,
	EHBI_LAST
};

#ifdef __cplusplus
}
#endif

#endif /* EHBIGINT_H */

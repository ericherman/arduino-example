/*
ehbigint-str.c: to and from string functions for ehbighint structs
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

#include "ehbigint-str.h"
#include "ehbigint-log.h"
#include "ehbigint-util.h"
#include "ehbigint-priv.h"
#include "ehbigint-eba.h"
#include "ehstr.h"

static int ehbi_hex_to_decimal(const char *hex, size_t hex_len, char *buf,
			       size_t buf_len);

static int ehbi_decimal_to_hex(const char *dec_str, size_t dec_len, char *buf,
			       size_t buf_len);

static int ehbi_hex_to_decimal(const char *hex, size_t hex_len, char *buf,
			       size_t buf_len);

static int ehbi_nibble_to_hex(unsigned char nibble, char *c);

static int ehbi_from_hex_nibble(unsigned char *nibble, char c);

/* public functions */
int ehbi_set_binary_string(struct ehbigint *bi, const char *str, size_t len)
{
	size_t i, j;
	struct eba_s eba;
	int err;

	Trace_bi_s(8, bi, str);

	eba.endian = eba_big_endian;
	eba.bits = NULL;
	eba.size_bytes = 0;

	Ehbi_struct_is_not_null(8, bi);
	ehbi_zero(bi);

	eba.bits = bi->bytes;
	eba.size_bytes = bi->bytes_len;

	if (str == 0) {
		Ehbi_log_error0("Null string");
		Return_i(8, EHBI_NULL_STRING);
	}
	if (len == 0 || str[0] == 0) {
		Ehbi_log_error0("Zero length string");
		Return_i(8, EHBI_ZERO_LEN_STRING);
	}
	if (len > 2 && str[0] == '0' && (str[1] == 'b' || str[1] == 'B')) {
		str = str + 2;
		len -= 2;
	}
	len = strnlen(str, len);
	for (i = 0; i < len; ++i) {
		if (str[i] != '0' && str[i] != '1') {
			len = i;
		}
	}

	err = EHBI_SUCCESS;

	for (i = 0, j = len - 1; i < len; ++i, --j) {
		ehbi_eba_err = EHBI_SUCCESS;
		eba_set(&eba, i, str[j] == '1' ? 1 : 0);
		if (!err) {
			err = ehbi_eba_err;
		}
	}

	ehbi_unsafe_reset_bytes_used(bi);

	Return_i(8, err);
}

int ehbi_set_hex_string(struct ehbigint *bi, const char *str, size_t str_len)
{
	size_t i, j;
	unsigned char high, low;

	Trace_bi_s(8, bi, str);

	Ehbi_struct_is_not_null(8, bi);

	if (str == 0) {
		Ehbi_log_error0("Null string");
		Return_i(8, EHBI_NULL_STRING);
	}
	if (str_len == 0 || str[0] == 0) {
		Ehbi_log_error0("Zero length string");
		Return_i(8, EHBI_ZERO_LEN_STRING);
	}

	bi->sign = 0;

	/* ignore characters starting with the first NULL in string */
	for (i = 1; i < str_len; ++i) {
		if (str[i] == 0) {
			str_len = i;
			break;
		}
	}

	/* skip over leading '0x' in string */
	if (str_len >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
		str += 2;
		str_len -= 2;
	}

	j = str_len;
	i = bi->bytes_len;

	bi->bytes_used = 0;
	while (j > 0) {
		low = str[--j];
		if (j > 0) {
			high = str[--j];
		} else {
			high = '0';
		}
		if (bi->bytes_used >= bi->bytes_len) {
			Ehbi_log_error0("byte[] too small");
			Return_i(8, EHBI_BYTES_TOO_SMALL);
		}
		if (ehbi_hex_chars_to_byte(high, low, &(bi->bytes[--i]))) {
			Ehbi_log_error2("Bad data (high: %c, low: %c)", high,
					low);
			Return_i(8, EHBI_BAD_DATA);
		}
		bi->bytes_used++;
	}

	/* let's just zero out the rest of the bytes, for easier debug */
	Eba_memset(bi->bytes, 0x00, i);

	ehbi_unsafe_reset_bytes_used(bi);

	Trace_msg_s_bi(8, "end", bi);
	Return_i(8, EHBI_SUCCESS);
}

int ehbi_set_decimal_string(struct ehbigint *bi, const char *dec, size_t len)
{
	char *hex;
	const char *str;
	size_t size;
	int err, negative;

	Trace_bi(8, bi);

	Ehbi_struct_is_not_null(8, bi);

	if (len == 0) {
		str = "0x00";
		len = 4;
	} else if (dec == NULL) {
		Ehbi_log_error0("Null string");
		Return_i(8, EHBI_NULL_STRING);
	}

	size = 4 /* strlen("0x00") */  + len + 1;
	hex = (char *)ehbi_stack_alloc(size);
	if (!hex) {
		Ehbi_log_error2("Could not %s(%lu) bytes", ehbi_stack_alloc_str,
				(unsigned long)size);
		Return_i(8, EHBI_STACK_TOO_SMALL);
	}
	if (dec[0] == '-') {
		str = dec + 1;
		len -= 1;
		negative = 1;
	} else {
		str = dec;
		negative = 0;
	}
	err = ehbi_decimal_to_hex(str, len, hex, size);
	if (err) {
		Return_i(8, err);
	}

	err = ehbi_set_hex_string(bi, hex, size);

	if (negative) {
		err = err ? err : ehbi_negate(bi);
	}

	ehbi_unsafe_reset_bytes_used(bi);

	ehbi_stack_free(hex, size);
	Trace_msg_s_bi(8, "end", bi);
	Return_i(8, err);
}

char *ehbi_to_binary_string(const struct ehbigint *bi, char *buf,
			    size_t buf_len, int *err)
{
	size_t i, j, k, written;
	unsigned char bit;
	struct eba_s eba;

	Trace_bi(8, bi);

	eba.endian = eba_big_endian;
	eba.bits = NULL;
	eba.size_bytes = 0;

	Ehbi_struct_is_not_null_e_j(bi, err, ehbi_to_binary_string_end);

	eba.bits = bi->bytes;
	eba.size_bytes = bi->bytes_len;

	if (buf == 0) {
		Ehbi_log_error0("Null buffer");
		*err = EHBI_NULL_STRING_BUF;
		goto ehbi_to_binary_string_end;
	}

	written = 0;
	buf[written] = '\0';
	*err = EHBI_SUCCESS;

	if (buf_len < ((bi->bytes_used * EBA_CHAR_BIT) + 3)) {
		Ehbi_log_error0("Buffer too small");
		*err = EHBI_STRING_BUF_TOO_SMALL;
		goto ehbi_to_binary_string_end;
	}
	buf[written++] = '0';
	buf[written++] = 'b';

	for (i = 0; i < bi->bytes_used; ++i) {
		for (j = 0; j < EBA_CHAR_BIT; ++j) {
			if ((written + 2) >= buf_len) {
				Ehbi_log_error0("Buffer too small");
				*err = EHBI_STRING_BUF_TOO_SMALL;
				goto ehbi_to_binary_string_end;
			}
			k = (bi->bytes_used * EBA_CHAR_BIT) - 1;
			k = k - ((i * EBA_CHAR_BIT) + j);
			ehbi_eba_err = EHBI_SUCCESS;
			bit = eba_get(&eba, k);
			*err = ehbi_eba_err;
			if (*err) {
				goto ehbi_to_binary_string_end;
			}
			buf[written++] = bit ? '1' : '0';
			buf[written] = '\0';	/* this just makes debug nicer */
		}
	}
	buf[written] = '\0';

ehbi_to_binary_string_end:
	if (*err) {
		buf[0] = '\0';
	}
	return buf;
}

char *ehbi_to_hex_string(const struct ehbigint *bi, char *buf, size_t buf_len,
			 int *err)
{
	size_t i, j;
	char *rv;

	Trace_bi(8, bi);

	Ehbi_struct_is_not_null_e_j(bi, err, ehbi_to_hex_string_end);

	if (buf == 0) {
		Ehbi_log_error0("Null buffer");
		*err = EHBI_NULL_STRING_BUF;
		goto ehbi_to_hex_string_end;
	}
	buf[0] = '\0';

	if (buf_len < (bi->bytes_used + 3)) {
		Ehbi_log_error0("Buffer too small");
		*err = EHBI_STRING_BUF_TOO_SMALL;
		goto ehbi_to_hex_string_end;
	}

	*err = EHBI_SUCCESS;
	j = 0;
	buf[j++] = '0';
	buf[j++] = 'x';

	for (i = bi->bytes_len - bi->bytes_used; i < bi->bytes_len; ++i) {
		if (j + 2 > buf_len) {
			Ehbi_log_error0("Buffer too small, partially written");
			*err = EHBI_STRING_BUF_TOO_SMALL_PARTIAL;
			goto ehbi_to_hex_string_end;
		}
		*err =
		    ehbi_byte_to_hex_chars(bi->bytes[i], buf + j, buf + j + 1);
		if (*err) {
			Ehbi_log_error0("Corrupted data?");
			goto ehbi_to_hex_string_end;
		}
		j += 2;
	}
	if (j > buf_len) {
		Ehbi_log_error0("Unable to write trailing NULL to buffer");
		*err = EHBI_STRING_BUF_TOO_SMALL_NO_NULL;
		goto ehbi_to_hex_string_end;
	}
	buf[j] = '\0';

	/* strip leading '0's ("0x0123" -> "0x123") */
	/* strip leading "00"s ("0x000123" -> "0x0123") */
	while ((buf[2] == '0' || buf[2] == 'F') && buf[2] == buf[3]
	       && buf[2] == buf[4] && buf[2] == buf[5]) {
		for (j = 2; j < buf_len - 1 && buf[j] != 0; j += 2) {
			buf[j] = buf[j + 2];
		}
	}

ehbi_to_hex_string_end:
	if (buf && (err == NULL || *err)) {
		buf[0] = '\0';
	}
	rv = ((err == NULL || *err) ? NULL : buf);

	Trace_msg_s_s(8, "end", buf);
	Return_s(8, rv);
}

char *ehbi_to_decimal_string(const struct ehbigint *bi, char *buf, size_t len,
			     int *err)
{
	char *hex, *rv;
	size_t size;

	Trace_bi(8, bi);

	hex = NULL;
	rv = NULL;

	Ehbi_struct_is_not_null_e_j(bi, err, ehbi_to_decimal_string_end);

	size = 0;

	if (buf == NULL || len == 0) {
		Ehbi_log_error0("Null Arguments(s)");
		if (err) {
			*err = EHBI_NULL_ARGS;
		}
		goto ehbi_to_decimal_string_end;
	}
	rv = buf;
	buf[0] = '\0';

	*err = EHBI_SUCCESS;

	size = 4 /* strlen("0x00") */  + (2 * bi->bytes_used) + 1;
	hex = (char *)ehbi_stack_alloc(size);
	if (!hex) {
		Ehbi_log_error2("Could not %s(%lu) bytes", ehbi_stack_alloc_str,
				(unsigned long)size);
		*err = EHBI_STACK_TOO_SMALL;
		goto ehbi_to_decimal_string_end;
	}

	if (ehbi_is_negative(bi, err)) {
		buf[0] = '-';
		buf[1] = '\0';
		buf = buf + 1;
		len -= 1;
	}

	ehbi_to_hex_string(bi, hex, size, err);
	if (*err) {
		goto ehbi_to_decimal_string_end;
	}
	*err = ehbi_hex_to_decimal(hex, size, buf, len);

ehbi_to_decimal_string_end:
	if (hex) {
		ehbi_stack_free(hex, size);
	}
	if (buf && (err == NULL || *err)) {
		buf[0] = '\0';
	}

	rv = (err == NULL || *err) ? NULL : rv;

	Trace_msg_s_s(8, "end", buf);
	Return_s(8, rv);
}

int ehbi_byte_to_hex_chars(unsigned char byte, char *high, char *low)
{
	int err;

	err = EHBI_SUCCESS;
	err += ehbi_nibble_to_hex((byte & 0xF0) >> 4, high);
	err += ehbi_nibble_to_hex((byte & 0x0F), low);

	return err;
}

int ehbi_hex_chars_to_byte(char high, char low, unsigned char *byte)
{
	int err;
	unsigned char nibble;

	err = ehbi_from_hex_nibble(&nibble, high);
	if (err) {
		Ehbi_log_error1("Error with high nibble (%c)", high);
		return EHBI_BAD_HIGH_NIBBLE;
	}
	*byte = (nibble << 4);

	err = ehbi_from_hex_nibble(&nibble, low);
	if (err) {
		Ehbi_log_error1("Error with low nibble (%c)", high);
		return EHBI_BAD_LOW_NIBBLE;
	}
	*byte += nibble;

	return EHBI_SUCCESS;
}

/* private functions */
static int ehbi_decimal_to_hex(const char *dec_str, size_t dec_len, char *buf,
			       size_t buf_len)
{
	char *rv;

	if (dec_str == 0 || buf == 0) {
		Ehbi_log_error0("Null argument");
		return EHBI_NULL_ARGS;
	}

	if (buf_len < 5) {
		Ehbi_log_error0("Buffer too small");
		return EHBI_STRING_BUF_TOO_SMALL;
	}

	rv = decimal_to_hex(dec_str, dec_len, buf, buf_len);

	if (rv == NULL) {
		Ehbi_log_error1("Character not decimal? (%s)", dec_str);
		return EHBI_BAD_INPUT;
	}

	return EHBI_SUCCESS;
}

static int ehbi_hex_to_decimal(const char *hex, size_t hex_len, char *buf,
			       size_t buf_len)
{
	char *rv;

	if (hex == 0 || buf == 0) {
		Ehbi_log_error0("Null argument");
		return EHBI_NULL_ARGS;
	}
	buf[0] = '\0';

	if (buf_len < 2 || buf_len < hex_len) {
		Ehbi_log_error0("Buffer too small");
		return EHBI_STRING_BUF_TOO_SMALL;
	}

	rv = hex_to_decimal(hex, hex_len, buf, buf_len);

	if (rv == NULL) {
		Ehbi_log_error1("Character not hex? (%s)", hex);
		return EHBI_BAD_INPUT;
	}

	return EHBI_SUCCESS;
}

static int ehbi_nibble_to_hex(unsigned char nibble, char *c)
{
	if (c == 0) {
		Ehbi_log_error0("Null char pointer");
		return EHBI_NULL_CHAR_PTR;
	}
	if (nibble < 10) {
		*c = '0' + nibble;
	} else if (nibble < 16) {
		*c = 'A' + nibble - 10;
	} else {
		Ehbi_log_error1("Bad input '%x'", nibble);
		return EHBI_BAD_INPUT;
	}
	return EHBI_SUCCESS;
}

static int ehbi_from_hex_nibble(unsigned char *nibble, char c)
{

	if (nibble == 0) {
		Ehbi_log_error0("Null char pointer");
		return EHBI_NULL_CHAR_PTR;
	}
	if (c >= '0' && c <= '9') {
		*nibble = c - '0';
	} else if (c >= 'a' && c <= 'f') {
		*nibble = 10 + c - 'a';
	} else if (c >= 'A' && c <= 'F') {
		*nibble = 10 + c - 'A';
	} else {
		Ehbi_log_error1("Not hex (%c)", c);
		return EHBI_NOT_HEX;
	}

	return EHBI_SUCCESS;
}

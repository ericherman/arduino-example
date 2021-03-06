/*
eh-printf-private.h - private headers for eh-printf.c
Copyright (C) 2016 Eric Herman

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later
version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License (COPYING) along with this library; if not, see:

        https://www.gnu.org/licenses/old-licenses/lgpl-2.1.txt
*/

/*
 * a byte is at least 8 bits, but *may* be more ...
 * thus use CHAR_BIT from limits.h
 * unless compiled with -DEH_CHAR_BIT=8 or something.
 */
#ifndef EH_CHAR_BIT
#ifdef CHAR_BIT
#define EH_CHAR_BIT CHAR_BIT
#else
#include <limits.h>
#define EH_CHAR_BIT CHAR_BIT
#endif
#endif

typedef size_t (eh_output_char_func) (void *ctx, char c);
typedef size_t (eh_output_str_func) (void *ctx, const char *str, size_t len);

struct buf_context {
	char *str;
	size_t len;
	size_t used;
};

enum eh_base {
	eh_binary = 2,
	eh_octal = 8,
	eh_decimal = 10,
	eh_hex = 16
};

static int eh_vprintf_ctx(eh_output_char_func output_char,
			  eh_output_str_func output_str, void *ctx,
			  const char *format, va_list ap);

static size_t eh_buf_output_char(void *ctx, char c);

static size_t eh_buf_output_str(void *ctx, const char *str, size_t len);

static size_t eh_append(eh_output_char_func output_char,
			eh_output_str_func output_str, void *ctx,
			size_t field_size, const char *str);

#ifndef NEED_EH_STRLEN
static size_t eh_strlen(const char *str);
#endif

static size_t eh_long_to_ascii(char *dest, size_t dest_size, enum eh_base base,
			       unsigned char zero_padded, size_t field_size,
			       long val);

static size_t eh_unsigned_long_to_ascii(char *dest, size_t dest_size,
					enum eh_base base,
					unsigned char zero_padded,
					size_t field_size, unsigned long val);

static size_t eh_unsigned_long_to_ascii_inner(char *dest, size_t dest_size,
					      enum eh_base base,
					      unsigned char zero_padded,
					      size_t field_size,
					      unsigned char was_negative,
					      unsigned long v);

/*
eh-printf.c - A version of sprintf for embedded applications
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
#include "eh-printf.h"
#include "eh-printf-private.h"
#include "eh-sys-context.h"

int eh_snprintf(char *dest, size_t size, const char *format, ...)
{
	va_list ap;
	int rv;
	va_start(ap, format);
	rv = eh_vsnprintf(dest, size, format, ap);
	va_end(ap);
	return rv;
}

int eh_vsnprintf(char *dest, size_t size, const char *format, va_list ap)
{
	struct buf_context ctx;

	/* huh? */
	if (dest == NULL || size < 1) {
		return 0;
	}

	dest[0] = '\0';

	ctx.str = dest;
	ctx.len = size;
	ctx.used = 0;

	return eh_vprintf_ctx(eh_buf_output_char, eh_buf_output_str, &ctx,
			      format, ap);
}

int eh_printf(const char *format, ...)
{
	va_list ap;
	int rv;
	va_start(ap, format);
	rv = eh_vprintf(format, ap);
	va_end(ap);
	return rv;

}

int eh_vprintf(const char *format, va_list ap)
{
	int rv;
	void *ctx;

	ctx = start_sys_printf_context();

	rv = eh_vprintf_ctx(eh_sys_output_char, eh_sys_output_str, &ctx, format,
			    ap);

	end_sys_printf_context(ctx);

	return rv;
}

/* internals */
static int eh_vprintf_ctx(eh_output_char_func output_char,
			  eh_output_str_func output_str, void *ctx,
			  const char *format, va_list ap)
{
	size_t used, fmt_idx, fmt_len;
	char buf[100];
	int special;
	unsigned char zero_padded;
	size_t field_size;

	/* supported types */
	char *s;
	char c;
	int d;
	unsigned int u;
	long l;
	unsigned long int lu;
	/* double f; */

	zero_padded = 0;
	field_size = 0;
	used = 0;
	fmt_idx = 0;
	fmt_len = eh_strlen(format);
	special = 0;

	while (fmt_idx < fmt_len) {

		if (special) {
			switch (format[fmt_idx]) {
			case '%':
				used += output_char(ctx, '%');
				special = 0;
				break;

			case '0':
				if (field_size == 0) {
					zero_padded = 1;
					break;
				} else {
					/* fall-through */
				}
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				field_size *= 10;
				field_size += format[fmt_idx] - '0';
				break;

			case 'l':
				++special;	/* long long int ? */
				break;

			case 'x':
			case 'X':
				if (special > 1) {
					l = va_arg(ap, long int);
				} else {
					d = va_arg(ap, int);
					l = d;
				}
				eh_long_to_ascii(buf, 100, eh_hex,
						 zero_padded, field_size, l);
				used += output_str(ctx, buf, eh_strlen(buf));
				special = 0;
				break;

			case 'u':
				if (special > 1) {
					lu = va_arg(ap, unsigned long int);
				} else {
					u = va_arg(ap, unsigned int);
					lu = u;
				}
				eh_unsigned_long_to_ascii(buf, 100, eh_decimal,
							  zero_padded,
							  field_size, lu);
				used += output_str(ctx, buf, eh_strlen(buf));
				special = 0;
				break;

			case 'd':
				if (special > 1) {
					l = va_arg(ap, long int);
				} else {
					d = va_arg(ap, int);
					l = d;
				}
				eh_long_to_ascii(buf, 100, eh_decimal,
						 zero_padded, field_size, l);
				used += output_str(ctx, buf, eh_strlen(buf));
				special = 0;
				break;

			case 'c':
				c = (char)va_arg(ap, int);
				used += output_char(ctx, c);
				special = 0;
				break;

			case 's':
				s = (char *)va_arg(ap, char *);
				used +=
				    eh_append(output_char, output_str, ctx,
					      field_size, s);
				special = 0;
				break;

			default:
				/* unhandled */
				used += output_char(ctx, '%');
				if (zero_padded) {
					used += output_char(ctx, '0');
				}
				l = field_size;
				eh_long_to_ascii(buf, 100, eh_decimal,
						 0, 0, field_size);
				used += output_str(ctx, buf, eh_strlen(buf));
				used += output_char(ctx, format[fmt_idx]);

				special = 0;
				break;
			}
			++fmt_idx;
			if (!special) {
				zero_padded = 0;
				field_size = 0;
			}
		} else {
			if (format[fmt_idx] == '%') {
				special = 1;
			} else {
				used += output_char(ctx, format[fmt_idx]);
			}
			++fmt_idx;
		}
	}
	return used;
}

static size_t eh_buf_output_char(void *ctx, char c)
{
	struct buf_context *buf;

	buf = (struct buf_context *)ctx;
	if (buf->used < (buf->len - 1)) {
		buf->str[buf->used++] = c;
		buf->str[buf->used] = '\0';
		return 1;
	}
	return 0;
}

static size_t eh_buf_output_str(void *ctx, const char *str, size_t len)
{
	struct buf_context *buf;
	size_t i;

	buf = (struct buf_context *)ctx;
	i = 0;

	/* not enough space for data, bail out! */
	if (len >= ((buf->len - 1) - buf->used)) {
		/* we don't know what to write, fill with "?" */
		for (i = 0; buf->used < (buf->len - 1); ++i) {
			buf->str[buf->used++] = '?';
		}
	} else {
		for (i = 0; i < len; ++i) {
			buf->str[buf->used++] = str[i];
		}
	}

	/* always null terminate */
	buf->str[buf->used] = '\0';
	return i;
}

static size_t eh_append(eh_output_char_func output_char,
			eh_output_str_func output_str, void *ctx,
			size_t field_size, const char *str)
{
	size_t used, i, s_len;

	used = 0;

	if (!str) {
		str = "(null)";
	}

	s_len = eh_strlen(str);
	if (s_len > field_size) {
		field_size = s_len;
	}

	if (s_len < field_size) {
		for (i = 0; i < (field_size - s_len); ++i) {
			used += output_char(ctx, ' ');
		}
	}

	used += output_str(ctx, str, eh_strlen(str));

	return used;
}

/*
Returns the number of bytes in the string, excluding the terminating
null byte ('\0').
*/
#ifdef NEED_EH_STRLEN
size_t eh_strlen(const char *str)
#else
static size_t eh_strlen(const char *str)
#endif
{
	size_t i;

	if (str == NULL) {
		return 0;
	}

	i = 0;
	while (*(str + i) != '\0') {
		++i;
	}
	return i;
}

static size_t eh_long_to_ascii(char *dest, size_t dest_size, enum eh_base base,
			       unsigned char zero_padded, size_t field_size,
			       long val)
{
	unsigned char was_negative;

	if (val < 0 && base == eh_decimal) {
		was_negative = 1;
		val = -val;
	} else {
		was_negative = 0;
	}

	return eh_unsigned_long_to_ascii_inner(dest, dest_size, base,
					       zero_padded, field_size,
					       was_negative,
					       (unsigned long int)val);
}

static size_t eh_unsigned_long_to_ascii(char *dest, size_t dest_size,
					enum eh_base base,
					unsigned char zero_padded,
					size_t field_size, unsigned long val)
{
	unsigned char was_negative = 0;

	return eh_unsigned_long_to_ascii_inner(dest, dest_size, base,
					       zero_padded, field_size,
					       was_negative,
					       (unsigned long int)val);
}

#define EH_LONG_BASE2_ASCII_BUF_SIZE \
	((EH_CHAR_BIT * sizeof(unsigned long int)) + 1)

static size_t eh_unsigned_long_to_ascii_inner(char *dest, size_t dest_size,
					      enum eh_base base,
					      unsigned char zero_padded,
					      size_t field_size,
					      unsigned char was_negative,
					      unsigned long v)
{
	size_t i, j;
	unsigned long int d, b;
	char reversed_buf[EH_LONG_BASE2_ASCII_BUF_SIZE];

	/* huh? */
	if (dest == NULL || dest_size < 2) {
		if (dest && dest_size) {
			dest[0] = '\0';
		}
		return 0;
	}
	/* bogus input, I guess we fix it? */
	if (field_size >= dest_size) {
		field_size = (dest_size - 1);
	}

	b = ((unsigned long int)base);

	i = 0;
	while (v > 0) {
		d = v % b;
		v = v / b;
		if (d < 10) {
			reversed_buf[i++] = '0' + d;
		} else {
			reversed_buf[i++] = 'A' + (d - 10);
		}
	}

	/* If the field size was not specified (zero), or the value is
	   wider than the specified field width, then the field is
	   expanded to contain the value. */
	if (field_size < i) {
		field_size = i;
	}

	j = 0;
	/* not enough space for data, bail out! */
	if (field_size >= dest_size) {
		/* we don't know what to write, fill with "?" */
		while (j < (dest_size - 1)) {
			dest[j++] = '?';
		}
		dest[j] = '\0';
		return j;
	}

	/* fill padding to right justify */
	if (zero_padded && base == eh_decimal && was_negative) {
		dest[j++] = '-';
	}
	while (j < (field_size - i)) {
		dest[j++] = (zero_padded) ? '0' : ' ';
	}
	if (!zero_padded && base == eh_decimal && was_negative) {
		if (j > 0) {
			dest[j - 1] = '-';
		} else {
			dest[j++] = '-';
		}
	}

	/* walk the reversed_buf backwards */
	while (i) {
		dest[j++] = reversed_buf[--i];
	}

	/* NULL terminate */
	dest[j] = '\0';

	/* return characters written, excluding null character */
	return j;
}

#undef EH_LONG_BASE2_ASCII_BUF_SIZE

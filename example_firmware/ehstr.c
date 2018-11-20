/*
libecheck: a few handy stirng functions
Copyright (C) 2016 Eric Herman <eric@freesa.org>

This work is free software: you can redistribute it and/or modify it
under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at
your option) any later version.

This work is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
License and the GNU General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
(COPYING) and the GNU General Public License (COPYING.GPL3).  If not, see
<http://www.gnu.org/licenses/>.
*/

#ifndef LONGBITS
#include <values.h>		/* LONGBITS */
#endif

#include <ctype.h>		/* isspace */

#include "ehstr.h"

#ifndef Ehstr_memset
#include <string.h>		/* memset */
#define Ehstr_memset memset
#endif

char *utob(char *buf, size_t buf_size, unsigned long val, size_t bits)
{
	size_t i, shift, str_pos;

	if (buf_size == 0) {
		return buf;
	}

	if (bits == 0 || bits > LONGBITS) {
		bits = LONGBITS;
	}

	str_pos = 0;
	for (i = bits; i > 0; --i) {
		if (str_pos >= (buf_size - 1)) {
			break;
		}
		shift = (i - 1);
		buf[str_pos++] = ((val >> shift) & 1) ? '1' : '0';
	}
	buf[str_pos] = '\0';

	return buf;
}

size_t ehstrnlen(const char *str, size_t buf_size)
{
	size_t i;

	for (i = 0; i < buf_size; ++i) {
		if (*(str + i) == '\0') {
			return i;
		}
	}

	return buf_size;
}

void trimstr(char *str, size_t buf_size)
{
	size_t i, j, offset, len, nonwhite;

	len = (str && buf_size) ? strnlen(str, buf_size) : 0;
	if (len == 0) {
		return;
	}

	nonwhite = 0;
	for (i = 0; i < len && isspace(str[i]); ++i) ;
	offset = i;

	if (offset) {
		for (i = 0, j = offset; j < len; ++i, ++j) {
			str[i] = str[j];
			if (isspace(str[i]) == 0) {
				nonwhite = i;
			}
		}
		if (nonwhite + 1 < len) {
			str[nonwhite + 1] = '\0';
		}
		return;
	}

	nonwhite = 0;
	for (i = len; i > 0 && nonwhite == 0; --i) {
		if (isspace(str[i - 1])) {
			str[i - 1] = '\0';
		} else {
			nonwhite = 1;
		}
	}
}

void revstr(char *str, size_t buf_size)
{
	size_t i, j, len;
	char swap;

	if ((!str) || (!str[0])) {
		return;
	}

	len = strnlen(str, buf_size);
	for (i = 0, j = len - 1; i < j; ++i, --j) {
		swap = str[i];
		str[i] = str[j];
		str[j] = swap;
	}
}

static char nibble_to_hex(unsigned char nibble)
{
	if (nibble < 10) {
		return '0' + nibble;
	} else if (nibble < 16) {
		return 'A' + nibble - 10;
	} else {
		return '\0';
	}
}

static unsigned char hex_to_nibble(char hex)
{
	if (hex >= '0' && hex <= '9') {
		return (unsigned char)hex - '0';
	} else if (hex >= 'a' && hex <= 'f') {
		return (unsigned char)10 + hex - 'a';
	} else if (hex >= 'A' && hex <= 'F') {
		return (unsigned char)10 + hex - 'A';
	}

	/* crash */
	((char *)NULL)[0] = hex;
	return (unsigned char)hex;
}

char *decimal_to_hex(const char *dec_str, size_t dec_len, char *buf,
		     size_t buf_len)
{
	size_t i, j, k, hex_len;
	unsigned char *hex_buf, byte;

	if (dec_str == 0 || buf == 0 || buf_len < 5) {
		return NULL;
	}

	buf[0] = '0';
	buf[1] = 'x';

	/* first operate with binary data, convert to ASCII later */
	/* start by adjusting the buf for our needs - needs to be unsigned */
	hex_buf = (unsigned char *)buf + 2;	/* skip past leading "0x" */
	hex_len = buf_len - 3;	/* and leave room for the NULL terminator */

	/* zero out the buffer */
	for (i = 0; i < hex_len; ++i) {
		hex_buf[i] = '\0';
	}

	for (i = 0; i < dec_len && dec_str[i] != '\0'; ++i) {
		if (dec_str[i] < '0' || dec_str[i] > '9') {
			buf[0] = '\0';
			return NULL;
		}
		/* we're doing another digit, multiply previous by 10 */
		for (j = 0; j < hex_len; ++j) {
			k = hex_len - 1 - j;
			hex_buf[k] *= 10;
		}

		hex_buf[hex_len - 1] += (dec_str[i] - '0');

		/* carry */
		for (j = 0; j < hex_len; ++j) {
			k = hex_len - 1 - j;
			if (hex_buf[k] >= 16) {
				hex_buf[k - 1] += (hex_buf[k] / 16);
				hex_buf[k] = (hex_buf[k] % 16);
			}
		}
	}

	/* convert to ASCII */
	for (j = 0; j < hex_len; ++j) {
		hex_buf[j] = nibble_to_hex(buf[2 + j]);
	}

	/* left shift away leading zeros */
	/* first find the index (j) of the first non-zero */
	for (j = 0; j < hex_len && hex_buf[j] == '0'; ++j) {
		;
	}

	/* but work on whole bytes */
	/* since j was incremented, whole bytes of '0' will be odd */
	if (j % 2 == 0) {
		j -= 1;
	}

	/* leave a "00" if the leading byte would be greater than 7F */
	if (j + 1 < hex_len) {
		byte = 0;

		byte = hex_to_nibble(hex_buf[j]) << 4;
		byte += hex_to_nibble(hex_buf[j + 1]);
		if (byte > 0x7F) {
			j -= 2;
		}
	}

	/* next, shift all the contents "j" places to the left */
	for (i = 0; i < (hex_len - j); ++i) {
		hex_buf[i] = hex_buf[i + j];
	}

	/* add a trailing NULL */
	buf[buf_len - 1 - j] = '\0';

	return buf;
}

char *hex_to_decimal(const char *hex, size_t hex_len, char *buf, size_t buf_len)
{
	size_t i, j, k, dec_len;
	unsigned char *dec_buf;
	char ascii_offset;
	unsigned char num_val;

	if (hex == 0 || buf == 0 || buf_len < 2 || buf_len < hex_len) {
		return NULL;
	}

	/* skip over leading '0x' in string */
	if (hex_len >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
		hex += 2;
		hex_len -= 2;
	}

	/* first operate with binary data, convert to ASCII later */
	/* start by adjusting the buf for our needs - needs to be unsigned */
	dec_buf = (unsigned char *)buf;
	dec_len = buf_len - 1;	/* leave room for the NULL terminator */

	/* zero out the buffer */
	Ehstr_memset(dec_buf, 0, dec_len);

	for (i = 0; i < hex_len && hex[i] != 0; ++i) {
		ascii_offset = 0;
		if (hex[i] >= '0' && hex[i] <= '9') {
			ascii_offset = '0';
		} else if (hex[i] >= 'A' && hex[i] <= 'F') {
			ascii_offset = 'A';
		} else if (hex[i] >= 'a' && hex[i] <= 'f') {
			ascii_offset = 'a';
		}
		if (ascii_offset == 0) {
			dec_buf[0] = '\0';
			return NULL;
		}

		/* we're doing another digit, multiply previous by 16 */
		for (j = 0; j < dec_len; ++j) {
			k = dec_len - 1 - j;
			dec_buf[k] *= 16;
		}

		if (ascii_offset == '0') {
			num_val = (hex[i] - '0');
		} else {
			num_val = 10 + (hex[i] - ascii_offset);
		}
		dec_buf[dec_len - 1] += num_val;

		/* carry */
		for (j = 0; j < dec_len; ++j) {
			k = dec_len - 1 - j;
			if (dec_buf[k] >= 10) {
				dec_buf[k - 1] += (dec_buf[k] / 10);
				dec_buf[k] = (dec_buf[k] % 10);
			}
		}
	}

	/* convert to ASCII */
	for (j = 0; j < dec_len; ++j) {
		buf[j] = '0' + dec_buf[j];
	}

	/* left shift away leading zeros */
	/* first find the index (j) of the first non-zero */
	for (j = 0; j < dec_len && dec_buf[j] == '0'; ++j) {
		;
	}
	/* if everything is zero, include the last zero */
	if (j == dec_len) {
		--j;
	}
	/* next, shift all the contents "j" places to the left */
	for (i = 0; i < (dec_len - j); ++i) {
		dec_buf[i] = dec_buf[i + j];
	}

	/* add a trailing NULL */
	buf[buf_len - 1 - j] = '\0';

	return buf;
}

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

#include "ehbigint-priv.h"
#include "ehbigint-log.h"
#include "ehbigint-util.h"
#include "ehbigint-eba.h"

void ehbi_unsafe_reset_bytes_used(struct ehbigint *bi)
{
	size_t i;

	Trace_bi(10, bi);

	for (i = 0; i < bi->bytes_len; ++i) {
		if (bi->bytes[i] != 0) {
			break;
		}
	}
	bi->bytes_used = (bi->bytes_len - i);
	if (bi->bytes_used == 0) {
		bi->bytes_used = 1;
	}

	if ((bi->bytes_used == 1) && (bi->bytes[bi->bytes_len - 1] == 0x00)) {
		bi->sign = 0;
	}

	if ((bi->bytes_used < bi->bytes_len)
	    && (bi->bytes[bi->bytes_len - bi->bytes_used] > 0x7F)) {
		++(bi->bytes_used);
	}

	Trace_msg_s_bi(10, "end", bi);
	Return_void(10);
}

void ehbi_unsafe_zero(struct ehbigint *bi)
{
	Trace_bi(10, bi);

	Eba_memset(bi->bytes, 0x00, bi->bytes_len);
	bi->bytes_used = 1;
	bi->sign = 0;

	Trace_msg_s_bi(10, "end", bi);
	Return_void(10);
}

void ehbi_unsafe_clear_null_struct(struct ehbigint *bi)
{
	bi->bytes = NULL;
	bi->bytes_len = 0;
	bi->bytes_used = 0;
	bi->sign = 0;
}

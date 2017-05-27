/*
 Copyright (C) 2017 Eric Herman <eric@freesa.org>

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
*/

#include "print-data-type-sizes.h"
#include "eh-printf.h"

#include <limits.h>
#include <stdint.h>
#include <float.h>

#ifndef ULLONG_MAX
# define ULLONG_MAX ((unsigned long long)-1LL)
#endif

#ifndef UINTPTR_MAX
# define UINTPTR_MAX SIZE_MAX
#endif

int print_data_type_sizes()
{
	int bytes;

	bytes = eh_printf("\r\n");

	bytes += eh_printf("%26s:  %3lu bits\r\n", "CHAR_BIT",
		       (unsigned long)CHAR_BIT);

	bytes += eh_printf("%26s: %4d (%ssigned)\r\n",
		       "CHAR_MIN", (int)CHAR_MIN, (CHAR_MIN == 0 ? "un" : ""));

	bytes += eh_printf("%26s:  %3lu bytes %25lu max\r\n",
		       "sizeof(unsigned char)",
		       (unsigned long)sizeof(unsigned char),
		       (unsigned long)UCHAR_MAX);

	bytes += eh_printf("%26s:  %3lu bytes %25lu max\r\n",
		       "sizeof(unsigned short)",
		       (unsigned long)sizeof(unsigned short),
		       (unsigned long)USHRT_MAX);

	bytes += eh_printf("%26s:  %3lu bytes %25lu max\r\n",
		       "sizeof(unsigned int)",
		       (unsigned long)sizeof(unsigned int),
		       (unsigned long)UINT_MAX);

	bytes += eh_printf("%26s:  %3lu bytes %25lu max\r\n",
		       "sizeof(unsigned long)",
		       (unsigned long)sizeof(unsigned long),
		       (unsigned long)ULONG_MAX);

	bytes += eh_printf("%26s:  %3lu bytes %25llu max\r\n",
		       "sizeof(unsigned long long)",
		       (unsigned long)sizeof(unsigned long long),
		       (unsigned long long)ULLONG_MAX);

	bytes += eh_printf("\r\n");

	bytes += eh_printf("%26s:  %3lu bytes %25llu max\r\n", "sizeof(size_t)",
		       (unsigned long)sizeof(size_t),
		       (unsigned long long)SIZE_MAX);

	bytes += eh_printf("%26s:  %3lu bytes %25llu max\r\n", "sizeof(void *)",
		       (unsigned long)sizeof(void *),
		       (unsigned long long)UINTPTR_MAX);

	bytes += eh_printf("%26s:  %3lu bytes\r\n",
		       "sizeof(float)", (unsigned long)sizeof(float));

	bytes += eh_printf("%26s:  %3lu bytes\r\n",
		       "sizeof(double)", (unsigned long)sizeof(double));

	bytes += eh_printf("%26s:  %3lu bytes\r\n",
		       "sizeof(long double)",
		       (unsigned long)sizeof(long double));

	return bytes;
}

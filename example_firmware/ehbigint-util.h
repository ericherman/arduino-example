/*
ehbigint-util.c: support-functions for ehbigint.c
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
#ifndef EHBIGINT_UTIL_H
#define EHBIGINT_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef EHBI_NO_ALLOCA
#include <stdlib.h>
void ehbi_do_stack_free(void *ptr, size_t size);
#define ehbi_stack_alloc malloc
#define ehbi_stack_alloc_str "malloc"
#define ehbi_stack_free ehbi_do_stack_free
#else
#include <alloca.h>
void ehbi_no_stack_free(void *ptr, size_t size);
#define ehbi_stack_alloc alloca
#define ehbi_stack_alloc_str "alloca"
#define ehbi_stack_free ehbi_no_stack_free
#endif

#ifndef EHBI_SKIP_IS_PROBABLY_PRIME
#ifndef ehbi_random_bytes
#define EHBI_RANDOM_FROM_LINUX_DEV_URANDOM
int ehbi_dev_urandom_bytes(unsigned char *buf, size_t len);
#define ehbi_random_bytes ehbi_dev_urandom_bytes
#endif /* ehbi_random_bytes */
#endif /* EHBI_SKIP_IS_PROBABLY_PRIME */

#ifdef __cplusplus
}
#endif

#endif /* EHBIGINT_UTIL_H */

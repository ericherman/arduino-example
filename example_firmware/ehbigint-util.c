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

#include "ehbigint-util.h"
#include "ehbigint-log.h"

#ifdef EHBI_NO_ALLOCA
void ehbi_do_stack_free(void *ptr, size_t size)
{
	if (size == 0) {
		Ehbi_log_error2("size is 0? (%p, %lu)\n", ptr,
				(unsigned long)size);
	}
	free(ptr);
}
#else
void ehbi_no_stack_free(void *ptr, size_t size)
{
	if (size == 0) {
		Ehbi_log_error2("size is 0? (%p, %lu)\n", ptr,
				(unsigned long)size);
	}
}
#endif

#ifndef EHBI_SKIP_IS_PROBABLY_PRIME
#ifdef EHBI_RANDOM_FROM_LINUX_DEV_URANDOM
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/random.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

/* from Insane Coding blog "A good idea with bad usage: /dev/urandom"
   http://insanecoding.blogspot.nl/2014/05/a-good-idea-with-bad-usage-devurandom.html
*/
static long retrying_read(int fd, void *buf, size_t len)
{
	long amount_read, r;

	amount_read = 0;
	while (amount_read < ((long)len)) {
		r = read(fd, ((unsigned char *)buf) + amount_read,
			 len - amount_read);
		if (r > 0) {
			amount_read += r;
		} else if (!r) {
			break;
		} else if (errno != EINTR) {
			amount_read = -1;
			break;
		}
	}
	return (amount_read);
}

int ehbi_dev_urandom_bytes(unsigned char *buf, size_t len)
{
	int err, save_errno, urandom_fd, entropy;
	long bytes_read;
	const char *urandom_str;

	err = EHBI_SUCCESS;
	urandom_str = "/dev/urandom";

	urandom_fd = open(urandom_str, O_RDONLY);
	if (-1 == urandom_fd) {
		save_errno = errno;
		Ehbi_log_error3("open('%s') failed, errno: %d %s",
				urandom_str, save_errno, strerror(save_errno));
		return EHBI_FILE_ERROR;
	}
	if (-1 == ioctl(urandom_fd, RNDGETENTCNT, &entropy)) {
		save_errno = errno;
		Ehbi_log_error3("%s not a random device? errno: %d %s",
				urandom_str, save_errno, strerror(save_errno));
		err = EHBI_FILE_ERROR;
		goto ehbi_dev_urandom_bytes_end;
	}

	if (entropy < ((long)(len * 8))) {
		Ehbi_log_error3("%s lacks %lu entropy, has %d",
				urandom_str, (unsigned long)(len * 8), entropy);
	}

	bytes_read = retrying_read(urandom_fd, buf, len);
	if (bytes_read < ((long)len)) {
		Ehbi_log_error3("wanted to read %lu bytes from %s, read %ld",
				(unsigned long)len, urandom_str,
				(long)bytes_read);
	}

ehbi_dev_urandom_bytes_end:
	if (-1 == close(urandom_fd)) {
		save_errno = errno;
		Ehbi_log_error3("close('%s') failed, errno: %d %s",
				urandom_str, save_errno, strerror(save_errno));
	}

	return err;
}
#endif /* EHBI_RANDOM_FROM_DEV_URANDOM */
#endif /* EHBI_SKIP_IS_PROBABLY_PRIME */

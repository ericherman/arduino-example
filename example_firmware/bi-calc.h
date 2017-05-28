/*
 * Copyright (C) 2012 Eric Herman <eric@freesa.org>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef BI_CALC_H
#define BI_CALC_H

#ifndef SKETCH_SKIP_EHBI

#ifdef __cplusplus
extern "C" {
#endif

int bi_calc(const char *a, char op, const char *b, char *result, size_t len,
	    int verbose);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SKETCH_SKIP_EHBI */

#endif /* BI_CALC_H */

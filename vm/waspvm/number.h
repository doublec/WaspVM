/* Copyright (C) 2006, Ephemeral Security, LLC
 *
 * This library is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU Lesser General Public License, version 2.1
 * as published by the Free Software Foundation.
 * 
 * This library is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License 
 * for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License 
 * along with this library; if not, write to the Free Software Foundation, 
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#ifndef WASP_INTEGER_H
#define WASP_INTEGER_H 1

#include "memory.h"

#define WASP_NUMBER_TYPE_INTEGER 0
#define WASP_NUMBER_TYPE_REAL 1

struct wasp_number_data {
    struct wasp_object_data header;
    int type;
    union {
        wasp_integer intval;
        wasp_real    realval;
    };
};
typedef struct wasp_number_data* wasp_number;

WASP_H_TP( number );
WASP_H_VF( number );

wasp_number wasp_nf_integer( wasp_integer x );
wasp_integer wasp_integer_fn( wasp_number x );
wasp_number wasp_nf_real( wasp_real x );
wasp_real wasp_real_fn( wasp_number x );

WASP_H_RQ( real );
WASP_H_RQ( integer );
WASP_H_RQ( number );

#define REQ_INTEGER_ARG( vn ) wasp_integer vn = wasp_req_intarg( );
#define INTEGER_RESULT( vn )  RESULT( wasp_vf_integer( vn ) );
#define OPT_INTEGER_ARG( vn ) \
    wasp_boolean has_##vn; \
    wasp_integer vn = wasp_opt_intarg( &has_##vn );

#define REQ_REAL_ARG( vn ) wasp_real vn = wasp_req_realarg( );
#define REAL_RESULT( vn )  RESULT( wasp_vf_real( vn ) );
#define OPT_REAL_ARG( vn ) \
    wasp_boolean has_##vn; \
    wasp_real vn = wasp_opt_realarg( &has_##vn );

wasp_boolean wasp_is_real( wasp_value val );
wasp_boolean wasp_is_integer( wasp_value val );
wasp_boolean wasp_is_number( wasp_value val );
wasp_value wasp_vf_integer( wasp_integer ix );
wasp_value wasp_vf_real( wasp_real ix );
wasp_integer wasp_integer_fv( wasp_value val );
wasp_real wasp_real_fv( wasp_value val );

wasp_integer wasp_number_compare( wasp_value a, wasp_value b );
wasp_integer wasp_req_intarg( );
wasp_integer wasp_opt_intarg( );

wasp_real wasp_req_realarg( );
wasp_real wasp_opt_realarg( );

wasp_value wasp_num_plus( wasp_value lhs, wasp_value rhs );
wasp_value wasp_num_minus( wasp_value lhs, wasp_value rhs );
wasp_value wasp_num_multiply( wasp_value lhs, wasp_value rhs );
wasp_value wasp_num_divide( wasp_value lhs, wasp_value rhs );

void wasp_init_number_subsystem( );

#endif

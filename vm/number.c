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

#include "waspvm.h"

void wasp_format_number( wasp_string buf, wasp_value v ){
    if( wasp_is_imm( v ) )
        wasp_string_append_signed( buf, wasp_integer_fv( v ) );
    else{
        wasp_number n = (wasp_number)wasp_obj_fv( v );
        if( n->type == WASP_NUMBER_TYPE_INTEGER )
            wasp_string_append_signed( buf, wasp_integer_fv( v ) );
        else
            wasp_string_append_real( buf, wasp_real_fv ( v ) );
    }
}

wasp_integer wasp_number_compare( wasp_value a, wasp_value b ){
    if( wasp_is_integer( a ) && wasp_is_integer( b ) )
        return wasp_integer_fv( a ) - wasp_integer_fv( b );
    else if( wasp_is_integer( a ) && wasp_is_real( b ) )
        return (wasp_integer)( wasp_integer_fv( a ) - wasp_real_fv( b ) );
    else if( wasp_is_real( a ) && wasp_is_integer( b ) )
        return (wasp_integer)( wasp_real_fv( a ) - wasp_integer_fv( b ) );
    else if( wasp_is_real( a ) && wasp_is_real( b ) )
        return (wasp_integer)( wasp_real_fv( a ) - wasp_real_fv( b ) );
}

WASP_GENERIC_GC( number );
WASP_C_TYPE( number );

wasp_number wasp_nf_integer( wasp_integer x ){
    wasp_number io = WASP_OBJALLOC( number );
    io->type = WASP_NUMBER_TYPE_INTEGER;
    io->intval = x;
    return io;
}
wasp_number wasp_nf_real( wasp_real x ){
    wasp_number io = WASP_OBJALLOC( number );
    io->type = WASP_NUMBER_TYPE_REAL;
    io->realval = x;
    return io;
}
wasp_integer wasp_integer_fn( wasp_number x ){
    assert( x->type == WASP_NUMBER_TYPE_INTEGER );
    return x->intval;
}
wasp_real wasp_real_fn( wasp_number x ){
    assert( x->type == WASP_NUMBER_TYPE_REAL );
    return x->realval;
}
wasp_integer wasp_integer_fv( wasp_value x ){
    assert( wasp_is_integer( x ) || wasp_is_imm( x ) );

    if( wasp_is_imm( x ) ){
        return wasp_imm_fv( x );
    }else{
        return wasp_integer_fn( (wasp_number)wasp_obj_fv( x ) );
    }
}
wasp_real wasp_real_fv( wasp_value x ){
    assert( wasp_is_real( x ) );

    return wasp_real_fn( (wasp_number)wasp_obj_fv( x ) );
}
wasp_value wasp_vf_integer( wasp_integer x ){
    if(( x < 0 )||( x > WASP_MAX_IMM )){
        return wasp_vf_number( wasp_nf_integer( x ) );
    }else{
        return wasp_vf_imm( x );
    }
}
wasp_value wasp_vf_real( wasp_real x ){
    return wasp_vf_number( wasp_nf_real( x ) );
}
wasp_boolean wasp_is_integer( wasp_value x ){
    return wasp_is_imm( x ) || (wasp_is_number( x ) && ((wasp_number)wasp_obj_fv( x ))->type == WASP_NUMBER_TYPE_INTEGER);
}
wasp_boolean wasp_is_real( wasp_value x ){
    return wasp_is_number( x ) && ((wasp_number)wasp_obj_fv( x ))->type == WASP_NUMBER_TYPE_REAL;
}
wasp_boolean wasp_is_number( wasp_value x ){
    return wasp_is_imm( x ) || ( wasp_obj_type( wasp_obj_fv( x ) ) == wasp_number_type );
}
wasp_integer wasp_req_integer( wasp_value x ){
    if( wasp_is_imm( x ) ){ 
        return wasp_imm_fv( x ); 
    }else if( wasp_is_integer( x ) ){
        return wasp_integer_fn( (wasp_number)wasp_obj_fv( x ) );
    }else{
        wasp_errf( wasp_es_vm, "sx", "expected integer", x );
    }
}
wasp_integer wasp_req_intarg( ){
    return wasp_req_integer( wasp_req_any( ) ); 
}
wasp_integer wasp_opt_intarg( wasp_boolean* has ){
    wasp_value x = wasp_opt_any( has );
    if( *has ) return wasp_req_integer( x );
}

wasp_real wasp_req_real( wasp_value x ){
    if( wasp_is_real( x ) ){
        return wasp_real_fn( (wasp_number)wasp_obj_fv( x ) );
    }else{
        wasp_errf( wasp_es_vm, "sx", "expected real", x );
    }
}
wasp_real wasp_req_realarg( ){
    return wasp_req_real( wasp_req_any( ) );
}
wasp_real wasp_opt_realarg( wasp_boolean* has ){
    wasp_value x = wasp_opt_any( has );
    if( *has ) return wasp_req_real( x );
}

wasp_value wasp_num_plus( wasp_value lhs, wasp_value rhs ){
    if( wasp_is_integer( lhs ) && wasp_is_integer( rhs ) )
        return wasp_vf_integer( wasp_integer_fv( lhs ) + wasp_integer_fv( rhs ) );
    else if( wasp_is_integer( lhs ) && wasp_is_real( rhs ) )
        return wasp_vf_real( wasp_integer_fv( lhs ) + wasp_real_fv( rhs ) );
    else if( wasp_is_real( lhs ) && wasp_is_integer( rhs ) )
        return wasp_vf_real( wasp_real_fv( lhs ) + wasp_integer_fv( rhs ) );
    else if( wasp_is_real( lhs ) && wasp_is_real( rhs ) )
        return wasp_vf_real( wasp_real_fv( lhs ) + wasp_real_fv( rhs ) );
}

wasp_value wasp_num_minus( wasp_value lhs, wasp_value rhs ){
    if( wasp_is_integer( lhs ) && wasp_is_integer( rhs ) )
        return wasp_vf_integer( wasp_integer_fv( lhs ) - wasp_integer_fv( rhs ) );
    else if( wasp_is_integer( lhs ) && wasp_is_real( rhs ) )
        return wasp_vf_real( wasp_integer_fv( lhs ) - wasp_real_fv( rhs ) );
    else if( wasp_is_real( lhs ) && wasp_is_integer( rhs ) )
        return wasp_vf_real( wasp_real_fv( lhs ) * wasp_integer_fv( rhs ) );
    else if( wasp_is_real( lhs ) && wasp_is_real( rhs ) )
        return wasp_vf_real( wasp_real_fv( lhs ) - wasp_real_fv( rhs ) );
}

wasp_value wasp_num_multiply( wasp_value lhs, wasp_value rhs ){
    if( wasp_is_integer( lhs ) && wasp_is_integer( rhs ) )
        return wasp_vf_integer( wasp_integer_fv( lhs ) * wasp_integer_fv( rhs ) );
    else if( wasp_is_integer( lhs ) && wasp_is_real( rhs ) )
        return wasp_vf_real( wasp_integer_fv( lhs ) * wasp_real_fv( rhs ) );
    else if( wasp_is_real( lhs ) && wasp_is_integer( rhs ) )
        return wasp_vf_real( wasp_real_fv( lhs ) * wasp_integer_fv( rhs ) );
    else if( wasp_is_real( lhs ) && wasp_is_real( rhs ) )
        return wasp_vf_real( wasp_real_fv( lhs ) * wasp_real_fv( rhs ) );
}

wasp_value wasp_num_divide( wasp_value lhs, wasp_value rhs ){
    if( wasp_is_integer( lhs ) && wasp_is_integer( rhs ) )
        return wasp_vf_real( (double) wasp_integer_fv( lhs ) / wasp_integer_fv( rhs ) );
    else if( wasp_is_integer( lhs ) && wasp_is_real( rhs ) )
        return wasp_vf_real( wasp_integer_fv( lhs ) / wasp_real_fv( rhs ) );
    else if( wasp_is_real( lhs ) && wasp_is_integer( rhs ) )
        return wasp_vf_real( wasp_real_fv( lhs ) / wasp_integer_fv( rhs ) );
    else if( wasp_is_real( lhs ) && wasp_is_real( rhs ) )
        return wasp_vf_real( wasp_real_fv( lhs ) / wasp_real_fv( rhs ) );
}

WASP_BEGIN_PRIM( "+", plus )
    wasp_value sum = wasp_req_any( );
    for(;;){
        wasp_boolean has_x;
        wasp_value x = wasp_opt_any( &has_x );
        if( ! has_x )break;
        sum = wasp_num_plus( sum, x );
    }

    RESULT( sum );
WASP_END_PRIM( plus )

WASP_BEGIN_PRIM( "-", minus )
    wasp_value base = wasp_req_any( );

    int any = 0;

    for(;;){
        wasp_boolean has_x;
        wasp_value x = wasp_opt_any( &has_x );
        if( ! has_x )break;
        any = 1;
        base = wasp_num_minus( base, x );
    }

RESULT( any ? base : wasp_num_multiply( base, wasp_vf_integer( -1 ) ) );
WASP_END_PRIM( minus )

WASP_BEGIN_PRIM( "&", bit_and )
    REQ_INTEGER_ARG( base );
    for(;;){
        OPT_INTEGER_ARG( x );
        if( ! has_x )break;
        base &= x;
    }
    INTEGER_RESULT( base );
WASP_END_PRIM( bit_and )

WASP_BEGIN_PRIM( "|", bit_or )
    REQ_INTEGER_ARG( base );
    for(;;){
        OPT_INTEGER_ARG( x );
        if( ! has_x )break;
        base |= x;
    }
    INTEGER_RESULT( base );
WASP_END_PRIM( bit_or )

WASP_BEGIN_PRIM( "^", bit_xor )
    REQ_INTEGER_ARG( base );
    for(;;){
        OPT_INTEGER_ARG( x );
        if( ! has_x )break;
        base ^= x;
    }
    INTEGER_RESULT( base );
WASP_END_PRIM( bit_xor )

WASP_BEGIN_PRIM( "<<", bit_left )
    REQ_INTEGER_ARG( base );
    REQ_INTEGER_ARG( offset );
    NO_REST_ARGS( );
    INTEGER_RESULT( base << offset );
WASP_END_PRIM( bit_left )

WASP_BEGIN_PRIM( ">>", bit_right )
    REQ_INTEGER_ARG( base );
    REQ_INTEGER_ARG( offset );
    NO_REST_ARGS( );
    INTEGER_RESULT( base >> offset );
WASP_END_PRIM( bit_right )

WASP_BEGIN_PRIM( "!", bit_not )
    REQ_INTEGER_ARG( base );
    NO_REST_ARGS( );
    INTEGER_RESULT( base ^ 0xFFFFFFFF );
WASP_END_PRIM( bit_not )

void wasp_init_number_subsystem( ){
    WASP_I_TYPE( number );
    wasp_set_global( 
        wasp_symbol_fs( "<integer>" ), wasp_vf_type( wasp_number_type ) 
    ); 
    WASP_BIND_PRIM( plus );
    WASP_BIND_PRIM( minus );
    WASP_BIND_PRIM( bit_and );
    WASP_BIND_PRIM( bit_or );
    WASP_BIND_PRIM( bit_xor );
    WASP_BIND_PRIM( bit_left );
    WASP_BIND_PRIM( bit_right );
    WASP_BIND_PRIM( bit_not );
    wasp_set_global( 
        wasp_symbol_fs( "*max-int*" ), wasp_vf_integer( WASP_MAX_INT ) );
    wasp_set_global( 
        wasp_symbol_fs( "*max-imm*" ), wasp_vf_integer( WASP_MAX_IMM ) );
    wasp_set_global( 
        wasp_symbol_fs( "*min-int*" ), wasp_vf_integer( WASP_MIN_INT ) );
    wasp_set_global( 
        wasp_symbol_fs( "*min-imm*" ), wasp_vf_integer( WASP_MIN_IMM ) );
}

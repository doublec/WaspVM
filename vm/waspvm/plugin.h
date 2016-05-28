/* Copyright (C) 2006, Scott W. Dunlop <swdunlop@gmail.com>
 * Portions copyright (C) 2006, Ephemeral Security, LLC -- used under the LGPL.
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

#ifndef WASP_PLUGIN_H
#define WASP_PLUGIN_H 1

void wasp_init_plugin_subsystem( );
void wasp_load_plugin( const char* path, const char* init );

#endif

/*
 * $Id: pe_cli.h 2786 2013-07-09 16:42:55 FreeWAF Development Team $
 *
 * (C) 2013-2014 see FreeWAF Development Team
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GNU Make; see the file LICENSE.GPLv2.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *  http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
 
#ifndef _PE_CLI_H_
#define _PE_CLI_H_

#ifdef __cplusplus
extern "C" {
#endif

#define cli_printf_info(context, format, args...) cparser_printf(context, format, ##args)

AP_DECLARE(void) cli_printf(cparser_context_t *context, const char *format, ...);
AP_DECLARE(void) cli_fprintf(cparser_context_t *context, const char *format, ...);
AP_DECLARE(int) clear_server_policy(void);
AP_DECLARE(int) interface_find(char *intf_name);
AP_DECLARE(int) bridge_check(char *bridge_name);
AP_DECLARE(int) clear_bridge();

#ifdef __cplusplus
}
#endif

#endif


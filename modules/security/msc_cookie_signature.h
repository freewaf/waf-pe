/*
 * $Id: msc_cookie_signature.h 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
 
/**
 * get_cookie_signature - 获取cookie签名
 * @msr: 处理上下文
 * @cookie_name_tb: 用于生成签名的cookiename清单
 * @need_ip: 生成签名时是否需要ip
 *
 * 成功返回签名字符串，失败时返回NULL
 */
extern char * get_cookie_signature(modsec_rec *msr, apr_table_t *cookie_name_tb, int need_ip);


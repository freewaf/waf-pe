/*
 * $Id: mod_offline.h 2786 2013-07-09 16:42:55 FreeWAF Development Team $
 *
 * (C) 2013-2014 FreeWAF Development Team
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
#ifndef MOD_OFFLINE_H
#define MOD_OFFLINE_H 

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_hooks.h"
#include "apr_network_io.h"

#if !defined(WIN32)
#define OFFLINE_DECLARE(type) type
#define OFFLINE_DECLARE_NONSTD(type) type
#define OFFLINE_DECLARE_DATA
#elif defined(OFFLINE_DECLARE_STATIC)
#define OFFLINE_DECLARE(type) type __stdcall
#define OFFLINE_DECLARE_NONSTD(type) type
#define OFFLINE_DECLARE_DATA
#elif defined(OFFLINE_DECLARE_EXPORT)
#define OFFLINE_DECLARE(type) __declspec(dllexport) type __stdcall
#define OFFLINE_DECLARE_NONSTD(type) __declspec(dllexport) type
#define OFFLINE_DECLARE_DATA __declspec(dllexport)
#else
#define OFFLINE_DECLARE(type) __declspec(dllimport) type __stdcall
#define OFFLINE_DECLARE_NONSTD(type) __declspec(dllimport) type
#define OFFLINE_DECLARE_DATA __declspec(dllimport)
#endif

#define OFFLINE_OPTIONAL_HOOK(name,fn,pre,succ,order) \
        APR_OPTIONAL_HOOK(offline,name,fn,pre,succ,order)

/* 预处理连接可选钩子 */
APR_DECLARE_EXTERNAL_HOOK(offline, OFFLINE, int, pre_connection, (conn_rec *c, void *csd))

/* 创建请求可选钩子 */
APR_DECLARE_EXTERNAL_HOOK(offline, OFFLINE, int, create_req, (request_rec *r, request_rec *pr))

#endif



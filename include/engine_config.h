/*
 * $Id: engine_config.h 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

#ifndef APACHE_ENGINE_CONFIG_H
#define APACHE_ENGINE_CONFIG_H


#ifdef __cplusplus
extern "C" {
#endif

#include "cli_common.h"

enum  directive_type {
    CONTAINER_COMMAND,
    CLOSED_CONTAINER_COMMAND,
    SINGLE_COMMAND  
};

/**********************************************************
 * 监听端口相关接口
 **********************************************************/
/**
 * Allocate listening port.
 * @return OK (is exceeded) or others( false)
 */
AP_DECLARE(int) ap_listen_ports_alloc(void);

/**
 * Allocate bridge port.
 * @return OK (is exceeded) or others( false)
 */
AP_DECLARE(int) ap_bridge_port_alloc(void);
/**********************************************************
 * 黑白名单相关接口
 **********************************************************/

/**
 * Deal with all of the access list.
 * @param lst Access control list. Including black and white lists.
 * @return OK (is exceeded) or others( false)
 */
AP_DECLARE(int) ap_access_list_handle(int lst);

/**********************************************************
 * 服务器策略相关接口
 **********************************************************/

/**
 * Deal with all of the server policy.
 * @param sp_hash Server policy hash table.
 * @return OK (is exceeded) or others( false)
 */
AP_DECLARE(int) ap_server_policy_walk(apr_hash_t *sp_hash);

/**********************************************************
 * 离线模式相关接口
 **********************************************************/

/**
 * Termination of the offline mode.
 * @return
 */
AP_DECLARE(void) ap_offline_mode_term(void);

/**
 * Offline mode initialization.
 * @return OK (is exceeded) or others( false)
 */
AP_DECLARE(int) ap_offline_configure(void);

/**********************************************************
 * 其他的接口
 **********************************************************/

/**
 * Engine config module initialization.
 * @param p Persistent configuration pool
 * @param ptrans Temporary pool
 * @return OK (is exceeded) or others( false)
 */
AP_DECLARE(int) ap_engine_config_init(apr_pool_t *p, apr_pool_t *ptrans);

#ifdef __cplusplus
}
#endif

#endif /* !APACHE_ENGINE_CONFIG_H */
/** @} */


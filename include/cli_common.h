/*
 * $Id: cli_common.h 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

#ifndef APACHE_CLI_COMMON_H
#define APACHE_CLI_COMMON_H


#ifdef __cplusplus
extern "C" {
#endif

#include "apr.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_hash.h"
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "mpm_common.h"
#include "ap_mpm.h"
#include "cparser.h"
#include "pod.h"

/* 公共常量定义 */

/* 1表示pe在前台运行，0表示pe转到后台运行 */
#define PE_FOREGROUND_RUN 0

#define TPROXY_HTTP     3129
#define TPROXY_HTTPS    3130

#ifndef BUF_LEN_MAX
#define BUF_LEN_MAX 1024        /** maximun length of buf */
#endif

#ifndef NAME_LEN_MAX
#define NAME_LEN_MAX 32         /** maximun length of name */
#endif

#ifndef COMMAND_LEN_MAX
#define COMMAND_LEN_MAX 400
#endif

#ifndef STR_LEN_MAX
#define STR_LEN_MAX 256         /** Maximum length of string array */
#endif

#ifndef DOMAIN_LEN_MAX
#define DOMAIN_LEN_MAX 64       /** Maximum length of domain name */
#endif

#ifndef SERVER_PLCY_LIMIT
#define SERVER_PLCY_LIMIT 10    /** Maximum number of server policy */
#endif

#ifndef DEFAULT_POLICY
#define DEFAULT_POLICY        "default"
#endif

#ifndef DEFAULT_ATTACK_LEVEL
#define DEFAULT_ATTACK_LEVEL   5
#endif

#ifndef INIT_ARR_LEN
#define INIT_ARR_LEN 5          /** Array initialization length */
#endif

#ifndef FLAG_ALL
#define FLAG_ALL        1 /* TRUE/FALSE取代 */
#endif

#ifndef OFFLINE_INTF_NUM
#define OFFLINE_INTF_NUM   32   /** off-line interface number */
#endif

#ifndef OFFLINE_INTF_MAX
#define OFFLINE_INTF_MAX   4   /** 离线可配置的最大接口个数 */
#endif

#ifndef NEW_KERNEL
#define NEW_KERNEL         1
#endif

#ifndef MAX_ARGV_NUM
#define  MAX_ARGV_NUM         9
#endif

#ifndef  ARGUMENT_SEPARATOR_DEFAULT
#define  ARGUMENT_SEPARATOR_DEFAULT   '&'
#endif

#define WORK_MODE_ACTIVE      "active"
#define WORK_MODE_INACTIVE    "inactive"

#ifndef  DEFAULT_CLI_PROMPT
#define DEFAULT_CLI_PROMPT    "FreeWAF"
#endif

/* 配置更新方式 */
typedef enum {
    GRACEFUL,               /** Graceful Restart */
    CLI_REST,               /** Graceful Restart, CLI exit and restart */
    SRV_TERM                /** Server terminates and exit */
} ap_update_mode_t;

/* 配置状态 */
typedef enum {
    CONF_START,             /** Start the configuration */
    CONF_READY,             /** Configuration has been prepared */
    CONF_DONE               /** Configuration has been completed */
} ap_conf_status_t;

/* 工作模式 */
typedef enum {
    WORK_BRIDGE,            /** bridge-proxy work mode */
    WORK_ROUTE,             /** route-proxy work mode */
    WORK_REVERSE,           /** reverse-proxy work mode */
    WORK_OFFLINE,           /** offline work mode */
    WORK_NUM,
    WORK_DEFAULT = WORK_BRIDGE
} ap_proxy_mode_t;

/* 工作模式选项操作标记 */
enum proxy_mode_opt_flags {
    MODE_FLAG,
};

/* 服务器策略选项操作标记 */
enum sp_opt_flags {
    ADVANCE_FLAG,
    ARGUMENT_SEPARATOR_FLAG,
    COOKIE_FORMAT_FLAG,
    ENGINE_FLAG,
    COMMIT_FLAG
};

/* 保护模式 */
typedef enum {
    BLOCK_OFF,              /** do not process rules */
    BLOCK_DET,              /** process rules but never executes any disruptive actions */
    BLOCK_ON                /** process rules */
} ap_protect_mode_t;

/* 审核日志 */
enum audit_flags {
    ACCESS_LOG,
    ATTACK_LOG,
    ADMIN_LOG,
    ALL_LOG,
    UNKNOWN_LOG
};

/* Cookie格式 */
typedef enum cookie_format {
    VERSION_0,    /* version-0 */
    VERSION_1     /* version-1 */
} cookie_format_t;

/* 客户端请求协议 */
enum req_proto {
    PROTO_HTTP = 1,
    PROTO_HTTPS
};

/* 以下是CLI数据结构定义*/

/* Structure used to pass information to the thread responsible for
 * creating the rest of the threads.
 */
typedef struct {
    process_rec *process;
    apr_pool_t *pool;
    apr_threadattr_t *threadattr;
} cli_thread_starter;

/* 监听端口的相关数据结构 */
typedef struct listen_port_t listen_port_t;
struct listen_port_t {
    /** The pool to use... */
    apr_pool_t *pool;

    listen_port_t *prev;
    listen_port_t *next;
    struct in_addr ipaddr;
    int proto;
    apr_port_t port;
    ap_proxy_mode_t create_mode;
};

/* 透明端口和桥相关数据结构 */
typedef struct bridge_port_t bridge_port_t;
struct bridge_port_t {
    /** The pool to use... */
    apr_pool_t *pool;

    bridge_port_t *prev;
    bridge_port_t *next;

    char br_name[NAME_LEN_MAX];
    int proto;
    apr_port_t ser_port;
    apr_port_t tproxy_port;
    ap_proxy_mode_t create_mode;
    int deploied;     /* 标识该桥是否被真正配置 */
    int deleted;      /* 标识该桥是否需要被删除 */
};

/* 服务器策略类型先在这里声明 */
typedef struct server_policy_t server_policy_t;

/* 配置安全策略相关数据结构 */
typedef struct sec_subpolicy_t sec_subpolicy_t;
struct sec_subpolicy_t {
    /** Pool associated with this subpolicy */
    apr_pool_t *pool;

    int sec_subpolicy;              /** 子策略类型 */
    char sec_policy[NAME_LEN_MAX];  /** Belong to the security policy  */
    int action;
    int log;
    int status;
};

typedef struct keyword_t keyword_t;
struct keyword_t {
    /** Pool associated with this keyword */
    apr_pool_t *pool;

    int type;
    /* 用来标识是否是关键字all */
    int flag;
    apr_array_header_t *keyword;
    int sec_subpolicy;              /** Belong to the security sub policy  */
    char sec_policy[NAME_LEN_MAX];  /** Belong to the security policy  */
};

typedef struct sec_policy_t sec_policy_t;
struct sec_policy_t {
    /** The name of the security policy */
    char name[NAME_LEN_MAX];
    /** The server policy associated with this security policy */
    server_policy_t *ser_policy;
    struct sec_policy_t *prev;
    struct sec_policy_t *next;
};

typedef struct sec_policy_list_t sec_policy_list_t;
struct sec_policy_list_t {
    /** Pool associated with this security policy list */
    apr_pool_t *pool;

    /** The name of the security policy */
    char name[NAME_LEN_MAX];
    /** The security and server policy linking list head */
    sec_policy_t head;
};

/* 配置服务器策略相关数据结构 */
typedef struct virt_host_t virt_host_t;
struct virt_host_t {
    /** The pool to use... */
    apr_pool_t *pool;

    virt_host_t *prev;
    virt_host_t *next;
    /* Information about the virtual host itself */
    struct in_addr ipaddr;
    char server_name[DOMAIN_LEN_MAX];
    int proto;
    int phttp;
    int phttps;
};

typedef struct orig_host_t orig_host_t;
struct orig_host_t {
    /** The pool to use... */
    apr_pool_t *pool;

    /** Back-end original server's address or hostname */
    struct in_addr ipaddr;
    int proto;
    apr_port_t port;
};

struct server_policy_t {
    /** Pool associated with this server policy */
    apr_pool_t *pool;
    /** Pool associated with this Virtual Host */
    apr_pool_t *pvhost;
    /** The name of the server_policy */
    char name[NAME_LEN_MAX];
    /** The virtual host for this server_policy */
    server_rec *server;
    /** It's the default server_policy */
    int is_default;
    /** The work mode for this server_policy */
    ap_proxy_mode_t work_mode;
    /** Option is set to be a flag */
    int opt_flags;

    /* cache root dir */
    char *cache_root;

    /** The security policy associated with this server policy */
    sec_policy_t *sec_policy;
    /** virt_host contains the virtual host address */
    virt_host_t *virt_host;
    /** orig_host contains back-end original server address */
    orig_host_t *orig_host;
    ap_protect_mode_t engine;       /** [online-detect-only] */
    int audit_set;                  /** audit log has been set */
    int audit_log;                  /** {all | {[access_log] [attack_log]}} */
    int atlog_lev;                  /** attack_log [severity level]*/
    char argument_separator;
    cookie_format_t cookie_format;  /** {version-0 | version-1} */

    int commit_status;
};

typedef struct admin_log_t admin_log_t;
struct admin_log_t {
    apr_time_t time;
    char *ip;
    char *admin_name;
    char *tty;
    char *action;
};

/* CLI全局变量 */    
extern ap_proxy_mode_t ap_work_mode;        /* 服务器工作模式 */
extern int ap_off_iface;                    /* 离线网口索引 */
extern listen_port_t *ap_listen_ports;      /* 监听端口列表 */
extern bridge_port_t *ap_bridge_ports;      /* 桥端口列表 */
extern server_rec *ap_main_server;          /* 主服务器配置 */

/* 用于引擎重启时，同步cli线程和主线程 */
ap_pod_t *pe_to_cli_pod;
ap_pod_t *cli_to_pe_pod;

extern int cli_thread_may_exit;
extern cparser_t cli_parser;                /* Cparser结构体 */
extern char g_cli_prompt[NAME_LEN_MAX];     /* cli命令提示符 */

/* 以下是CLI全局函数声明 */
#define PORT_IN_RANGE(port) ((port) > 0 && (port) <= 65535)

/* IPv4地址打印宏 */
#define NIPQUAD(addr) \
        ((unsigned char*)&addr)[3], \
        ((unsigned char*)&addr)[2], \
        ((unsigned char*)&addr)[1], \
        ((unsigned char*)&addr)[0]

/* 位操作宏 */
#define BitGet(val, pos) (((val)>>(pos)) & 1)
#define BitSet(val, pos) ((val) |= (1<<(pos)))
#define BitClr(val, pos) ((val) &= ~(1<<(pos)))

/* 用于引擎重启时，主线程和cli线程的同步 */
AP_DECLARE(int) ap_sync_init(apr_pool_t *pool);

/**********************************************************
 * 黑白名单相关接口
 **********************************************************/

/**
 * Give effect to the access list.
 * @param lst Access control list. Including black and white lists.
 * @return OK (is exceeded) or others( false)
 */
AP_DECLARE(int) ap_access_list_deploy(int lst);

/**
 * Clear the dynamic black-list
 * @param lst Access control list. Including black and white lists.
 * @param addr IP address
 * @return OK (is exceeded) or others( false)
 */
AP_DECLARE(int) ap_dyn_blacklist_clear(int lst, const char *addr);

/**********************************************************
 * 安全策略相关接口
 **********************************************************/

/**
 * Find security policy list.
 * @param name The name of security policy for the security policy list.
 * @return The security policy list
 */
AP_DECLARE(sec_policy_list_t *) ap_secpolicy_list_find(const char *name);

/**
 * Add a security policy list.
 * @param name The name of security policy for the security
 *             policy list.
 * @return OK (is exceeded) or others( false)
 */
AP_DECLARE(int) ap_secpolicy_list_add(const char *name);

/**
 * Delete a security policy list.
 * @param name The name of security policy for the security
 *             policy list.
 * @return OK (is exceeded) or others( false)
 */
AP_DECLARE(int) ap_secpolicy_list_del(const char *name);

/**
 * Deploy a security policy.
 * @param name The name of security policy.
 * @return OK (is exceeded) or others( false)
 */
AP_DECLARE(int) ap_secpolicy_deploy(const char *name);

/**********************************************************
 * 服务器策略相关接口
 **********************************************************/

/**
 * Deploy a server policy.
 * @param sp The server policy to be deployed.
 * @return OK (is exceeded) or others( false)
 */
AP_DECLARE(int) ap_server_policy_deploy(server_policy_t *sp);

/**
 * Remove a server policy.
 * @param name The name of the server policy.
 * @return OK (is exceeded) or others( false)
 */
AP_DECLARE(int) ap_server_policy_remove(const char *name);

/**
 * Clear all server policy.
 * @return OK (is exceeded) or others( false)
 */
AP_DECLARE(int) ap_server_policy_clear(void);

/**
 * Create default server policy.
 */
AP_DECLARE(int) ap_create_default_serpolicy(void);

AP_DECLARE(int) ap_change_default_policy_workmode(ap_proxy_mode_t newmode);
/**********************************************************
 * 其他的接口
 **********************************************************/
/* 获取日志类型 */
AP_DECLARE(enum audit_flags) ap_get_log_type(char *type);

AP_DECLARE(void) admin_log_process(cparser_context_t *context, char *action);

/* 清除访问日志 */
AP_DECLARE(void) clear_accesslog_content();

/* 清除攻击日志 */
AP_DECLARE(void) clear_attacklog_content();

/* 清除管理日志 */
AP_DECLARE(void) clear_adminlog_content();

/**
 * Update all the configuration.
 * @param upmode Configuration update mode
 * @return OK (is exceeded) or others( false)
 */
AP_DECLARE(int) ap_config_update(cparser_context_t *context, ap_proxy_mode_t new_mode, 
                  int workmode_switching, ap_update_mode_t upmode);

/**
 * Cli module initialization.
 * @param process The process this server is running in
 * @return OK (is exceeded) or others( false)
 */
AP_DECLARE(int) ap_cli_common_init(process_rec *process);

/**
 * The client thread dealing with the CLI command.
 * @param thd The thread handle
 * @param dummy The parameters passed to the thread
 * @return void
 */
AP_DECLARE(void *)  ap_cli_thread(apr_thread_t *thd, void * dummy);

/**********************************************************
 * 监听端口相关接口
 **********************************************************/
/* 创建一个ebtalbes配置 */
AP_DECLARE(int) create_ebtables_configure(char *br, int ser_port, int tproxy_port);

/* 删除一个ebtables配置 */
AP_DECLARE(int) destroy_ebtables_configure(char *br, int ser_port, int tproxy_port);

/* 创建一个iptables配置 */
AP_DECLARE(int) create_iptables_configure(int ser_port, int tproxy_port);

/* 删除一个iptables配置 */
AP_DECLARE(int) destroy_iptables_configure(int ser_port, int tproxy_port);

/* 模式切换前的清除操作 */
AP_DECLARE(int) workemode_change_prepare(cparser_context_t *context, ap_proxy_mode_t new_mode);

/**********************************************************
 * 初始化函数相关                                          *
 **********************************************************/
/* 全局策略初始化 */
AP_DECLARE(int) global_init(apr_pool_t *p);

/* 服务器策略初始化 */
AP_DECLARE(int) server_policy_init(apr_pool_t *p, apr_pool_t *ptrans);

/* 安全策略初始化 */
AP_DECLARE(int) security_policy_init(apr_pool_t *p);

/* 黑白名单初始化 */
AP_DECLARE(int) blackwhite_list_init(apr_pool_t *p);

/* 攻击日志显示初始化 */
AP_DECLARE(int) show_attacklog_init(apr_pool_t *p);

/* 访问日志显示初始化 */
AP_DECLARE(int) show_accesslog_init(apr_pool_t *p);

/* 管理日志显示初始化 */
AP_DECLARE(int) show_adminlog_init(apr_pool_t *p);

/* 接口配置初始化 */
AP_DECLARE(int) interface_init(apr_pool_t *p);

/* 查询接口是否存在 */
AP_DECLARE(int) ap_query_interface_exist(char *device_name);

/* 执行脚本 */
AP_DECLARE(int) ap_exec_shell(char *shell_name, char **argv);

/* 掩码正确性检测 */
AP_DECLARE(int) ap_check_mask_validation(apr_int32_t mask);

#ifdef __cplusplus

}
#endif

#endif /* !APACHE_CLI_COMMON_H */
/** @} */



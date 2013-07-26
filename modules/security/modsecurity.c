/*
* ModSecurity for Apache 2.x, http://www.modsecurity.org/
* Copyright (c) 2004-2011 Trustwave Holdings, Inc. (http://www.trustwave.com/)
*
* You may not use this file except in compliance with
* the License. You may obtain a copy of the License at
*
*  http://www.apache.org/licenses/LICENSE-2.0
*
* If any of the files related to licensing are missing or if you have any
* other questions related to licensing please contact Trustwave Holdings, Inc.
* directly using the email address security@modsecurity.org.
*/

#include <stdlib.h>
#include <GeoIP.h>
#include <GeoIPCity.h>
#include "apr_global_mutex.h"
#include "modsecurity.h"
#include "msc_parsers.h"
#include "msc_util.h"
#include "msc_xml.h"
#include "apr_version.h"
#include "apr_dbd.h"
#include "ip_bwlist.h"
#include "url_bwlist.h"

#define INSERT_ATTACKLOG_TABLE_SQL "insert into attack_log_table values(" \
            "%" APR_INT64_T_FMT ", '%s', %u, '%s', %u, x'%s', x'%s', '%s', '%s', x'%s', '%s'," \
            " '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s');"
#define INSERT_ATTACKLOG_TABLE_SQL_TEMP "insert into attack_log_temp_table values(" \
            "%" APR_INT64_T_FMT ", '%s', '%s', '%s', '%s', '%s', '%s');"

unsigned long int DSOLOCAL dbm_timeout = 3600; 
unsigned long int DSOLOCAL unicode_codepage = 20127;
int DSOLOCAL *unicode_map_table = NULL;
/* 允许访问 拒接访问 重定向 代理 断开连接 离线检测 */
static const char *actions[] = {"E58581E8AEB8E8AEBFE997AE", "E68B92E7BB9DE8AEBFE997AE", "E9878DE5AE9AE59091", 
        "E4BBA3E79086E8AFB7E6B182", "E696ADE5BC80E8BF9EE68EA5", "E7A6BBE7BABFE6A380E6B58B", NULL};
/* 高 高 高 中 中 中 低 低 */
static const char *severities[] = {"E9AB98", "E9AB98", "E9AB98", "E4B8AD", "E4B8AD", 
        "E4B8AD", "E4BD8E", "E4BD8E", NULL};
/* URL参数 POST表单 cookie 请求头 请求体 响应头 响应体 其他 */
static char *g_attack_domain[] = {"55524CE58F82E695B0", "504F5354E8A1A8E58D95", "636F6F6B6965", "E8AFB7E6B182E5A4B4",
                             "E8AFB7E6B182E4BD93", "E5938DE5BA94E5A4B4", "E5938DE5BA94E4BD93", "E585B6E4BB96", NULL};

static apr_status_t msc_unicode_map_destroy(void *data)
{
    if (unicode_map_table != NULL) {
        free(unicode_map_table);
        unicode_map_table = NULL;
    }

    return APR_SUCCESS;
}

/* 初始化unicode映射表 */
apr_status_t msc_unicode_map_init(apr_pool_t *mp)
{
    char errstr[1024];
    unicode_map *u_map;
    apr_int32_t wanted = APR_FINFO_SIZE;
    apr_finfo_t finfo;
    apr_status_t rc;
    apr_size_t nbytes;
    unsigned int codepage = 0;
    char *buf = NULL, *p = NULL, *savedptr = NULL;
    char *ucode = NULL, *hmap = NULL;
    int found = 0, processing = 0;
    int Code = 0, Map = 0;

    if(unicode_map_table != NULL)   {
        free(unicode_map_table);
        unicode_map_table = NULL;
    }

    u_map = apr_pcalloc(mp, sizeof(unicode_map));
    if (u_map == NULL)  {
        return -1;
    }

    u_map->map = NULL;   
    u_map->mapfn = ap_server_root_relative(mp, DEF_UNICODEMAPFILE_VAL); 
    
    if ((rc = apr_file_open(&u_map->map, u_map->mapfn, APR_READ, APR_OS_DEFAULT, mp)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Could not open unicode map file \"%s\": %s", 
            u_map->mapfn, apr_strerror(rc, errstr, 1024));
        return -1;
    }

    if ((rc = apr_file_info_get(&finfo, wanted, u_map->map)) != APR_SUCCESS)  {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
            "Could not get unicode map file information \"%s\": %s", u_map->mapfn, 
            apr_strerror(rc, errstr, 1024));
        apr_file_close(u_map->map);
        return -1;
    }

    buf = (char *)malloc(finfo.size + 1);
    if (buf == NULL)   {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,  "Could not alloc memory for unicode map");
        apr_file_close(u_map->map);
        return -1;
    }

    rc = apr_file_read_full(u_map->map, buf, finfo.size, &nbytes);

    if (unicode_map_table != NULL)  {
        memset(unicode_map_table, -1, (sizeof(int)*65536));
    } else {
        unicode_map_table = (int *)malloc(sizeof(int) * 65536);
        if (unicode_map_table == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Could not alloc memory for unicode map");
            free(buf);
            buf = NULL;
            apr_file_close(u_map->map);
            return -1;
        }

        memset(unicode_map_table, -1, (sizeof(int)*65536));
    }

    /* Setting some unicode values - http://tools.ietf.org/html/rfc3490#section-3.1 */

    /* Set 0x3002 -> 0x2e */
    unicode_map_table[0x3002] = 0x2e;
    /* Set 0xFF61 -> 0x2e */
    unicode_map_table[0xff61] = 0x2e;
    /* Set 0xFF0E -> 0x2e */
    unicode_map_table[0xff0e] = 0x2e;
    /* Set 0x002E -> 0x2e */
    unicode_map_table[0x002e] = 0x2e;

    p = apr_strtok(buf, CODEPAGE_SEPARATORS, &savedptr);

    while (p != NULL) {

        codepage = atol(p);

        if (codepage == unicode_codepage) {
            found = 1;
        }

        if (found == 1 && (strchr(p,':') != NULL)) {
            char *mapping = strdup(p);
            processing = 1;

            if(mapping != NULL) {
                ucode = apr_strtok(mapping,":", &hmap);
                sscanf(ucode,"%x",&Code);
                sscanf(hmap,"%x",&Map);
                if(Code >= 0 || Code <= 65535) {
                    unicode_map_table[Code] = Map;
                }

                free(mapping);
                mapping = NULL;
            }
        }

        if (processing == 1 && (strchr(p,':') == NULL)) {
            free(buf);
            buf = NULL;
            break;
        }

        p = apr_strtok(NULL,CODEPAGE_SEPARATORS,&savedptr);
    }

    apr_file_close(u_map->map);
    free(buf);
    buf = NULL;

    apr_pool_cleanup_register(mp, (const void *)unicode_map_table, msc_unicode_map_destroy, 
        apr_pool_cleanup_null);

    return APR_SUCCESS;    
}

/**
 * Format an alert message.
 */
const char *msc_alert_message(modsec_rec *msr, msre_actionset *actionset,
                const char *action_message, const char *rule_message)
{
    const char *message = NULL;

    if (rule_message == NULL) {
        rule_message = "Unknown error.";
    }

    if (action_message == NULL) {
        message = apr_psprintf(msr->mp, "%s%s", rule_message, msre_format_metadata(msr, actionset));
    } else {
        message = apr_psprintf(msr->mp, "%s %s%s", action_message, rule_message, msre_format_metadata(msr, actionset));
    }

    return message;
}

/* sql语句转义 */
const char *dbd_escape(const apr_dbd_driver_t *driver, apr_pool_t *pool, const char *string,
                apr_dbd_t *handle)
{
    const char *p;
    
    p = apr_dbd_escape(driver, pool, string, handle);
    if (p == NULL) {
        return "";
    }

    return p;
}

#ifdef DEBUG_DBLOG
/* 获取攻击类型名 */
static const char *get_attack_string(modsec_rec *msr)
{
    switch(msr->black_list_flag) {
    case IP_BLIST_ATTACK:
        return "IP Black Attack";
    case URL_BLIST_ATTACK:
        return "URL Black Attack";
    default:
        return "";
    }
}

/* 获取攻击域 */
static char *get_attack_domain(msre_var *var, const char *method)
{
    if (       !strcmp(var->name, "ARGS") 
            || !strcmp(var->name, "ARGS_NAME")
            || !strcmp(var->name, "ARGS_COMBINED_SIZE")) {
        if (!strcmp(method, "GET")) {
            return g_attack_domain[DOMAIN_URL_ARGS];
        } else if (!strcmp(method, "POST")) {
            return g_attack_domain[DOMAIN_POST_ARGS];
        }
    }

    return g_attack_domain[var->metadata->domain];
}

/**
 * record attack log on in temporary buffer msr->auditlogs and make the sql statement format.
 */
void msc_record_attacklog(modsec_rec *msr, msre_var *var, msre_actionset *actionset)
{
    int i;
    msre_action *action;
    const apr_array_header_t *tarr = NULL;
    const apr_table_entry_t *telts = NULL;
    const char *cliip;
    unsigned int cliport;
    const char *serip;
    unsigned int serport;
    const char *url;
    const char *method;
    const char *protocol;
    const char *attname;
    const char *clios;
    const char *clibrowser;
    int action_id;
    int severity_id;
    char *attdomain;
    char *sql_statement = NULL;
    char *sql_statement_temp = NULL;
    char *msg = NULL;
    char country[256] = { 0 };
    char province[256] = { 0 };
    char city[256] = { 0 };
    char isp_gbk[512] = { 0 };    
    char *isp_utf8;
    const char *rule_id;
    int rv;
    const char *host;

    if (actionset ? (actionset->severity > msr->txcfg->attacklog_level ? 1 : 0) : 0) {
        return;
    }

    attname = "";
    attdomain = "";
    action_id = 0; 
    severity_id = 0;
    rule_id = "0";
    cliip = msr->remote_addr;
    cliport = msr->remote_port;
    serip = msr->local_addr;
    serport = msr->local_port;
    method = msr->request_method;
    clibrowser = ap_get_client_browser(msr->mp, msr->r);
    clios = ap_get_client_os(msr->mp, msr->r);  
    host = apr_table_get(msr->r->headers_in, "Host");
    url = apr_pstrcat(msr->mp, msr->hostname, msr->r->uri, msr->r->args ? "?" : "", 
                    msr->r->args, NULL);
    protocol = msr->request_protocol;
    if (protocol && !strcmp(protocol, "HTTP/0.9")) {
        url = "/";
        method = "GET";
        host = "";
    }
    
    if (actionset) {
        action_id = actionset->intercept_action;
        severity_id = actionset->severity;
        if (severity_id < 0 || severity_id > 7) {
            return;
        }
        
        /* 获取攻击名称 */
        tarr = apr_table_elts(actionset->actions);
        telts = (const apr_table_entry_t*)tarr->elts;
        for (i = 0; i < tarr->nelts; i++) {
            action = (msre_action *)telts[i].val;
            if (strcmp("tag", action->metadata->name) != 0) {
                continue;
            }
            if ((attname = action->param) == NULL) {
                return ;
            }
        }

        /* 获取攻击域 */           
        attdomain = get_attack_domain(var, method);
        if ((msg = (char *)actionset->msg) == NULL) {
            return;
        }
        if ((rule_id = actionset->id) == NULL) {
            return;
        }
    }

    /* 地理信息提取 */
    ap_ip_get_country(g_ip_location, cliip, country, 256);
    ap_ip_get_province(g_ip_location, cliip, province, 256);
    ap_ip_get_city(g_ip_location, cliip, city, 256);
    ap_ip_get_isp(g_ip_location, cliip, isp_gbk, 512);
    isp_utf8 = ap_convert_all_to_utf8(msr->mp, isp_gbk, "GB2312");   
    if (!isp_utf8 || (isp_utf8 && !strcmp(isp_utf8, ""))) {
        /* 未知isp */
        isp_utf8 = "\xE6\x9C\xAA\xE7\x9F\xA5";
    }
  
    /* 数据库SQL语句 */
    if (!msr->black_list_flag) {          /* 规则攻击日志 */
        sql_statement = apr_psprintf(msr->mp, INSERT_ATTACKLOG_TABLE_SQL, 
            (apr_int64_t)apr_time_sec(apr_time_now()),
            cliip ? dbd_escape(ap_logdb_driver, msr->mp, cliip, ap_logdb_handle) : "", 
            cliport, 
            serip ? dbd_escape(ap_logdb_driver, msr->mp, serip, ap_logdb_handle) : "", 
            serport, 
            apr_socket_get_offline_mode() ?  actions[5] : (actions[action_id] ? actions[action_id] : ""),
            severities[severity_id] ? severities[severity_id] : "", 
            method ? dbd_escape(ap_logdb_driver, msr->mp, method, ap_logdb_handle) : "", 
            attname ? dbd_escape(ap_logdb_driver, msr->mp, attname, ap_logdb_handle) : "", 
            attdomain ? dbd_escape(ap_logdb_driver, msr->mp, attdomain, ap_logdb_handle) : "", 
            protocol ? dbd_escape(ap_logdb_driver, msr->mp, protocol, ap_logdb_handle) :"", 
            msg ? dbd_escape(ap_logdb_driver, msr->mp, msg, ap_logdb_handle) : "",
            url ? dbd_escape(ap_logdb_driver, msr->mp, url, ap_logdb_handle) : "",
            clios ? dbd_escape(ap_logdb_driver, msr->mp, clios, ap_logdb_handle) : "",
            clibrowser ? dbd_escape(ap_logdb_driver, msr->mp, clibrowser, ap_logdb_handle) : "",
            dbd_escape(ap_logdb_driver, msr->mp, country, ap_logdb_handle),
            dbd_escape(ap_logdb_driver, msr->mp, province, ap_logdb_handle),
            dbd_escape(ap_logdb_driver, msr->mp, city, ap_logdb_handle),
            isp_utf8,
            rule_id,
            host ? dbd_escape(ap_logdb_driver, msr->mp, host, ap_logdb_handle) : (msr->r->hostname ? msr->r->hostname : "")
            );

        /* 用于攻击日志的实时监控 */
        sql_statement_temp = apr_psprintf(msr->mp, INSERT_ATTACKLOG_TABLE_SQL_TEMP, 
            (apr_int64_t)apr_time_sec(apr_time_now()),
            cliip ? dbd_escape(ap_logdb_driver, msr->mp, cliip, ap_logdb_handle) : "", 
            attname ? dbd_escape(ap_logdb_driver, msr->mp, attname, ap_logdb_handle) : "", 
            dbd_escape(ap_logdb_driver, msr->mp, country, ap_logdb_handle),
            dbd_escape(ap_logdb_driver, msr->mp, province, ap_logdb_handle),
            dbd_escape(ap_logdb_driver, msr->mp, city, ap_logdb_handle),
            isp_utf8
            );
    } else {                             /* 黑名单攻击日志 */
        if (msr->black_list_log) {
            msg = apr_psprintf(msr->mp, "%s%d", "attack times:", msr->black_list_hitcount);
            sql_statement = apr_psprintf(msr->mp, INSERT_ATTACKLOG_TABLE_SQL, 
                (apr_int64_t)apr_time_sec(apr_time_now()),
                cliip ? dbd_escape(ap_logdb_driver, msr->mp, cliip, ap_logdb_handle) : "", 
                cliport, 
                serip ? dbd_escape(ap_logdb_driver, msr->mp, serip, ap_logdb_handle) : "", 
                serport, 
                apr_socket_get_offline_mode() ?  actions[5] : (actions[1] ? actions[1] : ""),
                severities[0] ? severities[0] : "",   
                method ? dbd_escape(ap_logdb_driver, msr->mp, method, ap_logdb_handle) : "", 
                get_attack_string(msr), 
                dbd_escape(ap_logdb_driver, msr->mp, g_attack_domain[7], ap_logdb_handle),
                protocol ? dbd_escape(ap_logdb_driver, msr->mp, protocol, ap_logdb_handle) : "", 
                msg ? msg : "",
                url ? dbd_escape(ap_logdb_driver, msr->mp, url, ap_logdb_handle) : "",
                clios ? dbd_escape(ap_logdb_driver, msr->mp, clios, ap_logdb_handle) : "",
                clibrowser ? dbd_escape(ap_logdb_driver, msr->mp, clibrowser, ap_logdb_handle) : "",
                dbd_escape(ap_logdb_driver, msr->mp, country, ap_logdb_handle),
                dbd_escape(ap_logdb_driver, msr->mp, province, ap_logdb_handle),
                dbd_escape(ap_logdb_driver, msr->mp, city, ap_logdb_handle),
                isp_utf8,
                rule_id,
                host ? dbd_escape(ap_logdb_driver, msr->mp, host, ap_logdb_handle) : (msr->r->hostname ? msr->r->hostname : "")
                );
            
            /* 用于攻击日志的实时监控 */
            sql_statement_temp = apr_psprintf(msr->mp, INSERT_ATTACKLOG_TABLE_SQL_TEMP, 
                (apr_int64_t)apr_time_sec(apr_time_now()),
                cliip ? dbd_escape(ap_logdb_driver, msr->mp, cliip, ap_logdb_handle) : "", 
                get_attack_string(msr), 
                dbd_escape(ap_logdb_driver, msr->mp, country, ap_logdb_handle),
                dbd_escape(ap_logdb_driver, msr->mp, province, ap_logdb_handle),
                dbd_escape(ap_logdb_driver, msr->mp, city, ap_logdb_handle),   
                isp_utf8
                );
        } 
    }

    if (sql_statement) {
        *(const char **)apr_array_push(msr->attacklogs) = sql_statement;
    }

    if (sql_statement_temp) {
        rv = log_send(sql_statement_temp, 0);
        if (rv < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "send temp attack log to log server failed.");
        }
    }    
}
#endif

/**
 * Log an alert message to the log, adding the rule metadata at the end.
 */
void msc_alert(modsec_rec *msr, int level, msre_actionset *actionset, const char *action_message,
        const char *rule_message)
{
    const char *message = msc_alert_message(msr, actionset, action_message, rule_message);

    msr_log(msr, level, "%s", message);
}

/**
 * Creates and initialises a ModSecurity engine instance.
 */
msc_engine *modsecurity_create(apr_pool_t *mp, int processing_mode) 
{
    msc_engine *msce = NULL;

    msce = apr_pcalloc(mp, sizeof(msc_engine));
    if (msce == NULL) {
        return NULL;
    }

    msce->mp = mp;
    msce->processing_mode = processing_mode;

    msce->msre = msre_engine_create(msce->mp);
    if (msce->msre == NULL) {
        return NULL;
    }
    
    msre_engine_register_default_variables(msce->msre);
    msre_engine_register_default_operators(msce->msre);
    msre_engine_register_default_tfns(msce->msre);
    msre_engine_register_default_actions(msce->msre);
    // TODO: msre_engine_register_default_reqbody_processors(msce->msre);

    return msce;
}

/**
 * Initialise the modsecurity engine. This function must be invoked
 * after configuration processing is complete as Apache needs to know the
 * username it is running as.
 */
int modsecurity_init(msc_engine *msce, apr_pool_t *mp) 
{
    apr_status_t rc;
    
    /* auditlog互斥锁 */
    rc = apr_global_mutex_create(&msce->auditlog_lock, NULL, APR_LOCK_DEFAULT, mp);
    if (rc != APR_SUCCESS) {
        return -1;
    }

#ifdef __SET_MUTEX_PERMS
#if AP_SERVER_MAJORVERSION_NUMBER > 1 && AP_SERVER_MINORVERSION_NUMBER > 2
    rc = ap_unixd_set_global_mutex_perms(msce->auditlog_lock);
#else
    rc = unixd_set_global_mutex_perms(msce->auditlog_lock);
#endif
    if (rc != APR_SUCCESS) {
        return -1;
    }
#endif /* SET_MUTEX_PERMS */

    /* geo互斥锁 */
    rc = apr_global_mutex_create(&msce->geo_lock, NULL, APR_LOCK_DEFAULT, mp);
    if (rc != APR_SUCCESS) {
        return -1;
    }

#ifdef __SET_MUTEX_PERMS
#if AP_SERVER_MAJORVERSION_NUMBER > 1 && AP_SERVER_MINORVERSION_NUMBER > 2
    rc = ap_unixd_set_global_mutex_perms(msce->geo_lock);
#else
    rc = unixd_set_global_mutex_perms(msce->geo_lock);
#endif
    if (rc != APR_SUCCESS) {
        return -1;
    }
#endif /* SET_MUTEX_PERMS */

#ifdef DEBUG_FILELOG
    const char *file_name = ap_server_root_relative(mp, "logs/audit_log");
    rc = apr_file_open(&auditlog_fd, file_name, 
            APR_WRITE | APR_APPEND | APR_CREATE | APR_BINARY, CREATEMODE, mp);
    if (rc != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Create or open audit failed.");
        return -1;
    }
#endif

    return 1;
}

/**
 * Performs per-child (new process) initialisation.
 */
void modsecurity_child_init(msc_engine *msce) 
{
    /* Need to call this once per process before any other XML calls. */
    xmlInitParser();

    if (msce->auditlog_lock != NULL) {
        apr_status_t rc = apr_global_mutex_child_init(&msce->auditlog_lock, NULL, msce->mp);
        if (rc != APR_SUCCESS) {
            /* 原本就无内容 */
        }
    }

    if (msce->geo_lock != NULL) {
        apr_status_t rc = apr_global_mutex_child_init(&msce->geo_lock, NULL, msce->mp);
        if (rc != APR_SUCCESS) {
            /* 原本就无内容 */
        }
    }

#ifdef DEBUG_DBLOG
    if (ap_logdb_mutex != NULL) {
        apr_status_t rc = apr_global_mutex_child_init(&ap_logdb_mutex, NULL, msce->mp);
        if (rc != APR_SUCCESS) {
            /* 原本就无内容 */
        }
    }
#endif
}

/**
 * Releases resources held by engine instance.
 */
void modsecurity_shutdown(msc_engine *msce) 
{
    if (msce == NULL) {
        return;
    }
}

/**
 *
 */
static void modsecurity_persist_data(modsec_rec *msr)
{
    const apr_array_header_t *arr;
    apr_table_entry_t *te;
    apr_time_t time_before, time_after;
    int i;

    time_before = apr_time_now();

    /* Collections, store & remove stale. */
    arr = apr_table_elts(msr->collections);
    te = (apr_table_entry_t *)arr->elts;
    for (i = 0; i < arr->nelts; i++) {
        apr_table_t *col = (apr_table_t *)te[i].val;

        /* Only store those collections that changed. */
        if (apr_table_get(msr->collections_dirty, te[i].key)) {
            collection_store(msr, col);
        }
    }

    time_after = apr_time_now();
    
    msr->time_storage_write += time_after - time_before;
    
    if (msr->txcfg->debuglog_level >= 4) {
        msr_log(msr, 4, "Recording persistent data took %" APR_TIME_T_FMT " microseconds.", msr->time_gc);
    }   
    
    /* Remove stale collections. */
    if (rand() < RAND_MAX / 100) {
        arr = apr_table_elts(msr->collections);
        te = (apr_table_entry_t *)arr->elts;
        for (i = 0; i < arr->nelts; i++) {
            collections_remove_stale(msr, te[i].key);
        }
        
        msr->time_gc = apr_time_now() - time_after;
        
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Garbage collection took %" APR_TIME_T_FMT " microseconds.", msr->time_gc);
        }   
    }
}

/**
 *
 */
static apr_status_t modsecurity_tx_cleanup(void *data) 
{
    modsec_rec *msr = (modsec_rec *)data;
    char *my_error_msg = NULL;
    
    if (msr == NULL) {
        return APR_SUCCESS;    
    }

    /* Multipart processor cleanup. */
    if (msr->mpd != NULL) {
        multipart_cleanup(msr);
    }

    /* XML processor cleanup. */
    if (msr->xml != NULL) {
        xml_cleanup(msr);
    }

    // TODO: Why do we ignore return code here?
    modsecurity_request_body_clear(msr, &my_error_msg);
    if (my_error_msg != NULL) {
        msr_log(msr, 1, "%s", my_error_msg);
    }
    
    if (msr->stream_input_data) {
        free(msr->stream_input_data);
        msr->stream_input_data = NULL;
    }
    
    if (msr->stream_output_data) {
        free(msr->stream_output_data);
        msr->stream_output_data = NULL;
    }

    if (msr->msc_reqbody_chunk_current && msr->msc_reqbody_chunk_current->data) {
        free(msr->msc_reqbody_chunk_current->data);
        msr->msc_reqbody_chunk_current->data = NULL;
    }

    return APR_SUCCESS;
}

static int  parse_request_cookie(modsec_rec *msr)
{
    const apr_array_header_t *arr;
    apr_table_entry_t *te;
    apr_table_t *cookies_tb;
    char cookies_key[20];
    char *key;
    int cookies_count;
    int i, j;

    arr = apr_table_elts(msr->request_headers);
    te = (apr_table_entry_t *)arr->elts;
    for (i = 0, j = 0; i < arr->nelts; i++) {
        if (strcasecmp(te[i].key, "Cookie") == 0) {
            cookies_tb = apr_table_make(msr->mp, 8);
            if (cookies_tb == NULL) {
                return -1;
            }
            if (msr->txcfg->cookie_format == COOKIES_V0) {
                cookies_count = parse_cookies_v0(msr, te[i].val, cookies_tb);
            } else {
                cookies_count = parse_cookies_v1(msr, te[i].val, cookies_tb);
            }
            if (cookies_count <= 0) {
                continue;
            }
            snprintf(cookies_key, 20, "cookies%d", ++j);
            key = apr_pstrdup(msr->mp, cookies_key);
            apr_table_setn(msr->request_cookies, key, (void *)cookies_tb);
        }
    }

    return 0;
}

/**
 *
 */
apr_status_t modsecurity_tx_init(modsec_rec *msr) 
{
    const char *s = NULL;

    /* Register TX cleanup */
    apr_pool_cleanup_register(msr->mp, msr, modsecurity_tx_cleanup, apr_pool_cleanup_null);

    /* Initialise C-L */
    msr->request_content_length = -1;
    s = apr_table_get(msr->request_headers, "Content-Length");
    if (s != NULL) {
        msr->request_content_length = strtol(s, NULL, 10);
    }

    /* Figure out whether this request has a body */
    msr->reqbody_chunked = 0;
    msr->reqbody_should_exist = 0;
    if (msr->request_content_length == -1) {
        /* There's no C-L, but is chunked encoding used? */
        char *transfer_encoding = (char *)apr_table_get(msr->request_headers, "Transfer-Encoding");
        if ((transfer_encoding != NULL) && (strstr(transfer_encoding, "chunked") != NULL)) {
            msr->reqbody_should_exist = 1;
            msr->reqbody_chunked = 1;
        }
    } else {
        /* C-L found */
        msr->reqbody_should_exist = 1;
    }

    /* Initialise C-T */
    msr->request_content_type = NULL;
    s = apr_table_get(msr->request_headers, "Content-Type");
    if (s != NULL) {
        msr->request_content_type = s;
    }
    
    /* Decide what to do with the request body. */
    if ((msr->request_content_type != NULL) 
            && (strncasecmp(msr->request_content_type, "application/x-www-form-urlencoded", 33) == 0)) {
        /* Always place POST requests with "application/x-www-form-urlencoded" payloads in memory. */
        msr->msc_reqbody_storage = MSC_REQBODY_MEMORY;
        msr->msc_reqbody_spilltodisk = 1;
        msr->msc_reqbody_processor = "URLENCODED";
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "msc reqbody processor change to URLENCODED");
    } else {
        /* In all other cases, try using the memory first but switch over to disk for larger bodies. */
        msr->msc_reqbody_storage = MSC_REQBODY_MEMORY;
        msr->msc_reqbody_spilltodisk = 1;

        /* If the C-L is known and there's more data than our limit go to disk straight away. */
        if ((msr->request_content_length != -1) 
             && (msr->request_content_length > msr->txcfg->reqbody_inmemory_limit)) {
            msr->msc_reqbody_storage = MSC_REQBODY_DISK;
        }

        if (msr->request_content_type != NULL) {
            if (strncasecmp(msr->request_content_type, "multipart/form-data", 19) == 0) {
                msr->msc_reqbody_processor = "MULTIPART";
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "msc reqbody processor change to MULTIPART");
            } else if (strncasecmp(msr->request_content_type, "text/xml", 8) == 0) {
                msr->msc_reqbody_processor = "XML";
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "msc reqbody processor change to XML");
            }
        }
    }

    /* Check if we are forcing buffering, then use memory only. */
    if (msr->txcfg->reqbody_buffering != REQUEST_BODY_FORCEBUF_OFF) {
        msr->msc_reqbody_storage = MSC_REQBODY_MEMORY;
        msr->msc_reqbody_spilltodisk = 0;
    }

    /* Initialise arguments */
    msr->arguments = apr_table_make(msr->mp, 32);
    if (msr->arguments == NULL) {
        return -1;
    }
    if (msr->query_string != NULL) {
        int invalid_count = 0;
        /* 查询串参数解析 */               
        if (parse_arguments(msr, msr->query_string, strlen(msr->query_string),
            msr->txcfg->argument_separator, "QUERY_STRING", msr->arguments, &invalid_count) < 0) {
            msr_log(msr, 1, "Initialisation: Error occurred while parsing QUERY_STRING arguments.");
            return -1;
        }

        if (invalid_count) {
            msr->urlencoded_error = 1;
        }
    }
     
    if (msr->request_uri != NULL) {  
        /* request_uri解析 */       
        msr->request_uri = (const char *)parse_uri(msr->mp, msr->request_uri);
        if (msr->request_uri == NULL) {
            msr_log(msr, 1, "Initialisation: Error occurred while parsing REQUEST_URI arguments.");
            return -1;
        }
    } 

    if (msr->request_line != NULL) {
        /* request_line解析 */
        msr->request_line = (const char *)parse_request_line(msr->mp, msr->request_line);
        if (msr->request_line == NULL) {
            msr_log(msr, 1, "Initialisation: Error occurred while parsing REQUEST_LINE arguments.");
            return -1;
        }
    }

    msr->arguments_to_sanitize = apr_table_make(msr->mp, 16);
    if (msr->arguments_to_sanitize == NULL) {
        return -1;
    }
    
    msr->request_headers_to_sanitize = apr_table_make(msr->mp, 16);
    if (msr->request_headers_to_sanitize == NULL) {
        return -1;
    }
    
    msr->response_headers_to_sanitize = apr_table_make(msr->mp, 16);
    if (msr->response_headers_to_sanitize == NULL) {
        return -1;
    }
    
    msr->pattern_to_sanitize = apr_table_make(msr->mp, 32);
    if (msr->pattern_to_sanitize == NULL) {
        return -1;
    }

    /* Initialise cookies */
    msr->request_cookies = apr_table_make(msr->mp, 5);
    if (msr->request_cookies == NULL) {
        return -1;
    }

    /* Initialize matched vars */
    msr->matched_vars = apr_table_make(msr->mp, 8);
    if (msr->matched_vars == NULL) {
        return -1;
    }
    apr_table_clear(msr->matched_vars);

    /* Locate the cookie headers and parse them */
    /* 解析请求cookie */
    if (parse_request_cookie(msr) == -1) {
        return -1;
    }

    /* Collections. */
    msr->tx_vars = apr_table_make(msr->mp, 32);
    if (msr->tx_vars == NULL) {
        return -1;
    }

    msr->geo_vars = apr_table_make(msr->mp, 8);
    if (msr->geo_vars == NULL) {
        return -1;
    }

    msr->collections_original = apr_table_make(msr->mp, 8);
    if (msr->collections_original == NULL) {
        return -1;
    }
    msr->collections = apr_table_make(msr->mp, 8);
    if (msr->collections == NULL) {
        return -1;
    }
    msr->collections_dirty = apr_table_make(msr->mp, 8);
    if (msr->collections_dirty == NULL) {
        return -1;
    }

    /* Other */
    msr->tcache = NULL;
    msr->tcache_items = 0;
    
    /* 初始化变量缓存内存池 */
#ifdef VAR_FETCH_CACHE
    if (apr_pool_create(&msr->var_fetch_cache_mptmp, msr->mp) != APR_SUCCESS) {
        return -1;
    }
    apr_pool_tag(msr->var_fetch_cache_mptmp, "varfetchcache");
#endif

    msr->matched_rules = apr_array_make(msr->mp, 16, sizeof(void *));
    if (msr->matched_rules == NULL) {
        return -1;
    }

    msr->matched_var = (msc_string *)apr_pcalloc(msr->mp, sizeof(msc_string));
    if (msr->matched_var == NULL) {
        return -1;
    }

    msr->highest_severity = 255; /* high, invalid value */

    msr->removed_rules = apr_array_make(msr->mp, 16, sizeof(char *));
    if (msr->removed_rules == NULL) {
        return -1;
    }

    msr->removed_rules_tag = apr_array_make(msr->mp, 16, sizeof(char *));
    if (msr->removed_rules_tag == NULL) {
        return -1;
    }

    return 1;
}

/**
 *
 */
#if 0
static int is_response_status_relevant(modsec_rec *msr, int status) 
{
    char *my_error_msg = NULL;
    apr_status_t rc;
    char buf[32];

    /* ENH: Setting is_relevant here will cause an audit even if noauditlog
     * was set for the last rule that matched.  Is this what we want?
     */
    if ((msr->txcfg->auditlog_relevant_regex == NULL) 
            ||(msr->txcfg->auditlog_relevant_regex == NOT_SET_P)) {
        return 0;
    }

    apr_snprintf(buf, sizeof(buf), "%d", status);

    rc = msc_regexec(msr->txcfg->auditlog_relevant_regex, buf, strlen(buf), &my_error_msg);
    if (rc >= 0) {
        return 1;
    }
    if (rc == PCRE_ERROR_NOMATCH) {
        return 0;
    }

    msr_log(msr, 1, "Regex processing failed (rc %d): %s", rc, my_error_msg);
    
    return 0;
}
#endif
/**
 *
 */
static apr_status_t modsecurity_process_phase_request_headers(modsec_rec *msr) 
{
    apr_time_t time_before;
    apr_status_t rc = 0;
    
    if (msr->txcfg->debuglog_level >= 4) {
        msr_log(msr, 4, "Starting phase REQUEST_HEADERS.");
    }
    
    time_before = apr_time_now();

    if (msr->txcfg->ruleset != NULL) {
        rc = msre_ruleset_process_phase(msr->txcfg->ruleset, msr);
    }
    
    msr->time_phase1 = apr_time_now() - time_before;

    return rc;
}

/**
 *
 */
static apr_status_t modsecurity_process_phase_request_body(modsec_rec *msr) 
{
    apr_time_t time_before;
    apr_status_t rc = 0;
    
    if ((msr->allow_scope == ACTION_ALLOW_REQUEST) || (msr->allow_scope == ACTION_ALLOW)) {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Skipping phase REQUEST_BODY (allow used).");
        }       
        return 0;
    } else {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Starting phase REQUEST_BODY.");
        }
    }
    
    time_before = apr_time_now();

    if (msr->txcfg->ruleset != NULL) {
        rc = msre_ruleset_process_phase(msr->txcfg->ruleset, msr);
    }
    
    msr->time_phase2 = apr_time_now() - time_before;

    return rc;
}

/**
 *
 */
static apr_status_t modsecurity_process_phase_response_headers(modsec_rec *msr) 
{
    apr_time_t time_before;
    apr_status_t rc = 0;
    
    if (msr->allow_scope == ACTION_ALLOW) {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Skipping phase RESPONSE_HEADERS (allow used).");
        }
        return 0;
    } else {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Starting phase RESPONSE_HEADERS.");
        }
    }
    
    time_before = apr_time_now();

    if (msr->txcfg->ruleset != NULL) {
        rc = msre_ruleset_process_phase(msr->txcfg->ruleset, msr);
    }
    
    msr->time_phase3 = apr_time_now() - time_before;

    return rc;
}

/**
 *
 */
static apr_status_t modsecurity_process_phase_response_body(modsec_rec *msr) 
{
    apr_time_t time_before;
    apr_status_t rc = 0;
    
    if (msr->allow_scope == ACTION_ALLOW) {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Skipping phase RESPONSE_BODY (allow used).");
        }
        return 0;
    } else {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Starting phase RESPONSE_BODY.");
        }
    }
    
    time_before = apr_time_now();

    if (msr->txcfg->ruleset != NULL) {
        rc = msre_ruleset_process_phase(msr->txcfg->ruleset, msr);
    }
    
    msr->time_phase4 = apr_time_now() - time_before;

    return rc;
}

/**
 *
 */
static apr_status_t modsecurity_process_phase_logging(modsec_rec *msr) 
{
    apr_time_t time_before, time_after;
    
    if (msr->txcfg->debuglog_level >= 4) {
        msr_log(msr, 4, "Starting phase LOGGING.");
    }
    
    time_before = apr_time_now();

    if (msr->txcfg->ruleset != NULL) {
        msre_ruleset_process_phase(msr->txcfg->ruleset, msr);
    }
    
    modsecurity_persist_data(msr);
    
    time_after = apr_time_now();
    msr->time_phase5 = time_after - time_before;

    /* Is this request relevant for logging purposes? */
#if 0
    if (msr->is_relevant == 0) {
        /* Check the status */
        msr->is_relevant += is_response_status_relevant(msr, msr->r->status);

        /* If we processed two requests and statuses are different then check the other status too. */
        if (msr->r_early->status != msr->r->status) {
            msr->is_relevant += is_response_status_relevant(msr, msr->r_early->status);
        }

    }
#endif

    /* Figure out if we want to keep the files (if there are any, of course). */
    if ((msr->txcfg->upload_keep_files == KEEP_FILES_ON) || 
        ((msr->txcfg->upload_keep_files == KEEP_FILES_RELEVANT_ONLY) && (msr->is_relevant))) {
        msr->upload_remove_files = 0;
    } else {
        msr->upload_remove_files = 1;
    }

    /* Are we configured for audit logging? */
    switch(msr->txcfg->attacklog_flag) {
    case AUDITLOG_OFF :
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Audit log: Not configured to run for this request.");
        }
        return DECLINED;
        break;
/* 裁减 */
#if 0
    case AUDITLOG_RELEVANT :
        if (msr->is_relevant == 0) {
            if (msr->txcfg->debuglog_level >= 4) {
                msr_log(msr, 4, "Audit log: Ignoring a non-relevant request.");
            }            
            return DECLINED;
        }
        break;
#endif
    case AUDITLOG_ON :
        /* All right, do nothing */
        break;

    default :
        msr_log(msr, 1, "Internal error: Could not determine if auditing is needed, so forcing auditing.");
        break;
    }

    /* Invoke the Audit logger */
    if (msr->txcfg->debuglog_level >= 4) {
        msr_log(msr, 4, "Audit log: Logging this transaction.");
    }

    /* sec_attack_logger(msr); 该函数移至外面 */
    
    msr->time_logging = apr_time_now() - time_after;    

    return 0;
}

/**
 * Processes one transaction phase. The phase number does not
 * need to be explicitly provided since it's already available
 * in the modsec_rec structure.
 */
apr_status_t modsecurity_process_phase(modsec_rec *msr, unsigned int phase) 
{   
    /* Check if we should run. */
    if ((msr->was_intercepted) && (phase != PHASE_LOGGING)) {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Skipping phase %d as request was already intercepted.", phase);
        }
        return 0;
    }

    /* Do not process the same phase twice. */
    if (msr->phase >= phase) {
        if (msr->txcfg->debuglog_level >= 4) {
            msr_log(msr, 4, "Skipping phase %d because it was previously run (at %d now).",
                phase, msr->phase);
        }
        return 0;
    }

    msr->phase = phase;
    /* Clear out the transformation cache at the start of each phase */
    if (msr->txcfg->cache_trans == MODSEC_CACHE_ENABLED) {
        if (msr->tcache) {
            apr_hash_index_t *hi;
            void *dummy;
            apr_table_t *tab;
            const void *key;
            apr_ssize_t klen;
            
#ifdef CACHE_DEBUG
            apr_pool_t *mp = msr->msc_rule_mptmp;
            const apr_array_header_t *ctarr;
            const apr_table_entry_t *ctelts;
            msre_cache_rec *rec;
            int cn = 0;
            int ri;
#else
            apr_pool_t *mp = msr->mp;
#endif

            for (hi = apr_hash_first(mp, msr->tcache); hi; hi = apr_hash_next(hi)) {
                apr_hash_this(hi, &key, &klen, &dummy);
                tab = (apr_table_t *)dummy;
                if (tab == NULL) {
                    continue;
                }

#ifdef CACHE_DEBUG
                /* Dump the cache out as we clear */
                ctarr = apr_table_elts(tab);
                ctelts = (const apr_table_entry_t*)ctarr->elts;
                for (ri = 0; ri < ctarr->nelts; ri++) {
                    cn++;
                    rec = (msre_cache_rec *)ctelts[ri].val;
                    if (rec->changed) {
                        if (msr->txcfg->debuglog_level >= 9) {
                            msr_log(msr, 9, "CACHE: %5d) hits=%d key=%pp %x;%s=\"%s\" (%pp - %pp)",
                                cn, rec->hits, key, rec->num, rec->path, 
                                log_escape_nq_ex(mp, rec->val, rec->val_len), rec->val, 
                                rec->val + rec->val_len);
                        }
                    } else {
                        if (msr->txcfg->debuglog_level >= 9) {
                            msr_log(msr, 9, "CACHE: %5d) hits=%d key=%pp %x;%s=<no change>",
                                cn, rec->hits, key, rec->num, rec->path);
                        }
                    }
                }
#endif
                apr_table_clear(tab);
                apr_hash_set(msr->tcache, key, klen, NULL);
            }

            if (msr->txcfg->debuglog_level >= 9) {
                msr_log(msr, 9, "Cleared transformation cache for phase %d", msr->phase);
            }
        }

        msr->tcache_items = 0;
        msr->tcache = apr_hash_make(msr->mp);
        if (msr->tcache == NULL) {
            return -1;
        }
    }

    /* 清除变量缓存 */
#ifdef VAR_FETCH_CACHE
    apr_pool_clear(msr->var_fetch_cache_mptmp);
    msr->var_fetch_cache = apr_hash_make(msr->var_fetch_cache_mptmp);
    if (msr->var_fetch_cache == NULL) {
        return -1;
    }
#endif

    switch(phase) {
    case 1 :
        return modsecurity_process_phase_request_headers(msr);
    case 2 :
        return modsecurity_process_phase_request_body(msr);
    case 3 :
        return modsecurity_process_phase_response_headers(msr);
    case 4 :
        return modsecurity_process_phase_response_body(msr);
    case 5 :
        return modsecurity_process_phase_logging(msr);
    default :
        msr_log(msr, 1, "Invalid processing phase: %d", msr->phase);
        break;
    }

    return -1;
}


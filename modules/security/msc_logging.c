/*
* ModSecurity for Apache 2.x, http://www.modsecurity.org/
* Copyright (c) 2004-2011 Trustwave Holdings, Inc. (http://www.trustwave.com/)
*
* You may not use this file except in compliance with
* the License. You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* If any of the files related to licensing are missing or if you have any
* other questions related to licensing please contact Trustwave Holdings, Inc.
* directly using the email address security@modsecurity.org.
*/
#include <GeoIP.h>
#include <GeoIPCity.h>
#include "msc_logging.h"
#include "apr_strings.h"

#ifdef DEBUG_DBLOG
#include "apr_dbd.h"
#endif

#define INSERT_ACCESSLOG_TABLE_SQL "insert into access_log_table values(" \
        "%" APR_INT64_T_FMT ", '%s', %u, '%s', %u, '%s', '%s', '%s', %d, '%s', '%s'," \
        "'%s', '%s', '%d', '%s', '%s', %u, '%s', %d, %d, %u, %d, %d," \
        " %" APR_INT64_T_FMT ", %" APR_INT64_T_FMT ", %" APR_INT64_T_FMT ", %" APR_INT64_T_FMT \
        ", '%s', '%s', '%s', '%s', '%s')"

#ifdef DEBUG_FILELOG
static int sec_auditlog_write(modsec_rec *msr, const char *data, unsigned int len) 
{
    apr_size_t nbytes_written, nbytes = len;
    apr_status_t rc;

    /* Do nothing if there's no data. */
    if (data == NULL) {
        return -1;
    }

    /* Do not write if we do not have a file descriptor. */
    if (auditlog_fd == NULL) {
        return -1;
    }

    /* Write data to file. */
    rc = apr_file_write_full(auditlog_fd, data, nbytes, &nbytes_written);
    if (rc != APR_SUCCESS) {
        msr_log(msr, 1, "Attack log: Failed writing (requested %" APR_SIZE_T_FMT
            " bytes, written %" APR_SIZE_T_FMT ")", nbytes, nbytes_written);
        return -1;
    }

    return 1;
}

/* audit_log文件日志接口 */
static void sec_file_sender(modsec_rec *msr)
{
    int i;
    char *text;
    
    /* Messages */
    text = NULL;
    for(i = 0; i < msr->alerts->nelts; i++) {
        text = apr_psprintf(msr->mp, "Message: %s\n", ((char **)msr->alerts->elts)[i]);
        sec_auditlog_write(msr, text, strlen(text));
    }
}
#endif

/* 发送邮件接口 */
static void sec_email_sender(modsec_rec *msr)
{
}

/* 写入数据库接口 */
#ifdef DEBUG_DBLOG
static void sec_remotedb_sender(modsec_rec *msr)
{
    int i;
    int rv;
    char *text = "";
    int lognums;

    lognums = msr->attacklogs->nelts;
    if (lognums == 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "this request without attack log.");
        return;
    }

    /* 攻击日志发送 */
    for(i = 0; i < lognums; i++) {
        //text = apr_pstrcat(msr->mp, text, ((const char **)msr->attacklogs->elts)[i], NULL);
        text = ((char **)msr->attacklogs->elts)[i];

        rv = log_send(text, 1);
        if (rv < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "send attack log to log server failed.");
        }
    } 
}
#endif

/**
 * 攻击日志处理
 */
void attack_log_process(modsec_rec *msr)
{
    /* 邮件发送 */
    sec_email_sender(msr);

    /* 文件日志 */
#ifdef DEBUG_FILELOG
    apr_global_mutex_lock(msr->modsecurity->auditlog_lock);
    sec_file_sender(msr);
    apr_global_mutex_unlock(msr->modsecurity->auditlog_lock);
#endif

    /* 发送远程数据库 */
#ifdef DEBUG_DBLOG
    sec_remotedb_sender(msr);
#endif
}

/**
 * 访问日志处理
 */
void access_log_process(modsec_rec *msr)
{
    int rv;
    apr_time_t request_time, response_time, proxy_request_time, proxy_response_time;
    const char *cliip;
    unsigned int cliport;
    const char *serip;
    unsigned int serport;
    const char *url;
    const char *method;
    const char *protocol;
    const char *clios;
    const char *clibrowser;
    const char *browserfamily;
    int status;
    char *sql_statement;
    request_rec *r;
    char *plugins;
    int access_method;
    char *search_engine;
    char *keywords;
    apr_size_t request_bytes;
    const char *content_type;
    int out_reqbody_limit;
    int out_reqbody_mem_limit;
    apr_size_t response_bytes;
    int out_resbody_limit;
    int out_resbody_mem_limit;  
    char country[256] = { 0 };
    char province[256] = { 0 };
    char city[256] = { 0 };
    char isp_gbk[512] = { 0 };
    char *isp_utf8;
    const char *host;

    if (msr->txcfg->accesslog_flag != ACCESSLOG_ON) {
        return;
    }

    r = msr->r;
    while (r->next) {
        r = r->next;   
    }

    request_time = r->request_time;
    response_time = r->response_time;
    proxy_request_time = r->proxy_request_time;
    proxy_response_time = r->proxy_response_time;
    cliip = r->connection->remote_ip;
    cliport = r->connection->remote_addr->port;
    serip = r->connection->local_ip;
    serport = r->connection->local_addr->port;
    method = r->method;
    status = r->status;
    host = apr_table_get(r->headers_in, "Host");
    clios = ap_get_client_os(r->pool, r);
    clibrowser = ap_get_client_browser(r->pool, r);
    browserfamily = ap_get_client_browser_family(r->pool, r);
    plugins = ap_get_client_plugin(r->pool, r);
    access_method = ap_get_client_access_type(r->pool, r);
    search_engine = ap_get_client_search_engine(r->pool, r);
    keywords = ap_get_client_keywords(r->pool, r);    
    request_bytes = r->request_bytes;
    content_type = r->content_type;
    out_reqbody_limit = (msr->reqbody_length > msr->txcfg->reqbody_limit) ? 1 : 0;
    out_reqbody_mem_limit = (msr->reqbody_length > msr->txcfg->reqbody_inmemory_limit) ? 1 : 0;
    response_bytes = r->response_bytes;
    out_resbody_limit = (msr->resbody_length > msr->txcfg->of_limit) ? 1 : 0;
    out_resbody_mem_limit = (msr->resbody_length > msr->txcfg->of_inmemory_limit) ? 1 : 0;
    url = apr_pstrcat(msr->mp, r->hostname, r->uri, r->args ? "?" : "", r->args, NULL);
    protocol = r->protocol;
    if (protocol && !strcmp(protocol, "HTTP/0.9")) { 
        url = "/";
        method = "GET";
        content_type = "";
        host = "";
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

    /* 插入数据库sql语句 */
    sql_statement = apr_psprintf(r->pool, INSERT_ACCESSLOG_TABLE_SQL, 
        (apr_int64_t)apr_time_sec(apr_time_now()), 
        cliip ? dbd_escape(ap_logdb_driver, msr->mp, cliip, ap_logdb_handle) : "",
        cliport, 
        serip ? dbd_escape(ap_logdb_driver, msr->mp, serip, ap_logdb_handle) : "",
        serport, 
        method ? dbd_escape(ap_logdb_driver, msr->mp, method, ap_logdb_handle) : "",
        url ? dbd_escape(ap_logdb_driver, r->pool, url, ap_logdb_handle) : "", 
        protocol ? dbd_escape(ap_logdb_driver, msr->mp, protocol, ap_logdb_handle) : "",
        status, 
        clios ? dbd_escape(ap_logdb_driver, msr->mp, clios, ap_logdb_handle) : "",
        clibrowser ? dbd_escape(ap_logdb_driver, msr->mp, clibrowser, ap_logdb_handle) : "",
        browserfamily ? dbd_escape(ap_logdb_driver, msr->mp, browserfamily, ap_logdb_handle) : "",
        plugins ? dbd_escape(ap_logdb_driver, msr->mp, plugins, ap_logdb_handle) : "",
        access_method,
        search_engine ? dbd_escape(ap_logdb_driver, msr->mp, search_engine, ap_logdb_handle) : "",
        keywords ? dbd_escape(ap_logdb_driver, msr->mp, keywords, ap_logdb_handle) : "",
        (unsigned int)request_bytes, 
        content_type ? dbd_escape(ap_logdb_driver, msr->mp, content_type, ap_logdb_handle) : "",
        out_reqbody_limit, out_reqbody_mem_limit, (unsigned int)response_bytes, out_resbody_limit, out_resbody_mem_limit,
        (apr_int64_t)apr_time_as_msec(request_time), 
        (apr_int64_t)apr_time_as_msec(response_time), 
        (apr_int64_t)apr_time_as_msec(proxy_request_time), 
        (apr_int64_t)apr_time_as_msec(proxy_response_time),
        dbd_escape(ap_logdb_driver, msr->mp, country, ap_logdb_handle),
        dbd_escape(ap_logdb_driver, msr->mp, province, ap_logdb_handle),
        dbd_escape(ap_logdb_driver, msr->mp, city, ap_logdb_handle),
        isp_utf8,
        host ? dbd_escape(ap_logdb_driver, msr->mp, host, ap_logdb_handle) : (r->hostname ? r->hostname : "")
        );

    /* 发送日志服务器 */
    rv = log_send(sql_statement, 1);
    if (rv < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "send access log to log server failed.");
        return;
    }

    return;
}


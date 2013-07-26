/*
 * $Id: cli_log.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#include "cparser_priv.h"
#include "cparser_token.h"
#include "global_root.h"
#include "cparser_show_tree.h"
#include "cparser_tree.h"
#include "cparser.h"
#include "cli_common.h"
#include "apr_dbd.h"
#include "httpd.h"
#include "apr_time.h"
#include "pe_cli.h"

#define ATTACKLOG_TABLE         "attack_log_table" 
#define ACCESSLOG_TABLE         "access_log_table" 
#define FORMATE_ATTACK_STRING   "%-24s  %-15s  %-15s  %-8s  %-10s  %-30s  %-8s  %s\n"
#define FORMATE_ATTACK_STRING1  "%-24s  %-15s  %-15s  %-8s  %-10s  %-30s  %-s  %s\n"
#define FORMATE_ACCESS_STRING   "%-24s  %-15s  %-15s  %-8s  %-10s  %-6s  %s\n"
#define FORMATE_ADMINLOG_STRING "%-24s  %-12s  %-15s  %-12s  %-12s  %s\n"

static apr_pool_t *patcklog;
static apr_pool_t *pacslog;
static apr_pool_t *padminlog;

static const char * const actions[] = {"", "DROP", "DENY", "PASS", NULL};
static const char * const method[] = {"", "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", \
                                        "TRACE", NULL};

AP_DECLARE(int) show_attacklog_init(apr_pool_t *p)
{   
    int rv;
    
    /* 分配子池 */
    rv = apr_pool_create(&patcklog, p);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "ATTACK_LOG:Failed to create memory pool.");
        return DECLINED;
    }
    apr_pool_tag(patcklog, "patcklog");

    return APR_SUCCESS;
}

AP_DECLARE(int) show_accesslog_init(apr_pool_t *p)
{   
    int rv;
    
    /* 分配子池 */
    rv = apr_pool_create(&pacslog, p);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "ACCESS_LOG:Failed to create memory pool.");
        return DECLINED;
    }
    apr_pool_tag(pacslog, "pacslog");

    return APR_SUCCESS;
}

AP_DECLARE(int) show_adminlog_init(apr_pool_t *p)
{   
    int rv;
    
    /* 分配子池 */
    rv = apr_pool_create(&padminlog, p);
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "ACCESS_LOG:Failed to create memory pool.");
        return DECLINED;
    }
    apr_pool_tag(padminlog, "padminlog");

    return APR_SUCCESS;
}

static void printf_adminlog_result(cparser_context_t *context, apr_pool_t *ptemp, apr_dbd_results_t **res)
{
    int rv;
    apr_dbd_row_t *row;
    int nrows, ncols;
    int i, j;
    const char *entry;
    apr_time_t time_int;
    char time_str[64];
    char *user_name, *login_ip, *tty, *app, *command;
    
    cli_printf_info(context, FORMATE_ADMINLOG_STRING, 
        "Time", "User-Name", "Login-IP", "Tty", "Application", "Command");

    nrows = apr_dbd_num_tuples(ap_logdb_driver, *res);
    row = NULL;
#if APU_HAVE_SQLITE3
    for (i = 0; i < nrows; i++) {
        rv = apr_dbd_get_row(ap_logdb_driver, ptemp, *res, &row, -1);
#elif APU_HAVE_MYSQL
    for (i = 1; i <= nrows; i++) {
        rv = apr_dbd_get_row(ap_logdb_driver, ptemp, *res, &row, i);
#else
    return;
#endif
        if (rv == 0) {
            ncols = apr_dbd_num_cols(ap_logdb_driver, *res);
            memset(time_str, 0, 64);
            user_name = NULL;
            login_ip = NULL;
            tty = NULL;
            app = NULL;
            command = NULL;
            for (j = 0; j < ncols; j++) {
                entry = apr_dbd_get_entry(ap_logdb_driver, row, j);
                switch(j) {
                case 0:
                    /* 时间 */
                    time_int = apr_atoi64(entry);
                    apr_ctime(time_str, time_int * APR_USEC_PER_SEC);
                    break;
                case 1:
                    /* ip */
                    login_ip = apr_psprintf(ptemp, "%s", entry);
                    break;
                case 2:
                    /* 用户名 */
                    user_name = apr_psprintf(ptemp, "%s", entry);
                    break;
                case 3:
                    /* tty */
                    tty = apr_psprintf(ptemp, "%s", entry); 
                    break;     
                case 4:
                    /* command */
                    command = apr_psprintf(ptemp, "%s", entry);
                    break;
                case 5:
                    /* app */
                    app = apr_psprintf(ptemp, "%s", entry); 
                    break;
                default:
                    break;
                }
            }

            cli_printf_info(context, FORMATE_ADMINLOG_STRING, 
                time_str[0] ? time_str : "--", user_name ? user_name : "--",
                login_ip ? login_ip : "--", tty ? tty : "--", app ? app : "--",
                command ? command : "--");
        }
    }
}

static void printf_access_result(cparser_context_t *context, apr_pool_t *ptemp, apr_dbd_results_t **res)
{
    int rv;
    apr_dbd_row_t *row;
    int nrows, ncols;
    int i, j;
    const char *entry;
    apr_time_t time_int;
    char time_str[64];
    char *cli_ip, *ser_ip, *acc_method, *proto, *acc_status, *acc_url;

    cli_printf_info(context, FORMATE_ACCESS_STRING, 
        "Time", "Client-IP", "Server-IP", "Method", "Protocol", "Status", "URL");

    nrows = apr_dbd_num_tuples(ap_logdb_driver, *res); 
    row = NULL;
#if APU_HAVE_SQLITE3
    for (i = 0; i < nrows; i++) {
        rv = apr_dbd_get_row(ap_logdb_driver, ptemp, *res, &row, -1);
#elif APU_HAVE_MYSQL
    for (i = 1; i <= nrows; i++) {
        rv = apr_dbd_get_row(ap_logdb_driver, ptemp, *res, &row, i);
#else
    return;
#endif
        if (rv == 0) {
            cli_ip = NULL;
            ser_ip = NULL;
            acc_method = NULL;
            proto = NULL;
            acc_status = NULL;
            acc_url = NULL;
            memset(time_str, 0, 64);
            ncols = apr_dbd_num_cols(ap_logdb_driver, *res);
            for (j = 0; j < ncols; j++) {
                entry = apr_dbd_get_entry(ap_logdb_driver, row, j);
                switch(j) {
                case 0:
                    /* 时间 */
                    time_int = apr_atoi64(entry);
                    apr_ctime(time_str, time_int * APR_USEC_PER_SEC);
                    break;
                case 1:
                    /* 客户端ip */
                    cli_ip = apr_psprintf(ptemp, "%s", entry);
                    break;
                case 2:
                    break;
                case 3:
                    /* 服务器端ip */
                    ser_ip = apr_psprintf(ptemp, "%s", entry);
                    break;
                case 4:
                    break;
                case 5:
                    /* 请求方法 */
                    acc_method = apr_psprintf(ptemp, "%s", entry);  
                    break;
                case 6:
                    /* 请求url */
                    acc_url = apr_psprintf(ptemp, "%s", entry); 
                    break;
                case 7:
                    /* 协议 */
                    proto = apr_psprintf(ptemp, "%s", entry); 
                    break;
                case 8:
                    /* 状态 */
                    acc_status = apr_psprintf(ptemp, "%s", entry);
                    break;
                default:
                    break;
                }
            }
            cli_printf_info(context, FORMATE_ACCESS_STRING, 
                time_str[0] ? time_str : "--", cli_ip ? cli_ip : "--", ser_ip ? ser_ip : "--",
                acc_method ? acc_method : "--", proto ? proto : "--",
                acc_status ? acc_status : "--", acc_url ? acc_url : "--");
        }
    }
}

static void printf_attack_result(cparser_context_t *context, apr_pool_t *ptemp, apr_dbd_results_t **res)
{
    int rv;
    apr_dbd_row_t *row;
    int nrows, ncols;
    int i, j;
    const char *entry;
    apr_time_t time_int;
    char time_str[64];
    char *cli_ip, *ser_ip, *att_method, *proto, *att_type, *att_action, *att_url;
    char format[32];

    cli_printf_info(context, FORMATE_ATTACK_STRING, "Time", "Client-IP", "Server-IP", 
        "Method", "Protocol", "Attack-Type", "Action", "URL");

    nrows = apr_dbd_num_tuples(ap_logdb_driver, *res);
    row = NULL;
#if APU_HAVE_SQLITE3
    for (i = 0; i < nrows; i++) {
        rv = apr_dbd_get_row(ap_logdb_driver, ptemp, *res, &row, -1);
#elif APU_HAVE_MYSQL
    for (i = 1; i <= nrows; i++) {
        rv = apr_dbd_get_row(ap_logdb_driver, ptemp, *res, &row, i);
#endif
        if (rv == 0) {
            cli_ip = NULL;
            ser_ip = NULL;
            att_method = NULL;
            proto = NULL;
            att_type = NULL;
            att_action = NULL;
            att_url = NULL;
            memset(time_str, 0, 64);
            memset(format, 0, 32);
            ncols = apr_dbd_num_cols(ap_logdb_driver, *res);
            for (j = 0; j < ncols; j++) {
                entry = apr_dbd_get_entry(ap_logdb_driver, row, j);
                switch(j) {
                case 0:   
                    /* 时间 */
                    time_int = apr_atoi64(entry);
                    apr_ctime(time_str, time_int * APR_USEC_PER_SEC);
                    break;
                case 1:
                    /* 客户端ip */
                    cli_ip = apr_psprintf(ptemp, "%s", entry);
                    break;
                case 2:  
                    /* 客户端端口号 */
                    break;
                case 3:
                    /* 服务器端ip */
                    ser_ip = apr_psprintf(ptemp, "%s", entry);
                    break;
                case 4: 
                    /* 服务器端端口号 */
                    break;
                case 5:
                    /* 动作 */
                    /* 从数据库中获取的action是utf-8编码的，每个汉字3个字节，
                     * 而在printf的时候确是按照每个汉字2个字节打印，会减少1/3长度，
                     * 所以在打印的时候要在把长度多加1/3
                     */   
                    sprintf(format, "%%-%ds", (apr_int32_t)(8 + (strlen(entry) / 3)));
                    att_action = apr_psprintf(ptemp, format, entry);  
                    break;
                case 6:
                    /* 严重等级 */
                    break;
                case 7:
                    /* 方法 */
                    att_method = apr_psprintf(ptemp, "%s", entry);
                    break;
                case 8:
                    /* 攻击类型 */
                    att_type = apr_psprintf(ptemp, "%s", entry); 
                    break;
                case 9:
                    /* 攻击域 */  
                    break;
                case 10:
                    /* 协议 */
                    proto = apr_psprintf(ptemp, "%s", entry);  
                    break;
                case 11:
                    /* 信息 */ 
                    break;
                case 12:
                    /* url */
                    att_url = apr_psprintf(ptemp, "%s", entry);  
                    break;
                default:
                    break;
                }
            }
            cli_printf_info(context, FORMATE_ATTACK_STRING1,
                time_str[0] ? time_str : "--", cli_ip ? cli_ip : "--", ser_ip ? ser_ip : "--", 
                att_method ? att_method : "--", proto ? proto : "--", att_type ? att_type : "--", 
                att_action ? att_action : "--", att_url ? att_url : "--");
        }
    }
}

static char *format_time(apr_pool_t *ptemp, int year_int,int month_int, int day_int, int hour_int, 
                int minute_int, int second_int)
{
    char *month_str;
    char *day_str;
    char *hour_str;
    char *minute_str;
    char *second_str;

    if (month_int < 10) {
        month_str = apr_psprintf(ptemp, "%d%d", 0, month_int);
    } else {
        month_str = apr_psprintf(ptemp, "%d", month_int);
    }

    if (day_int < 10) {
        day_str = apr_psprintf(ptemp, "%d%d", 0, day_int);
    } else {
        day_str = apr_psprintf(ptemp, "%d", day_int);
    }

    if (hour_int < 10) {
        hour_str = apr_psprintf(ptemp, "%d%d", 0, hour_int);
    } else {
        hour_str = apr_psprintf(ptemp, "%d", hour_int);
    }

    if (minute_int < 10) {
        minute_str = apr_psprintf(ptemp, "%d%d", 0, minute_int);
    } else {
        minute_str = apr_psprintf(ptemp, "%d", minute_int);
    }

    if (second_int < 10) {
        second_str = apr_psprintf(ptemp, "%d%d", 0, second_int);
    } else {
        second_str = apr_psprintf(ptemp, "%d", second_int);
    }

    return apr_psprintf(ptemp, "%d-%s-%s %s:%s:%s", year_int, month_str, day_str, hour_str, 
            minute_str, second_str);
}

static char *format_adminlog_sql_statement(apr_pool_t *ptemp, int flag, uint32_t recent_hours,
                uint32_t start_year, uint32_t start_month, uint32_t start_day, 
                uint32_t start_hour, uint32_t start_min, uint32_t start_sec,
                uint32_t end_year, uint32_t end_month, uint32_t end_day, 
                uint32_t end_hour, uint32_t end_min, uint32_t end_sec)
{
    char *sql_statement;
    char *start_time;
    char *end_time;
    char *temp;

        /* 如果没有输入查询条件，则查询所有 */
    sql_statement = apr_psprintf(ptemp, "select * from admin_log_table where app_type = 'pe'");

    /* 时间条件 */
    if (flag == 1) {
#if APU_HAVE_SQLITE3
        temp = apr_psprintf(ptemp, "and julianday('now', 'localtime') * 86400 - julianday(time) * 86400 <= %d ", 
                recent_hours * 3600);
#elif APU_HAVE_MYSQL
        temp = apr_psprintf(ptemp, "and UNIX_TIMESTAMP() - time <= %d ", 
                recent_hours * 3600);
#endif

        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
    } else if (flag == 2) {
        start_time = format_time(ptemp, start_year, start_month, start_day, start_hour, start_min, start_sec);
        end_time = format_time(ptemp, end_year, end_month, end_day, end_hour, end_min, end_sec);
        
#if APU_HAVE_SQLITE3 
        temp = apr_psprintf(ptemp, "and julianday(time) * 86400 between julianday('%s') * 86400 "
                "and julianday('%s') * 86400 ", start_time, end_time);
#elif APU_HAVE_MYSQL
        temp = apr_psprintf(ptemp, "and time between UNIX_TIMESTAMP('%s') "
            "and UNIX_TIMESTAMP('%s')", start_time, end_time);
#endif

        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
    }

    sql_statement = apr_pstrcat(ptemp, sql_statement, ";", NULL);  
    return sql_statement;
}

static char *format_access_sql_statement(apr_pool_t *ptemp, int flag, uint32_t recent_hours,
                uint32_t start_year, uint32_t start_month, uint32_t start_day, 
                uint32_t start_hour, uint32_t start_min, uint32_t start_sec,
                uint32_t end_year, uint32_t end_month, uint32_t end_day, 
                uint32_t end_hour, uint32_t end_min, uint32_t end_sec)
{
    char *sql_statement;
    char *start_time;
    char *end_time;
    char *temp;

    /* 如果没有输入查询条件，则查询所有 */
    sql_statement = apr_psprintf(ptemp, "select * from %s where 1 = 1 ", ACCESSLOG_TABLE);
    
    /* 时间条件 */
    if (flag == 1) {
#if APU_HAVE_SQLITE3
        temp = apr_psprintf(ptemp, "and julianday('now', 'localtime') * 86400 - julianday(time) * 86400 <= %d ", 
                recent_hours * 3600);
#elif APU_HAVE_MYSQL
        temp = apr_psprintf(ptemp, "and UNIX_TIMESTAMP() - record_time <= %d ", 
                recent_hours * 3600);
#endif

        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
    } else if (flag == 2) {
        start_time = format_time(ptemp, start_year, start_month, start_day, start_hour, start_min, start_sec);
        end_time = format_time(ptemp, end_year, end_month, end_day, end_hour, end_min, end_sec);
        
#if APU_HAVE_SQLITE3
        temp = apr_psprintf(ptemp, "and julianday(time) * 86400 between julianday('%s') * 86400 "
                "and julianday('%s') * 86400 ", start_time, end_time);
#elif APU_HAVE_MYSQL
        temp = apr_psprintf(ptemp, "and record_time between UNIX_TIMESTAMP('%s') "
            "and UNIX_TIMESTAMP('%s')", start_time, end_time);
#endif

        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
    }

#if 0
    /* 客户端IP */
    ip_str = apr_psprintf(ptemp, "%s", inet_ntoa(*(struct in_addr *)GETCDBVAR(paddr, 1)));
    if (ip_str != NULL && strcmp(ip_str, "0.0.0.0")) {
        temp = apr_psprintf(ptemp, "and cliip = '%s' ", ip_str);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);   
    }

     /* 客户端端口 */
    port = GETCDBVAR(int, 12);
    if (port) {
        temp = apr_psprintf(ptemp, "and cliport = %d ", port);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);   
    } 

    /* 服务器端IP */
    ip_str = apr_psprintf(ptemp, "%s", inet_ntoa(*(struct in_addr *)GETCDBVAR(paddr, 2)));
    if (ip_str != NULL && strcmp(ip_str, "0.0.0.0")) {
        temp = apr_psprintf(ptemp, "and serip = '%s' ", ip_str);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);   
    }

    /* 服务器端端口 */
    port = GETCDBVAR(int, 15);
    if (port) {
        temp = apr_psprintf(ptemp, "and serport = %d ", port);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);   
    }

    /* url */
    url = GETCDBVAR(string, 2);
    if (url != NULL && url[0] != '\0') {
        temp = apr_psprintf(ptemp, "and url LIKE '%%%s%%' ", url);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
    }
#endif

    sql_statement = apr_pstrcat(ptemp, sql_statement, ";", NULL);
   
    return sql_statement;
}

static char *format_attack_sql_statement(apr_pool_t *ptemp, int flag, uint32_t recent_hours,
                uint32_t start_year, uint32_t start_month, uint32_t start_day, 
                uint32_t start_hour, uint32_t start_min, uint32_t start_sec,
                uint32_t end_year, uint32_t end_month, uint32_t end_day, 
                uint32_t end_hour, uint32_t end_min, uint32_t end_sec)
{
    char *sql_statement;
    char *start_time;
    char *end_time;
    char *temp;

    /* 如果没有输入查询条件，则查询所有 */
    sql_statement = apr_psprintf(ptemp, "select * from %s where 1 = 1 ", ATTACKLOG_TABLE);

    /* 时间条件 */
    if (flag & 1) {
#if APU_HAVE_SQLITE3
        temp = apr_psprintf(ptemp, "and julianday('now', 'localtime') * 86400 - julianday(time) * 86400 <= %d ", 
                recent_hours * 3600);
#elif APU_HAVE_MYSQL
        temp = apr_psprintf(ptemp, "and UNIX_TIMESTAMP() - time <= %d ", 
                recent_hours * 3600);
#endif

        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
    } else if (flag & (1 << 1)) {
        start_time = format_time(ptemp, start_year, start_month, start_day, start_hour, start_min, start_sec);
        end_time = format_time(ptemp, end_year, end_month, end_day, end_hour, end_min, end_sec);
        
#if APU_HAVE_SQLITE3    
        temp = apr_psprintf(ptemp, "and julianday(time) * 86400 between julianday('%s') * 86400 "
                "and julianday('%s') * 86400 ", start_time, end_time);
#elif APU_HAVE_MYSQL
        temp = apr_psprintf(ptemp, "and time between UNIX_TIMESTAMP('%s') "
            "and UNIX_TIMESTAMP('%s')", start_time, end_time);
#endif

        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
    }
    
#if 0
    /* 攻击类型 */
    item_str = GETCDBVAR(string, 1);
    if (item_str != NULL && item_str[0] != '\0') {
        temp = apr_psprintf(ptemp, "and attname LIKE '%%%s%%' ", item_str);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
    }

    /* 严重等级 */
    if (GETCDBVAR(flag, 1) & (1 << 2)) {
        temp = apr_psprintf(ptemp, "and severity = %d ", GETCDBVAR(int, 11));
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
    }

    /* 客户端IP */
    ip_str = apr_psprintf(ptemp, "%s", inet_ntoa(*(struct in_addr *)GETCDBVAR(paddr, 1)));
    if (ip_str != NULL && strcmp(ip_str, "0.0.0.0")) {
        temp = apr_psprintf(ptemp, "and cliip = '%s' ", ip_str);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);   
    }

    /* 客户端端口 */
    item_int = GETCDBVAR(int, 12);
    if (item_int) {
        temp = apr_psprintf(ptemp, "and cliport = %d ", item_int);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);   
    }

    /* 服务器端IP */
    ip_str = apr_psprintf(ptemp, "%s", inet_ntoa(*(struct in_addr *)GETCDBVAR(paddr, 2)));
    if (ip_str != NULL && strcmp(ip_str, "0.0.0.0")) {
        temp = apr_psprintf(ptemp, "and serip = '%s' ", ip_str);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);   
    }

    /* 服务器端端口 */
    item_int = GETCDBVAR(int, 15);
    if (item_int) {
        temp = apr_psprintf(ptemp, "and serport = %d ", item_int);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);   
    }

    /* actions */
    item_int = GETCDBVAR(int, 14);
    switch(item_int) {
    case 1:
        temp = apr_psprintf(ptemp, "and actions = '%s' ", actions[1]);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
        break;
    case 2:
        temp = apr_psprintf(ptemp, "and actions = '%s' ", actions[2]);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
        break;
    case 3:
        temp = apr_psprintf(ptemp, "and actions = '%s' ", actions[3]);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
        break;
    default:
        break;
    }

    /* method */
    item_int = GETCDBVAR(int, 13);
    switch(item_int) {
    case 1:
        temp = apr_psprintf(ptemp, "and method = '%s' ", method[1]);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
        break;
    case 2:
        temp = apr_psprintf(ptemp, "and method = '%s' ", method[2]);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
        break;
    case 3:
        temp = apr_psprintf(ptemp, "and method = '%s' ", method[3]);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
        break;
    case 4:
        temp = apr_psprintf(ptemp, "and method = '%s' ", method[4]);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
        break;
    case 5:
        temp = apr_psprintf(ptemp, "and method = '%s' ", method[5]);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
        break;
    case 6:
        temp = apr_psprintf(ptemp, "and method = '%s' ", method[6]);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
        break;
    case 7:
        temp = apr_psprintf(ptemp, "and method = '%s' ", method[7]);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
        break;
    default:
        break;
    }

    /* url */
    item_str = GETCDBVAR(string, 2);
    if (item_str != NULL && item_str[0] != '\0') {
        temp = apr_psprintf(ptemp, "and url LIKE '%%%s%%' ", item_str);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
    }

    /* msg */
    item_str = GETCDBVAR(string, 3);
    if (item_str != NULL && item_str[0] != '\0') {
        temp = apr_psprintf(ptemp, "and msg LIKE '%%%s%%' ", item_str);
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
    }
#endif

    sql_statement = apr_pstrcat(ptemp, sql_statement, ";", NULL);
 
    return sql_statement;
}

void show_adminlog_content(cparser_context_t *context, int flag, uint32_t recent_hours, uint32_t start_year, uint32_t start_month, 
        uint32_t start_day, uint32_t start_hour, uint32_t start_min, uint32_t start_sec,
        uint32_t end_year, uint32_t end_month, uint32_t end_day, uint32_t end_hour, 
        uint32_t end_min, uint32_t end_sec)
{
    int rv;  
    apr_dbd_results_t *res;
    apr_pool_t *ptemp;
    char *sql_statement;
    char buf[COMMAND_LEN_MAX];

    apr_pool_create(&ptemp, padminlog);
    apr_pool_tag(ptemp, "ptemp");

    /* 构建管理日志语句 */
    if (flag == 0) {
        sprintf(buf, "show admin-log");    
    } else if (flag == 1) {
        sprintf(buf, "show admin-log recent %d", recent_hours);
    } else if (flag == 2) {
        sprintf(buf, "show admin-log start-time %d %d %d %d %d %d end-time %d %d %d %d %d %d", 
                start_year, start_month, start_day, 
                start_hour, start_min, start_sec, end_year, end_month, 
                end_day, end_hour, end_min, end_sec);
    }

    /* 构建sql语句 */
    sql_statement = format_adminlog_sql_statement(ptemp, flag, recent_hours, 
                        start_year, start_month, start_day, start_hour, start_min, start_sec, 
                        end_year, end_month, end_day, end_hour, end_min, end_sec);
    if (sql_statement == NULL) {
        goto __exit;
    }

     /* 数据库查询 */
    res = NULL;
    apr_global_mutex_lock(ap_logdb_mutex);
#if APU_HAVE_SQLITE3
    rv = apr_dbd_select(ap_logdb_driver, ptemp, ap_logdb_handle, &res, sql_statement, 0);
#elif APU_HAVE_MYSQL
    rv = apr_dbd_select(ap_logdb_driver, ptemp, ap_logdb_handle, &res, sql_statement, 1);
#endif

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "show admin log failure");
        goto __exit;    
    }

    /* 管理日志打印 */
    printf_adminlog_result(context, ptemp, &res);
    admin_log_process(context, buf);  
__exit:
    apr_global_mutex_unlock(ap_logdb_mutex);
    apr_pool_destroy(ptemp);  
    return;
}

void show_accesslog_content(cparser_context_t *context, int flag, uint32_t recent_hours, uint32_t start_year, uint32_t start_month, 
        uint32_t start_day, uint32_t start_hour, uint32_t start_min, uint32_t start_sec,
        uint32_t end_year, uint32_t end_month, uint32_t end_day, uint32_t end_hour, 
        uint32_t end_min, uint32_t end_sec)
{
    int rv;  
    apr_dbd_results_t *res;
    apr_pool_t *ptemp;
    char *sql_statement;
    char buf[COMMAND_LEN_MAX];
     
    apr_pool_create(&ptemp, patcklog);
    apr_pool_tag(ptemp, "ptemp");

    /* 构建管理日志语句 */
    if (flag == 0) {
        sprintf(buf, "show access-log");    
    } else if (flag == 1) {
        sprintf(buf, "show access-log recent %d", recent_hours);
    } else if (flag == 2) {
        sprintf(buf, "show access-log start-time %d %d %d %d %d %d end-time %d %d %d %d %d %d", 
                start_year, start_month, start_day, 
                start_hour, start_min, start_sec, end_year, end_month, 
                end_day, end_hour, end_min, end_sec);
    }
   
    /* 构建sql语句 */
    sql_statement = format_access_sql_statement(ptemp, flag, recent_hours, 
                        start_year, start_month, start_day, start_hour, start_min, start_sec, 
                        end_year, end_month, end_day, end_hour, end_min, end_sec);
    if (sql_statement == NULL) {
        goto __exit;
    }

    /* 数据库查询 */
    res = NULL;
    apr_global_mutex_lock(ap_logdb_mutex);
#if APU_HAVE_SQLITE3
    rv = apr_dbd_select(ap_logdb_driver, ptemp, ap_logdb_handle, &res, sql_statement, 0);
#elif APU_HAVE_MYSQL
    rv = apr_dbd_select(ap_logdb_driver, ptemp, ap_logdb_handle, &res, sql_statement, 1);
#endif
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "show access log failure");
        goto __exit;    
    }
    
    /* 攻击日志打印 */
    printf_access_result(context, ptemp, &res);
    admin_log_process(context, buf);
__exit:
    apr_global_mutex_unlock(ap_logdb_mutex);
    apr_pool_destroy(ptemp);
    
    return;
}

void show_attacklog_content(cparser_context_t *context, int flag, uint32_t recent_hours,uint32_t start_year, uint32_t start_month, uint32_t start_day, 
                            uint32_t start_hour, uint32_t start_min, uint32_t start_sec,
                            uint32_t end_year, uint32_t end_month, uint32_t end_day, 
                            uint32_t end_hour, uint32_t end_min, uint32_t end_sec)
{   
    int rv;  
    apr_dbd_results_t *res;
    apr_pool_t *ptemp;
    char *sql_statement;
    char buf[COMMAND_LEN_MAX];
    
    apr_pool_create(&ptemp, patcklog);
    apr_pool_tag(ptemp, "ptemp");

    /* 构建管理日志语句 */
    if (flag == 0) {
        sprintf(buf, "show attack-log");    
    } else if (flag == 1) {
        sprintf(buf, "show attack-log recent %d", recent_hours);
    } else if (flag == 2) {
        sprintf(buf, "show attack-log start-time %d %d %d %d %d %d end-time %d %d %d %d %d %d", 
                start_year, start_month, start_day, 
                start_hour, start_min, start_sec, end_year, end_month, 
                end_day, end_hour, end_min, end_sec);
    }
   
    /* 构建sql语句 */
    sql_statement = format_attack_sql_statement(ptemp, flag, recent_hours, 
                        start_year, start_month, start_day, start_hour, start_min, start_sec, 
                        end_year, end_month, end_day, end_hour, end_min, end_sec);
    if (sql_statement == NULL) {
        goto __exit;
    }
    
    /* 数据库查询 */
    res = NULL;

    apr_global_mutex_lock(ap_logdb_mutex);
#if APU_HAVE_SQLITE3
    rv = apr_dbd_select(ap_logdb_driver, ptemp, ap_logdb_handle, &res, sql_statement, 0);
#elif APU_HAVE_MYSQL
    rv = apr_dbd_select(ap_logdb_driver, ptemp, ap_logdb_handle, &res, sql_statement, 1);
#endif
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "show attack log failure");
        goto __exit;    
    } 

    /* 攻击日志打印 */
    printf_attack_result(context, ptemp, &res);
    admin_log_process(context, buf);
__exit:
    apr_global_mutex_unlock(ap_logdb_mutex);
    apr_pool_destroy(ptemp);
    
    return;
}

cparser_result_t cparser_cmd_show_log_type(cparser_context_t *context,
                    char **log_type_ptr)
{ 
    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        if (!strcmp(*log_type_ptr, "attack-log")) {
            show_attacklog_content(context, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,0 ,0);
        } else if (!strcmp(*log_type_ptr, "access-log")) {
            show_accesslog_content(context, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,0 ,0);
        } else if (!strcmp(*log_type_ptr, "admin-log")) {
            show_adminlog_content(context, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,0 ,0);
        }
      
        return CPARSER_OK;
    }    
}

cparser_result_t cparser_cmd_show_log_type_recent_hours(cparser_context_t *context,
                    char **log_type_ptr, uint32_t *hours_ptr) 
{ 
    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        if (!strcmp(*log_type_ptr, "attack-log")) {
            show_attacklog_content(context, 1, *hours_ptr, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,0 ,0);
        } else if (!strcmp(*log_type_ptr, "access-log")) {
            show_accesslog_content(context, 1, *hours_ptr, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,0 ,0);
        } else if (!strcmp(*log_type_ptr, "admin-log")) {
            show_adminlog_content(context, 1, *hours_ptr, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,0 ,0);
        }

        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_show_log_type_start_time_start_year_start_month_start_day_start_hour_start_min_start_sec_end_time_end_year_end_month_end_day_end_hour_end_min_end_sec(cparser_context_t *context,
                    char **log_type_ptr,
                    uint32_t *start_year_ptr, uint32_t *start_month_ptr, uint32_t *start_day_ptr, uint32_t *start_hour_ptr, uint32_t *start_min_ptr, uint32_t *start_sec_ptr,
                    uint32_t *end_year_ptr, uint32_t *end_month_ptr, uint32_t *end_day_ptr, uint32_t *end_hour_ptr, uint32_t *end_min_ptr, uint32_t *end_sec_ptr)
{ 
    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    } else {
        if (!strcmp(*log_type_ptr, "attack-log")) {
            show_attacklog_content(context, 2, 0,  *start_year_ptr, *start_month_ptr, *start_day_ptr, 
                *start_hour_ptr, *start_min_ptr, *start_sec_ptr, *end_year_ptr, *end_month_ptr, 
                *end_day_ptr, *end_hour_ptr, *end_min_ptr, *end_sec_ptr);
        } else if (!strcmp(*log_type_ptr, "access-log")) {
            show_accesslog_content(context, 2, 0, *start_year_ptr, *start_month_ptr, *start_day_ptr, 
                *start_hour_ptr, *start_min_ptr, *start_sec_ptr, *end_year_ptr, *end_month_ptr, 
                *end_day_ptr, *end_hour_ptr, *end_min_ptr, *end_sec_ptr);
        } else if (!strcmp(*log_type_ptr, "admin-log")) {
            show_adminlog_content(context, 2, 0, *start_year_ptr, *start_month_ptr, *start_day_ptr, 
                *start_hour_ptr, *start_min_ptr, *start_sec_ptr, *end_year_ptr, *end_month_ptr, 
                *end_day_ptr, *end_hour_ptr, *end_min_ptr, *end_sec_ptr);
        }
        return CPARSER_OK;
    }
}

AP_DECLARE(void) clear_accesslog_content()
{
    int rv;
    const char *sql_statement;  
    apr_pool_t *ptemp;
    int nrows;
    
    apr_pool_create(&ptemp, pacslog);
    apr_pool_tag(ptemp, "ptemp");

    sql_statement = apr_psprintf(ptemp, "delete from %s", ACCESSLOG_TABLE);

    apr_global_mutex_lock(ap_logdb_mutex);
    rv = apr_dbd_query(ap_logdb_driver, ap_logdb_handle, &nrows, sql_statement);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "clear access log failure");
    }
    
    apr_global_mutex_unlock(ap_logdb_mutex); 
    apr_pool_destroy(ptemp);
}

AP_DECLARE(void) clear_attacklog_content()
{
    int rv;
    const char *sql_statement;  
    apr_pool_t *ptemp;
    int nrows;
    
    apr_pool_create(&ptemp, patcklog);
    apr_pool_tag(ptemp, "ptemp");

    sql_statement = apr_psprintf(ptemp, "delete from %s", ATTACKLOG_TABLE);

    apr_global_mutex_lock(ap_logdb_mutex);
    rv = apr_dbd_query(ap_logdb_driver, ap_logdb_handle, &nrows, sql_statement);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "clear attack log failure");
    }
   
    apr_global_mutex_unlock(ap_logdb_mutex); 
    apr_pool_destroy(ptemp);
}

void clear_adminlog_content()
{
    int rv;
    const char *sql_statement;  
    apr_pool_t *ptemp;
    int nrows;

    apr_pool_create(&ptemp, padminlog);
    apr_pool_tag(ptemp, "ptemp");

    sql_statement = apr_psprintf(ptemp, "delete from admin_log_table");     

    apr_global_mutex_lock(ap_logdb_mutex);
    rv = apr_dbd_query(ap_logdb_driver, ap_logdb_handle, &nrows, sql_statement);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "clear admin log failure");
    }
   
    apr_global_mutex_unlock(ap_logdb_mutex);
    apr_pool_destroy(ptemp);
}


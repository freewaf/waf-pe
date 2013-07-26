/*
 * $Id: cli_security_policy.h 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

#ifndef CLI_SECURITY_POLICY_H
#define CLI_SECURITY_POLICY_H


#ifdef __cplusplus
extern "C" {
#endif

#include "ap_config.h"
#include "httpd.h"
#include "http_main.h"
#include "http_log.h"
#include "mpm_common.h"
#include "cli_common.h"
#include "convert_rule.h"
#include "cparser.h"
#include "cparser_priv.h"
#include "cparser_token.h"
#include "global_root.h"
#include "cparser_show_tree.h"
#include "cparser_tree.h"
 
#define SUBPOLICY_NUM 31
#define MAX_SCPNAME_LEN 256
#define NO_TYPE 0
#define EXPIRECOOKIE_MAX_TIMEOUT 65535     /* 单位(分钟)*/

typedef struct generate_subpolicy_s generate_subpolicy_t;
struct generate_subpolicy_s {
    apr_pool_t *pool;
    int sec_subpolicy;                      /* 子安全策略类型 */
    char sec_policy[NAME_LEN_MAX];          /* 子安全策略所属的安全策略 */
    int action;
    int log;
    int status;
    int flag;                               /* 用来标识是否从cli输入 */
};

typedef struct file_upload_subpolicy_s file_upload_subpolicy_t;
struct file_upload_subpolicy_s {
    apr_pool_t *pool;
    int sec_subpolicy;                      /* 子安全策略类型 */
    char sec_policy[NAME_LEN_MAX];          /* 子安全策略所属的安全策略 */
    int action;
    int log;
    int status;
    int flag;
    /* 用来标识关键字是否在cli中输入, 当用no命令时，设置individual_file_size为默认值，并且flag置为1 */
    int individual_file_size;          
    int all_file_size;
};

typedef struct cookie_subpolicy_s cookie_subpolicy_t;
struct cookie_subpolicy_s {
    apr_pool_t *pool;
    int sec_subpolicy;                      /* 子安全策略类型 */
    char sec_policy[NAME_LEN_MAX];          /* 子安全策略所属的安全策略 */
    int action;
    int log;
    int status;
    int flag;
    int expire_time;                        /* 当为no命令时，设置默认值，并且flag置为1，
	                                           标识show run的时候cli已经处理*/
    int verification_mothed;
    int attribution;
};

typedef struct protocol_subpolicy_s protocol_subpolicy_t;
struct protocol_subpolicy_s {
    apr_pool_t *pool;
    int sec_subpolicy;                      /* 子安全策略类型 */
    char sec_policy[NAME_LEN_MAX];          /* 子安全策略所属的安全策略 */
    int action;
    int log;
    int status;
    int flag;
    int request_header_num;
    int header_size_except_cookie;
    int cookie_size;
    int request_url_size;
    int query_string_size;
    int request_argument_name_size;
    int request_argument_name_value_size;
    int request_argument_num;
    int request_argument_size;
    int request_body_size;
};

typedef struct cc_protect_subpolicy_s cc_protect_subpolicy_t;
struct cc_protect_subpolicy_s {
    apr_pool_t *pool;
    int sec_subpolicy;                      /* 子安全策略类型 */
    char sec_policy[NAME_LEN_MAX];          /* 子安全策略所属的安全策略 */
    int action;
    int log;
    int status;
    int flag;
    int source_ip;
    int referrer_url;
    int access_rate;
	 /* 这里的flag我觉得不需要 ,如果需要添加的话，每加入 url成功的时候，flag加1，当no成功的时候减1，当flag <= 0时，则不在show run进行显示 */
   // int url_string_flag;                   
};

typedef struct security_policy_s security_policy_t;
struct security_policy_s {
    apr_pool_t *pool;
    char name[NAME_LEN_MAX];
    generate_subpolicy_t sql_subply;
    generate_subpolicy_t xss_subply; 
    generate_subpolicy_t ldap_subply; 
    generate_subpolicy_t email_subply; 
    generate_subpolicy_t code_subply;
    generate_subpolicy_t null_subply;
    generate_subpolicy_t csrf_subply;
    generate_subpolicy_t overflow_subply;
    generate_subpolicy_t base_subply;
    generate_subpolicy_t file_subply;
    generate_subpolicy_t path_subply;
    generate_subpolicy_t dir_subply;
    generate_subpolicy_t xml_subply;
    generate_subpolicy_t spider_subply;
    generate_subpolicy_t weakpwd_subply;
    protocol_subpolicy_t protocol_subply;
    generate_subpolicy_t cmd_subply;
    cookie_subpolicy_t cookie_subply;
    file_upload_subpolicy_t fileup_subply;
    generate_subpolicy_t filedown_subply;
    generate_subpolicy_t trojan_subply;
    generate_subpolicy_t server_subply;
    generate_subpolicy_t version_subply;
    generate_subpolicy_t iccard_subply;
    generate_subpolicy_t http_subply;
    generate_subpolicy_t program_subply;
    generate_subpolicy_t idcard_subply;
    generate_subpolicy_t magcard_subply;
    generate_subpolicy_t request_subply;
    generate_subpolicy_t keyword_subply;
    cc_protect_subpolicy_t ccprotect_subply;
    APR_RING_ENTRY(security_policy_s) ring;
    int commit_flag;    /* 标识是否commit */
    int commit_status;
    int url_page_flag;  /* 标识是否进入了url-page模式 */
}; 

APR_RING_HEAD(security_list_head, security_policy_s);

extern char *subpolicy_type[SUBPOLICY_NUM];
extern apr_pool_t *psec;
extern char scpname[MAX_SCPNAME_LEN];
extern  struct security_list_head sec_policy_ring;

extern cparser_node_t cparser_node_st_configure_root_protect_engine_security_policy_secpname_eol;
extern cparser_node_t cparser_node_pe_protect_engine_security_policy_secpname_root_sql_injection_protect_option_eol;
extern cparser_node_t cparser_node_pe_protect_engine_security_policy_secpname_root_weak_password_protect_option_eol;
extern cparser_node_t cparser_node_scp_weak_password_protect_option_root_url_type_url_string_password_name_passwordname_eol;
extern cparser_node_t cparser_node_pe_protect_engine_security_policy_secpname_root_command_injection_protect_option_eol;
extern cparser_node_t cparser_node_pe_protect_engine_security_policy_secpname_root_code_injection_protect_option_eol;
extern cparser_node_t cparser_node_pe_protect_engine_security_policy_secpname_root_xss_attack_protect_option_eol;
extern cparser_node_t cparser_node_pe_protect_engine_security_policy_secpname_root_csrf_attack_protect_option_eol;
extern cparser_node_t cparser_node_pe_protect_engine_security_policy_secpname_root_spider_scanner_attack_protect_option_eol;
extern cparser_node_t cparser_node_pe_protect_engine_security_policy_secpname_root_trojan_protect_option_eol;
extern cparser_node_t cparser_node_pe_protect_engine_security_policy_secpname_root_server_version_protect_option_eol;
extern cparser_node_t cparser_node_pe_protect_engine_security_policy_secpname_root_creditcard_information_protect_option_eol;
extern cparser_node_t cparser_node_pe_protect_engine_security_policy_secpname_root_idcard_information_protect_option_eol;
extern cparser_node_t cparser_node_pe_protect_engine_security_policy_secpname_root_file_download_protect_option_eol;
extern cparser_node_t cparser_node_pe_protect_engine_security_policy_secpname_root_file_upload_protect_option_eol;
extern cparser_node_t cparser_node_pe_protect_engine_security_policy_secpname_root_cookie_protect_option_eol;
extern cparser_node_t cparser_node_pe_protect_engine_security_policy_secpname_root_protocol_param_protect_option_eol;
extern cparser_node_t cparser_node_pe_protect_engine_security_policy_secpname_root_request_method_protect_option_eol;
extern cparser_node_t cparser_node_pe_protect_engine_security_policy_secpname_root_keyword_filter_option_eol;
extern cparser_node_t cparser_node_pe_protect_engine_security_policy_secpname_root_cc_protect_option_eol;

/**
 * 添加关键字 
 */
void keyword_add(cparser_context_t *context, int sec_subpolicy, int type, apr_pool_t *ptemp, char **key_str1, char **key_str2);

/**
 * 删除所有关键字 
 */
cparser_result_t cmd_no_keyword_all(cparser_context_t *context, int sec_subpolicy, int type);

/**
 * 删除指定关键字 
 *
 */
cparser_result_t cmd_no_keyword_plain_text_keyword(cparser_context_t *context, int sec_subpolicy, int type, char **keyword_ptr);

/**
 * 获取当前安全策略名 
 */
void transfer_security_policy_name(cparser_context_t *context);

/**
 * 显示出弱密码下url下的关键字
 */
void wp_url_by_keyword(keyword_t *kw_sub, char *url_string, cparser_context_t *context, int type);

/** 
 * 为cookie删除关键字提供共同的接口 
 */
cparser_result_t cookie_cmd_no_keyword(cparser_context_t *context, int type);

/**
 * 根据关键字类型显示CC关键字
 */
void cc_by_type(int type, apr_array_header_t *k, cparser_context_t *context);

/**
 * 下面四个提供cc配置关键字接口
 */
cparser_result_t cc_cmd_set_source_ip_keyword(cparser_context_t *context, uint32_t *seconds_ptr,
                    uint32_t *times_ptr, int type);

cparser_result_t cc_cmd_set_status_408_rate_keyword(cparser_context_t *context, uint32_t *seconds_ptr,
                    uint32_t *times_ptr, int type);

cparser_result_t cc_cmd_set_referrer_url_keyword(cparser_context_t *context, uint32_t *seconds_ptr,
                    uint32_t *times_ptr, int type);

cparser_result_t cc_cmd_set_url_access_rate_keyword(cparser_context_t *context, uint32_t *seconds_ptr,
                    uint32_t *times_ptr, int type);

/**
 * 计算安全策略中子安全策略enable以及disable数
 */
void securitypolicy_sum(security_policy_t *ring_tmp, int *sub_policy_num, int *enable_num, 
    int *disable_num);

/**
 * 显示安全策略中子安全策略enable以及disable数
 */
void securitypolicy_show(cparser_context_t *context, security_policy_t *ring_tmp);

/**
 * 根据子安全策略的类型显示子安全策略
 */
void scp_show_viatype(cparser_context_t *context,security_policy_t *ring_tmp, int type);

/**
 * 关键字显示
 */
void keyword_show(int type, apr_pool_t *ptemp, cparser_context_t *context);

/**
 * 根据类型显示
 */
void cc_url_by_type(int type, apr_array_header_t *k, cparser_context_t *context);

/**
 * 添加一个安全策略 
 */
 void add_security_policy(cparser_context_t *context, char *sec_policy_name);

/**
 * 显示弱密码下url的命令 
 */
void wp_url_printf(cparser_context_t *context, int type, char **str);

/* 显示弱密码下url的keyword命令 */
void wp_url_keyword_printf(cparser_context_t *context, int type, char **str);

/* 对类型进行比较，用于若密码中 */
int type_compare(int bef_type, int type);

/**
 * 安全子策略命令中存在action 
 */
void set_default_sub_secpolicy_typefirst(generate_subpolicy_t *subpolicy, int type, 
    security_policy_t *ring_tmp);

/**
 * 安全子策略命令中不存在action 
 */
void set_default_sub_secpolicy_typesecond(generate_subpolicy_t *subpolicy, int type, 
    security_policy_t *ring_tmp);

/**
 * 设置安全策略默认包含子策略 
 */
void set_default_security_policy(security_policy_t *ring_tmp);

/* 设置子安全策略action、log、status属性 */
void sec_policy_get_option(generate_subpolicy_t *subpolicy, char **option_ptr, char *buf);
void sec_policy_get_action(generate_subpolicy_t *subpolicy, char **action_ptr, char *buf);
void sec_policy_get_action_option(generate_subpolicy_t *subpolicy, char **action_ptr, 
        char **option_ptr, char *buf);
void sec_policy_get_log_option(generate_subpolicy_t *subpolicy, char **option_ptr, char *buf);
void sec_policy_get_action_log(generate_subpolicy_t *subpolicy, char **action_ptr, char *buf);
void sec_policy_get_action_log_option(generate_subpolicy_t *subpolicy, char **action_ptr, 
        char **option_ptr, char *buf);

/**********************************************************
 * c2p相关接口
 **********************************************************/
void cmd_c2p_sql(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_ldap(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_email(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_command(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_code(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_null(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_xss(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_csrf(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_overflow(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_file(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_base(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_path(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_directory(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_spider(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_trojan(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_xml(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_weak_password(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_server_version(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_http(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_iccard(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_server_error(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_program(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_magcard(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_idcard(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_file_download(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_file_upload(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_cookie(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_protocol(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_request_method(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_keyword_filter(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cmd_c2p_cc(cparser_context_t *context, generate_subpolicy_t *sec_subpolicy);
void cookie_c2p(cparser_context_t *context, const apr_array_header_t *result,  security_policy_t *ring_tmp);
void protocol_c2p(cparser_context_t *context, const apr_array_header_t *result, security_policy_t *ring_tmp);
void file_upload_c2p(cparser_context_t *context, const apr_array_header_t *result, security_policy_t *ring_tmp);
void commit_c2p(cparser_context_t *context);
void keyword_c2p(cparser_context_t *context, int type, apr_pool_t *ptemp);
void cmd_c2p_url_page(cparser_context_t *context, security_policy_t *ring_tmp);

#ifdef __cplusplus
}
#endif

#endif /* PE_SECURITY_POLICY_H */

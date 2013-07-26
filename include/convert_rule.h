/**
 * @file  convert_rule.h
 * @brief Rule Convert Modules functions
 *
 * @defgroup APACHE_CONVERT Rule Convert Modules
 * @ingroup  APACHE
 * @{
 */

#ifndef _APACHE_CONVERT_RULE_H_
#define _APACHE_CONVERT_RULE_H_


#ifdef __cplusplus
extern "C" {
#endif

#include "cli_common.h"

#define URL_BWLIST_ENTRY_NUM    128
#define IP_BWLIST_ENTRY_NUM     128

#define IP_BLACK_TIMEOUT        "60"
#define URL_BLACK_TIMEOUT       "60"

#define FLAG_ALL                1

#define OUTER_KEYWORD           0
#define INNER_KEYWORD           1

/* 返回码 */
#define CONV_OK                 0       /* 操作成功 */
#define CONV_FAIL               -1      /* 操作失败 */
#define CONV_CONFLICT           -2      /* 数据已设置 */
#define CONV_OVERFLOW           -3      /* 数量超限 */
#define CONV_NOTEXIST           -4      /* 数据不存在 */
#define CONV_EXIST              -5      /* 数据已经存在于内置库中 */

/* 规则参数 */
enum variable {
    VARIABLE_URL = 1,
    VARIABLE_POST,
    VARIABLE_COOKIE,
    VARIABLE_REQUEST,
    VARIABLE_RESPONSE
};

enum operator {
    OPERATOR_EQ = 1,
    OPERATOR_GT,
    OPERATOR_GTE,
    OPERATOR_LT,
    OPERATOR_LTE,
    OPERATOR_MATCH,
    OPERATOR_NONMATCH
};

enum action {
    ACTION_DROP = 1,
    ACTION_DENY,
    ACTION_PASS
};

enum status {
    DISABLE,
    ENABLE
};

enum method {
    PUT = 1,
    HEAD,
    OPTIONS,
    DETELETE,
    TRACE,
    CONNECT,
    OTHER
};

/* 编码类型 */
typedef enum {
    UTF_8 = 1,
    BIG5,
    GB2312,
    GBK,
    GB18030
}encode_type_t;

enum information_leakage_type {
    PLAIN = 1,
    REGEX
};

enum weakpasswd_keyword_type {
    PLAIN_URL = 1,
    REGEX_URL,
    PLAIN_PLAIN,
    PLAIN_REGEX,
    REGEX_PLAIN,
    REGEX_REGEX
};

enum weakpasswd_flag {
    WP_CHECK_URL = 1,                   /* 用于 url {plain url-string | regular-exp url-string} password-name string */
    WP_NO_URL_ALL,                      /* 用于 no url all */
    WP_NO_URL,                          /* 用于 no url {plain url-string | regular-exp url-string} */
    WP_NO_KEYWORD_ALL,                  /* 用于no keyword all */
    WP_KEYWORD,                         /* 用于增加或删除单个关键字 */
    WP_KEYWORD_DEFAULT                  /* 用于增加默认的关键字 */
};

/* 安全子策略的子类别 */
/* 协议参数防护安全子策略关键字类别 */
enum protocol_keyword {
    REQUEST_HEADER_NUM = 1,
    HEADER_SIZE_EXCEPT_COOKIE,
    COOKIE_SIZE,
    REQUEST_URL_SIZE,
    QUERY_STRING_SIZE,
    ARGUMENT_NUM,
    ARGUMENT_SIZE,
    BODY_SIZE,
    ARGUMENT_NAME_SIZE,
    ARGUMENT_NAME_VALUE_SIZE,
    END_PROTOCOL
};

/* 关键字过滤安全子策略关键字类别 */
enum keyword_filter {
    URL = 1,
    KEY_COOKIE,
    POST,
    REQUEST_BODY,
    RESPONSE_BODY
};

/* 文件上传安全子策略关键字类别 */
enum fileupload_keyword {
    FILE_TYPE = 1,
    INDIVIDUAL_FILE_SIZE,
    ALL_FILE_SIZE
};

/* Cookie防护安全子策略关键字类别 */
enum cookie {
    COOKIE_NAME = 1,
    EXPIRE_TIME,
    VERIFICATION,
    ATTRIBUTION
};

enum verification_method_group_one {
    SIGNATURE = 1,
    ENCRYPTION
};

enum verification_method_group_two {
    COOKIE_VERTFICATION = 1,
    IP_AND_COOKIE
};

enum attribution {
    SECURE = 1,
    HTTPDONLY,
    SECURE_HTTPONLY
};

enum cc_keyword {
    SOURCE_IP = 1,
    REFERRER_URL,
    STATUS_408_RATE,
    CC_PLAIN_URL,
    CC_REGEX_URL,
    URL_ACCESS_RATE,
    CC_KEYWORD_ALL
};

enum csrf_keyword {
    CSRF_COOKIE_NAME = 1,
    CSRF_URL_PLAIN,
    CSRF_URL_REGEX,
    CSRF_URL_ALL
};

/* 安全子策略类别 */
typedef enum {
    SQL_INJECTION,          /* SQL注入防护 */
    LDAP_INJECTION,             /* LDAP注入防护 */
    EMAIL_INJECTION,            /* EMAIL注入防护 */
    COMMAND_INJECTION,          /* COMMAND注入防护 */
    CODE_INJECTION,             /* CODE注入防护 */
    NULL_BYTE_INJECTION,        /* NULL BYTE注入防护 */
    XSS,                        /* XSS攻击防护 */
    CSRF,                       /* CSRF攻击防护 */
    OVERFLOW,                   /* 溢出攻击防护 */
    FILE_INCLUDE,               /* 文件包含攻击防护 */
    BASE_ATTACK,                /* 基本攻击防护 */
    PATH_TRAVERSAL,             /* 路径遍历攻击防护 */
    DIRECTORY_INDEX,            /* 目录索引防护 */
    SPIDER_SCANNER,             /* 爬虫与扫描攻击防护 */
    TROJAN,                     /* 木马防护 */
    XML_ATTACK,                 /* XML攻击防护 */
    WEAK_PASSWORD,              /* 弱口令防护 */
    SERVER_VERSION,             /* 服务器版本信息泄露防护 */
    HTTP_STATUS_CODE,           /* HTTP状态码信息泄露防护 */
    ICCARD_INFORMATION,         /* IC卡信息泄漏防护 */
    SERVER_ERROR_INFO,          /* 服务器错误信息泄漏防护 */
    PROGRAM_CODE,               /* 程序代码信息泄露防护 */
    MAGCARD_INFORMATION,        /* 配置磁卡信息防护 */
    IDCARD_INFORMATION,         /* 配置ID卡信息防护 */
    FILE_DOWNLOAD,              /* 下载文件防护 */
    FILE_UPLOAD,                /* 上载文件防护 */
    COOKIE,                     /* COOKIE防护 */
    PROTOCOL_PARAM,             /* 协议参数防护 */
    REQUEST_METHOD,             /* 请求方法防护 */
    KEYWORD_FILTER,             /* 关键字过滤 */
    CC_PROTECT,                 /* CC防护 */
    MAIN_CONFIG,                /* 主配置文件 */
    MAX_SUBPOLICY               /* 最大安全子策略编号 */
}  subpolicy_type_t;

/* 黑白名单相关定义 */
enum black_white_lst {
    IP_BLACK = 0,
    IP_WHITE,
    URL_BLACK,
    URL_WHITE,
    ALL_LIST
};

/* IP黑名单子类别 */
enum ip_black_type {
    IB_CLIENT_IP = 0,
    IB_DYN_TIMEOUT,
    IB_DYN_EXCEPT,
    IB_DYN_CLEAR
};

/* IP白名单子类别 */
enum ip_white_type {
    IW_CLIENT_IP = 0,
    IW_SERVER_IP,
    IW_SERVER_HOST
};

/* URL黑名单子类别 */
enum url_black_type {
    UB_URL_PLAIN = 0,
    UB_URL_REGEX,
    UB_DYN_TIMEOUT,
    UB_DYN_EXCEPT,
    UB_DYN_CLEAR
};

/* URL白名单子类别 */
enum url_white_type {
    UW_URL_PLAIN = 0,
    UW_URL_REGEX
};

/* 通用的关键字 all */
#define KEYWORD_ALL             "all"
#define KEYWORD_DEFAULT         "default"
#define KEYWORD_ALL_FLAG        1
#define KEYWORD_DEFAULT_FLAG    2

extern encode_type_t encode_type;           /* 编码类型 */

/* 判断输入是否全部为ASCII字符 */
extern int is_ascii(char *str);

/* 转换接口 */

/**
 * Set up for rule convert.
 * @param p The pool for save persistent data
 * @param ptrans Pool for save transient data
 */
int convert_init(apr_pool_t *p, apr_pool_t *pconf);

/* 安全策略转换相关接口 */

/**
 * Delete security policy
 * @param name The policy to be deleted
 * @return
 *      CONV_OK         succeed
 *      CONV_FAIL       failure
 *      CONV_NOTEXIST   not exist
 */
int convert_sec_policy_del(const char *name);

/**
 * Query for security policy directive
 * @param name The security policy to be query
 * @param result An array of all rule string in this security policy
 * @return OK (succeed) or others( failure)
 */
int convert_sec_policy_query(const char *name, apr_array_header_t **result);

/**
 * Set security sub policy
 * @param s The security sub policy to be set
 * @return OK (succeed) or others( failure)
 */
int convert_sec_subpolicy_set(sec_subpolicy_t *s);

/**
 * Add security sub policy keyword
 * @param k The keyword to be added
 * @return
 *      CONV_OK         succeed
 *      CONV_FAIL       failure
 *      CONV_CONFLICT   keyword already exist
 */
int convert_keyword_add(keyword_t *k);

/**
 * Delete security sub policy keyword
 * @param k The keyword to be deleted
 * @return
 *      CONV_OK         succeed
 *      CONV_FAIL       failure
 *      CONV_NOTEXIST   not exist
 */
int convert_keyword_del(keyword_t *k);

/**
 * list the security policy's information
 * @sec_policy: the name of the policy
 * @sec_subpolicy: the subpolicy, see also subpolicy_type_t.
 * @result: the result to be shown *
 * @return: CONV_OK (succeed) or CONV_FAIL(failure)
 */
int convert_sec_policy_list(char *sec_policy, int sec_subpolicy, apr_array_header_t **result);


/* 访问列表（黑白名单）转换相关接口 */

/**
 * Set the access control list
 * @param lst Access control list. Including black and white lists.
 * @param type Set the access control object type. For example, the client Ip
 * @param data Access control data. For example, IP address, time
 * @return
 *      CONV_OK         succeed
 *      CONV_FAIL       failure
 *      CONV_CONFLICT   already existed
 *      CONV_OVERFLOW   overflow
 */
int convert_access_list_set(int lst, int type, char *data);

/**
 * Clear the access control list
 * @param lst Access control list. Including black and white lists.
 * @param type Set the access control object type. For example, the client Ip
 * @param data Access control data. For example, IP address
 * @return CONV_OK (succeed) or CONV_FAIL( failure)
 */
int convert_access_list_clear(int lst, int type, char *data);

/**
 * Query for the access control list directive
 * @param lst Access control list. Including black and white
 *            lists.
 * @param result An array of all access list string
 * @return CONV_OK (succeed) or CONV_FAIL(failure)
 */
int convert_access_list_query(int lst, apr_array_header_t **result);

/**
 * Show the access control list data
 * @param lst Access control list. Including black and white
 *            lists.
 * @param type Set the access control object type. For example, the client Ip
 * @param result An array of all access list string
 * @return CONV_OK (succeed) or CONV_FAIL(failure)
 */
int convert_access_list_show(int lst, int type, apr_array_header_t **result);


#ifdef __cplusplus
}
#endif

#endif /* !APACHE_CONVERT_RULE_H */
/** @} */


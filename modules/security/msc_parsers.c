/*
* ModSecurity for Apache 2.x, http://www.modsecurity.org/
* Copyright (c) 2004-2011 Trustwave Holdings, Inc. (http://www.trustwave.com/)
*
* You may not use this file except in compliance with
* the License.  You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* If any of the files related to licensing are missing or if you have any
* other questions related to licensing please contact Trustwave Holdings, Inc.
* directly using the email address security@modsecurity.org.
*/

#include "msc_parsers.h"
#include <ctype.h>

#if 0
/**
 *
 */
int parse_cookies_v0(modsec_rec *msr, char *_cookie_header,
                     apr_table_t *cookies)
{
    char *attr_name = NULL, *attr_value = NULL;
    char *cookie_header;
    char *saveptr = NULL;
    int cookie_count = 0;
    char *p = NULL;

    if (_cookie_header == NULL) {
        msr_log(msr, 1, "Cookie parser: Received null for argument.");
        return -1;
    }

    cookie_header = strdup(_cookie_header);
    if (cookie_header == NULL) return -1;
    
    p = apr_strtok(cookie_header, ";", &saveptr);
    while(p != NULL) {
        attr_name = NULL;
        attr_value = NULL;

        /* ignore whitespace at the beginning of cookie name */
        while(isspace(*p)) p++;
        attr_name = p;

        attr_value = strstr(p, "=");
        if (attr_value != NULL) {
            /* terminate cookie name */
            *attr_value = 0;
            /* move over to the beginning of the value */
            attr_value++;
        }

        /* we ignore cookies with empty names */
        if ((attr_name != NULL)&&(strlen(attr_name) != 0)) {
            if (attr_value != NULL) {
                if (msr->txcfg->debuglog_level >= 5) {
                    msr_log(msr, 5, "Adding request cookie: name \"%s\", value \"%s\"",
                        log_escape(msr->mp, attr_name), log_escape(msr->mp, attr_value));
                }
            } else {
                if (msr->txcfg->debuglog_level >= 5) {
                    msr_log(msr, 5, "Adding request cookie: name \"%s\", value empty",
                        log_escape(msr->mp, attr_name));
                }

                apr_table_add(cookies, attr_name, "");
            }

            cookie_count++;
        }

        p = apr_strtok(NULL, ";", &saveptr);
    }

    free(cookie_header);
    
    return cookie_count;
}

/**
 *
 */
int parse_cookies_v1(modsec_rec *msr, char *_cookie_header,
                     apr_table_t *cookies)
{
    char *attr_name = NULL, *attr_value = NULL, *p = NULL;
    char *prev_attr_name = NULL;
    char *cookie_header = NULL;
    int cookie_count = 0;

    if (_cookie_header == NULL) return -1;
    // XXX Should it not match _v0 parser?
    //if (_cookie_header == NULL) {
    //    msr_log(msr, 1, "Cookie parser: Received null for argument.");
    //    return -1;
    //}

    cookie_header = strdup(_cookie_header);
    if (cookie_header == NULL) return -1;

    p = cookie_header;
    while(*p != 0) {
        attr_name = NULL;
        attr_value = NULL;

        /* attribute name */

        /* remove space from the beginning */
        while((isspace(*p))&&(*p != 0)) p++;
        attr_name = p;
        while((*p != 0)&&(*p != '=')&&(*p != ';')&&(*p != ',')) p++;

        /* if we've reached the end of string */
        if (*p == 0) goto add_cookie;

        /* if there is no cookie value supplied */
        if ((*p == ';')||(*p == ',')) {
            *p++ = 0; /* terminate the name */
            goto add_cookie;
        }

        /* terminate the attribute name,
         * writing over the = character
         */
        *p++ = 0;

        /* attribute value */

        /* skip over the whitespace at the beginning */
        while((isspace(*p))&&(*p != 0)) p++;

        /* no value supplied */
        if (*p == 0) goto add_cookie;

        if (*p == '"') {
            if (*++p == 0) goto add_cookie;
            attr_value = p;
            while((*p != 0)&&(*p != '"')) p++;
            if (*p != 0) *p++ = 0;
            else {
                /* Do nothing about this. */
            }
        } else {
            attr_value = p;
            while((*p != 0)&&(*p != ',')&&(*p != ';')) p++;
            if (*p != 0) *p++ = 0;

            /* remove the whitespace from the end of cookie value */
            if (attr_value != NULL) {
                char *t = attr_value;
                int i = 0;

                while(*t != 0) {
                    t++;
                    i++;
                }

                while((i-- > 0)&&(isspace(*(--t)))) *t = 0;
            }
        }

    add_cookie:

        /* remove the whitespace from the end of cookie name */
        if (attr_name != NULL) {
            char *t = attr_name;
            int i = 0;

            while(*t != 0) {
                t++;
                i++;
            }

            while((i-- > 0)&&(isspace(*(--t)))) *t = 0;
        }

        /* add the cookie to the list now */
        if ((attr_name != NULL)&&(strlen(attr_name) != 0)) {

            /* handle special attribute names */
            if (attr_name[0] == '$') {
                if (prev_attr_name != NULL) {
                    /* cookie keyword, we change the name we use
                     * so they can have a unique name in the cookie table
                     */
                    attr_name = apr_psprintf(msr->mp, "$%s_%s", prev_attr_name, attr_name + 1);
                }
            }

            if (attr_value != NULL) {
                if (msr->txcfg->debuglog_level >= 5) {
                    msr_log(msr, 5, "Adding request cookie: name \"%s\", value \"%s\"",
                        log_escape(msr->mp, attr_name), log_escape(msr->mp, attr_value));
                }

                apr_table_add(cookies, attr_name, attr_value);
            } else {
                if (msr->txcfg->debuglog_level >= 5) {
                    msr_log(msr, 5, "Adding request cookie: name \"%s\", value empty",
                        log_escape(msr->mp, attr_name));
                }
                apr_table_add(cookies, attr_name, "");
            }

            cookie_count++;

            /* only keep the cookie names for later */
            if (attr_name[0] != '$') prev_attr_name = attr_name;
        }

        /* at this point the *p is either 0 (in which case we exit), or
         * right after the current cookie ended - we need to look for
         * the next cookie
         */
        while( (*p != 0)&&( (*p == ',')||(*p == ';')||(isspace(*p)) ) ) p++;
    }

    free(cookie_header);
    return cookie_count;
}
#endif

int parse_cookies_v0(modsec_rec *msr, char *_cookie_header, apr_table_t *cookies)
{
    char *attr_name = NULL, *attr_value = NULL;
    char *cookie_header;
    msre_cookie_attr_t *attrval;
    int hasequal;
    char *hasseparatmark;
    char *saveptr = NULL;
    int cookie_count = 0;
    char *p = NULL;
    char *key;

    if (_cookie_header == NULL) {
        msr_log(msr, 1, "Cookie parser0: Received null for argument.");
        return -1;
    }

    cookie_header = strdup(_cookie_header);
    if (cookie_header == NULL) {
        return -1;
    }

    hasseparatmark = strchr(cookie_header, ';');
    p = apr_strtok(cookie_header, ";", &saveptr);
    while(p != NULL) {
        attr_name = NULL;
        attr_value = NULL;
        hasequal = 0;

        /* ignore whitespace at the beginning of cookie name */
        while(isspace(*p)) {
            p++;
        }

        attr_name = p;

        attr_value = strchr(p, '=');
        if (attr_value != NULL) {
            hasequal = 1;
            /* terminate cookie name */
            *attr_value = 0;
            /* move over to the beginning of the value */
            attr_value++;
        }

        /* we ignore cookies with empty names */
        if ((attr_name != NULL) && (strlen(attr_name) != 0)) {
            attrval = (msre_cookie_attr_t *)apr_pcalloc(msr->mp, sizeof(msre_cookie_attr_t));
            if (attrval == NULL) {
                return -1;
            }

            attrval->hasequalmark = hasequal;
            if (!hasseparatmark) {
                attrval->separatemark = MSRE_COOKIE_SEP_END;
            }
            if (attr_value != NULL) {
                if (msr->txcfg->debuglog_level >= 5) {
                    msr_log(msr, 5, "Adding cookie: name \"%s\", value \"%s\"",
                        log_escape(msr->mp, attr_name), log_escape(msr->mp, attr_value));
                }
                attrval->attrval = apr_pstrdup(msr->mp, attr_value);
            } else {
                if (msr->txcfg->debuglog_level >= 5) {
                    msr_log(msr, 5, "Adding cookie: name \"%s\", value empty",
                            log_escape(msr->mp, attr_name));
                }
            }
            key = apr_pstrdup(msr->mp, attr_name);
            apr_table_addn(cookies, key, (void *)attrval);
            cookie_count++;
        }

        hasseparatmark = strchr(saveptr, ';');
        p = apr_strtok(NULL, ";", &saveptr);
    }

    free(cookie_header);

    return cookie_count;
}

int parse_cookies_v1(modsec_rec *msr, char *_cookie_header, apr_table_t *cookies)
{
    char *attr_name = NULL, *attr_value = NULL, *p = NULL;
    char *cookie_header = NULL;
    msre_cookie_attr_t *attrval;
    int hasequalmark, hasleftquotmark, hasrightquotmark, separatmark;
    int cookie_count = 0;
    char *key;

    if (_cookie_header == NULL) {
        return -1;
    }

    cookie_header = strdup(_cookie_header);
    if (cookie_header == NULL) {
        return -1;
    }

    p = cookie_header;
    while(*p != 0) {
        attr_name = NULL;
        attr_value = NULL;
        hasequalmark = 0;
        hasleftquotmark = 0;
        hasrightquotmark = 0;
        separatmark = MSRE_COOKIE_SEP_SEMICOLON;

        /* attribute name */

        /* remove space from the beginning */
        while((isspace(*p)) && (*p != 0)) {
            p++;
        }

        attr_name = p;
        while((*p != 0) && (*p != '=') && (*p != ';') && (*p != ',')) {
            p++;
        }

        /* if we've reached the end of string */
        if (*p == 0) {
            separatmark = MSRE_COOKIE_SEP_END;
            goto add_cookie;
        }

        /* if there is no cookie value supplied */
        if (*p == ';') {
            separatmark = MSRE_COOKIE_SEP_SEMICOLON;
            *p++ = 0; /* terminate the name */
            goto add_cookie;
        }

        /* if there is no cookie value supplied */
        if (*p == ',') {
            separatmark = MSRE_COOKIE_SEP_COMMA;
            *p++ = 0; /* terminate the name */
            goto add_cookie;
        }

        /* terminate the attribute name,
         * writing over the = character
         */
        *p++ = 0;
        hasequalmark = 1;

        /* attribute value */

        /* skip over the whitespace at the beginning */
        while((isspace(*p)) && (*p != 0)) {
            p++;
        }

        /* no value supplied */
        if (*p == 0) {
            separatmark = MSRE_COOKIE_SEP_END;
            goto add_cookie;
        }

        if (*p == '"') {
            hasleftquotmark = 1;
            if (*++p == 0) {
                separatmark = MSRE_COOKIE_SEP_END;
                goto add_cookie;
            }
            attr_value = p;

            while((*p != 0) && (*p != '"')) {
                p++;
            }
            if (*p != 0) {
                hasrightquotmark = 1;
                *p++ = 0;
                while((*p != 0) && (isspace(*p))) {
                    p++;
                }
                if (*p == ';') {
                    separatmark = MSRE_COOKIE_SEP_SEMICOLON;
                    p++;
                } else if (*p == ',') {
                    separatmark = MSRE_COOKIE_SEP_COMMA;
                    p++;
                }
            } else {
                separatmark = MSRE_COOKIE_SEP_END;
            }
        } else {
            attr_value = p;
            while((*p != 0) && (*p != ',') && (*p != ';')) {
                p++;
            }

            if (*p == 0) {
                separatmark = MSRE_COOKIE_SEP_END;
            } else {
                if (*p == ';') {
                    separatmark = MSRE_COOKIE_SEP_SEMICOLON;
                } else if (*p == ',') {
                    separatmark = MSRE_COOKIE_SEP_COMMA;
                }
                *p++ = 0;
            }

            /* remove the whitespace from the end of cookie value */
            if (attr_value != NULL) {
                char *t = attr_value;
                int i = 0;

                while(*t != 0) {
                    t++;
                    i++;
                }

                while((i-- > 0)&&(isspace(*(--t)))) *t = 0;
            }
        }

    add_cookie:

        /* remove the whitespace from the end of cookie name */
        if (attr_name != NULL) {
            char *t = attr_name;
            int i = 0;

            while(*t != 0) {
                t++;
                i++;
            }

            while((i-- > 0)&&(isspace(*(--t)))) *t = 0;
        }

        /* add the cookie to the list now */
        if ((attr_name != NULL)&&(strlen(attr_name) != 0)) {
            attrval = (msre_cookie_attr_t *)apr_pcalloc(msr->mp, sizeof(msre_cookie_attr_t));
            if (attrval == NULL) {
                return -1;
            }

            attrval->hasequalmark = hasequalmark;
            attrval->hasleftquotmark = hasleftquotmark;
            attrval->hasrightquotmark = hasrightquotmark;
            attrval->separatemark = separatmark;
            if (attr_value != NULL) {
                if (msr->txcfg->debuglog_level >= 5) {
                    msr_log(msr, 5, "Adding cookie: name \"%s\", value \"%s\"",
                        log_escape(msr->mp, attr_name), log_escape(msr->mp, attr_value));
                }
                attrval->attrval = apr_pstrdup(msr->mp, attr_value);
            } else {
                if (msr->txcfg->debuglog_level >= 5) {
                    msr_log(msr, 5, "Adding cookie: name \"%s\", value empty",
                        log_escape(msr->mp, attr_name));
                }
            }
            key = apr_pstrdup(msr->mp, attr_name);
            apr_table_addn(cookies, key, (void *)attrval);
            cookie_count++;
        }

        /* at this point the *p is either 0 (in which case we exit), or
         * right after the current cookie ended - we need to look for
         * the next cookie
         */
        while((*p != 0) && ((*p == ',') || (*p == ';') || (isspace(*p)))) {
            p++;
        }
    }

    free(cookie_header);

    return cookie_count;
}

int parse_cookie_name(modsec_rec *msr, const char *_cookienames, apr_table_t *cookiename_tb)
{
    char *attr_name;
    char *cookienames;
    char *name;
    char *saveptr;
    int cookie_count = 0;
    char *p = NULL;

    if (_cookienames == NULL) {
        return -1;
    }

    cookienames = strdup(_cookienames);
    if (cookienames == NULL) {
        return -1;
    }

    p = apr_strtok(cookienames, ",", &saveptr);
    while(p != NULL) {
        attr_name = NULL;

        while(isspace(*p)) p++;
        attr_name = p;
        if ((attr_name != NULL) && (strlen(attr_name) != 0)) {
            name = apr_pstrdup(msr->mp, attr_name);
            apr_table_addn(cookiename_tb, name, NULL);
            cookie_count++;
        }

        p = apr_strtok(NULL, ",", &saveptr);
    }

    free(cookienames);

    return cookie_count;
}

char *generate_a_setcookiestr(modsec_rec *msr, apr_table_t *cookies_tb)
{
    const apr_array_header_t  *cookies_arr;
    apr_table_entry_t *cookies_te;
    struct msre_cookie_attr_s *cookie_attr;
    char *setcookiestr;
    int i;

    setcookiestr = NULL;
    cookies_arr = apr_table_elts(cookies_tb);
    cookies_te = (apr_table_entry_t *)cookies_arr->elts;
    for (i = 0; i< cookies_arr->nelts; i++) {
        cookie_attr = (struct msre_cookie_attr_s *)cookies_te[i].val;
        setcookiestr = apr_pstrcat(msr->mp, setcookiestr ? setcookiestr : "",
            cookies_te[i].key,
            cookie_attr->hasequalmark ? "=" : "",
            cookie_attr->hasleftquotmark ? "\"" : "",
            cookie_attr->attrval ? cookie_attr->attrval : "",
            cookie_attr->hasrightquotmark ? "\"" : "", NULL);
        if (setcookiestr == NULL) {
            break;
        }
        if (cookie_attr->separatemark == MSRE_COOKIE_SEP_SEMICOLON) {
            setcookiestr = apr_pstrcat(msr->mp, setcookiestr, "; ", NULL);
        } else if (cookie_attr->separatemark == MSRE_COOKIE_SEP_COMMA) {
            setcookiestr = apr_pstrcat(msr->mp, setcookiestr, ", ", NULL);
        } else {
        }
        if (setcookiestr == NULL) {
            break;
        }
    }

    return setcookiestr;
}

char * parse_uri(apr_pool_t *pool, const char *uri)
{
    char *new_uri;
    int invalid_count;
    int changed;

    if (pool == NULL || uri == NULL) {
        return NULL;
    }
    new_uri = apr_pstrdup(pool, uri);
    if (new_uri == NULL) {
        return NULL;
    }
    if (urldecode_nonstrict_inplace_ex((unsigned char *)new_uri, strlen(new_uri), &invalid_count, &changed) == -1) {
        return NULL;
    }

    return new_uri;    
}

char * parse_request_line(apr_pool_t *pool, const char *request_line)
{
    char *new_request_line;
    int invalid_count;
    int changed;

    if (pool == NULL || request_line == NULL) {
        return NULL;
    }
    new_request_line = apr_pstrdup(pool, request_line);
    if (new_request_line == NULL) {
        return NULL;
    }
    if (urldecode_nonstrict_inplace_ex((unsigned char *)new_request_line, strlen(new_request_line), &invalid_count, 
        &changed) == -1) {
        return NULL;
    }

    return new_request_line;    
}

/**
 *
 */
int parse_arguments(modsec_rec *msr, const char *s, apr_size_t inputlength, int argument_separator, 
        const char *origin, apr_table_t *arguments, int *invalid_count)
{
    msc_arg *arg;
    apr_size_t i, j;
    char *value = NULL;
    char *buf;
    int status;
    int changed;

    if (s == NULL) {
        return -1;
    }
    if (inputlength == 0) {
        return 1;
    }

    /* Check that adding one will not overflow */
    if (inputlength + 1 <= 0) {
        return -1;
    }

    buf = (char *)malloc(inputlength + 1);
    if (buf == NULL) {
        return -1;
    }

    arg = (msc_arg *)apr_pcalloc(msr->mp, sizeof(msc_arg));
    arg->origin = origin;

    i = 0;
    j = 0;
    status = 0;
    *invalid_count = 0;
    while (i < inputlength) {
        if (status == 0) {
            /* parameter name */
            arg->name_origin_offset = i;
            while ((s[i] != '=') && (s[i] != argument_separator) && (i < inputlength)) {
                buf[j] = s[i];
                j++;
                i++;
            }
            buf[j++] = '\0';
            arg->name_origin_len = i - arg->name_origin_offset;
        } else {
            /* parameter value */
            arg->value_origin_offset = i;
            while ((s[i] != argument_separator) && (i < inputlength)) {
                buf[j] = s[i];
                j++;
                i++;
            }
            buf[j++] = '\0';
            arg->value_origin_len = i - arg->value_origin_offset;
        }

        if (status == 0) {
            arg->name_len = urldecode_nonstrict_inplace_ex((unsigned char *)buf, arg->name_origin_len, invalid_count, &changed);
            arg->name = apr_pstrmemdup(msr->mp, buf, arg->name_len);
            if (s[i] == argument_separator) {
                /* Empty parameter */
                arg->value_len = 0;
                arg->value = "";

                add_argument(msr, arguments, arg);

                arg = (msc_arg *)apr_pcalloc(msr->mp, sizeof(msc_arg));
                arg->origin = origin;

                status = 0; /* unchanged */
                j = 0;
            } else {
                status = 1;
                value = &buf[j];
            }
        } else {
            arg->value_len = urldecode_nonstrict_inplace_ex((unsigned char *)value, 
                                arg->value_origin_len, invalid_count, &changed);
            arg->value = apr_pstrmemdup(msr->mp, value, arg->value_len);

            add_argument(msr, arguments, arg);

            arg = (msc_arg *)apr_pcalloc(msr->mp, sizeof(msc_arg));
            arg->origin = origin;

            status = 0;
            j = 0;
        }

        i++; /* skip over the separator */
    }

    /* the last parameter was empty */
    if (status == 1) {
        arg->value_len = 0;
        arg->value = "";

        add_argument(msr, arguments, arg);
    }

    free(buf);

    return 1;
}

/**
 *
 */
void add_argument(modsec_rec *msr, apr_table_t *arguments, msc_arg *arg)
{
    if (msr->txcfg->debuglog_level >= 5) {
        msr_log(msr, 5, "Adding request argument (%s): name \"%s\", value \"%s\"",
            arg->origin, log_escape_ex(msr->mp, arg->name, arg->name_len),
            log_escape_ex(msr->mp, arg->value, arg->value_len));
    }

    apr_table_addn(arguments, log_escape_nq_ex(msr->mp, arg->name, arg->name_len), (void *)arg);
}


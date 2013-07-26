/*
 * $Id: convert_iccard_information.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#include "convert_private.h"

static char *iccard_flag[] = {"creditcard-body-information", "creditcard-headers-information"};
static char *iccard_rule[] = {"SecRule STREAM_OUTPUT_BODY \"@rsubSen"\
                        " s/(?:^|[^\\d])(?<!google_ad_client = \\\"pub-)%s(?:[^\\d]|$)/%s/[c]\""\
                        " \"phase:4,t:none,pass,msg:'ic information  Leakage', id:'%s',"
                        " tag:'information  disclosure',severity:'3'\"",

                        "SecRule RESPONSE_HEADERS:Location \"@rsubSen"\
                        " s/(?:^|[^\\d])(?<!google_ad_client = \\\"pub-)%s(?:[^\\d]|$)/%s/[c]\""\
                        " \"phase:3,t:none,pass,msg:'ic information  Leakage', id:'%s',"
                        " tag:'information  disclosure',severity:'3'\""};

static int iccard_information_subpolicy_del(const char *sec_policy, apr_pool_t *ptemp);

static int iccard_information_keyword_add(keyword_t *k, apr_pool_t *ptemp)
{
    return add_two_keyword(k, ptemp);
}

static int iccard_information_keyword_del(keyword_t *k, apr_pool_t *ptemp)
{
    if (k->flag == FLAG_ALL) {
        return iccard_information_subpolicy_del(k->sec_policy, ptemp);
    }

    return delete_two_keyword(k, ptemp, KEYWORD_SECOND);
}

static int iccard_information_subpolicy_query(const char *name, apr_dbd_row_t *orig_row,
                                            apr_array_header_t **result, apr_pool_t *ptemp)
{
    int rv;
    const char *flag;

    if (orig_row == NULL) {
        return CONV_NOTEXIST;
    }

    if ((name == NULL) || (result == NULL) || (*result == NULL) || (ptemp == NULL)) {
        return CONV_FAIL;
    }

    flag = apr_dbd_get_entry(driver, orig_row, B_FLAG);
    if ( (flag != NULL) && (strcmp(flag, iccard_flag[0]) == 0)) { /* 响应体新加规则在原有规则之前 */
        rv = query_info_leakage(name, ICCARD_INFORMATION, iccard_rule[0], result, ptemp);
        if (rv != CONV_OK) {
            return rv;
        }

        combined_rule(orig_row, NULL, NULL, result, ptemp);
        return CONV_OK;
    } else if (strcmp(flag, iccard_flag[1]) == 0) {     /* 响应头新加规则在原有规则之后 */
        combined_rule(orig_row, NULL, NULL, result, ptemp);
        rv = query_info_leakage(name, ICCARD_INFORMATION, iccard_rule[1], result, ptemp);
        if (rv != CONV_OK) {
            return rv;
        }

        return CONV_OK;
    } else {
        return CONV_FAIL;
    }
}

static int iccard_information_subpolicy_del(const char *sec_policy, apr_pool_t *ptemp)
{
    return sub_with_new_del(sec_policy, ICCARD_INFORMATION, ptemp);
}

static int iccard_information_subpolicy_list(const char *sec_policy,
                                            apr_array_header_t **result, apr_pool_t *ptemp)
{
    return list_two_keyword(sec_policy, ICCARD_INFORMATION, result, ptemp);
}

subpolicy_t iccard_information_subpolicy = {
    ICCARD_INFORMATION,
    iccard_information_keyword_add,
    iccard_information_keyword_del,
    iccard_information_subpolicy_query,
    iccard_information_subpolicy_del,
    iccard_information_subpolicy_list
};


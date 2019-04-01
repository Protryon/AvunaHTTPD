/*
 * string.c
 *
 *  Created on: Nov 17, 2015
 *      Author: root
 */
#include <avuna/pmem.h>
#include <avuna/string.h>
#include <avuna/list.h>
#include <avuna/hash.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>

char* str_trim(char* str) {
    if (str == NULL) return NULL;
    size_t len = strlen(str);
    for (ssize_t i = len - 1; i >= 0; i--) {
        if (isspace(str[i])) {
            str[i] = 0;
        } else break;
    }
    for (int i = 0; i < len; i++) {
        if (!isspace(str[i])) return str + i;
    }
    return str + len;
}

int str_eq_case(const char* str1, const char* str2) {
    if (str1 == NULL || str2 == NULL) return 0;
    if (str1 == str2) return 1;
    size_t l1 = strlen(str1);
    size_t l2 = strlen(str2);
    if (l1 != l2) return 0;
    for (ssize_t i = 0; i < l1; i++) {
        if (str1[i] != str2[i]) {
            return 0;
        }
    }
    return 1;
}

int str_eq(const char* str1, const char* str2) {
    if (str1 == NULL || str2 == NULL) return 0;
    if (str1 == str2) return 1;
    size_t l1 = strlen(str1);
    size_t l2 = strlen(str2);
    if (l1 != l2) return 0;
    for (int i = 0; i < l1; i++) {
        char s1 = str1[i];
        if (s1 >= 'A' && s1 <= 'Z') s1 += ' ';
        char s2 = str2[i];
        if (s2 >= 'A' && s2 <= 'Z') s2 += ' ';
        if (s1 != s2) {
            return 0;
        }
    }
    return 1;
}

int str_prefixes_case(const char* str, const char* with) {
    if (str == NULL || with == NULL) return 0;
    if (str == with) return 1;
    size_t l1 = strlen(str);
    size_t l2 = strlen(with);
    if (l1 < l2) return 0;
    for (int i = 0; i < l2; i++) {
        if (str[i] != with[i]) {
            return 0;
        }
    }
    return 1;
}

int str_prefixes(const char* str, const char* with) {
    if (str == NULL || with == NULL) return 0;
    if (str == with) return 1;
    size_t l1 = strlen(str);
    size_t l2 = strlen(with);
    if (l1 < l2) return 0;
    for (ssize_t i = 0; i < l2; i++) {
        char s1 = str[i];
        if (s1 >= 'A' && s1 <= 'Z') s1 += ' ';
        char s2 = with[i];
        if (s2 >= 'A' && s2 <= 'Z') s2 += ' ';
        if (s1 != s2) {
            return 0;
        }
    }
    return 1;
}

int str_suffixes_case(const char* str, const char* with) {
    if (str == NULL || with == NULL) return 0;
    if (str == with) return 1;
    size_t l1 = strlen(str);
    size_t l2 = strlen(with);
    if (l1 < l2) return 0;
    for (ssize_t i = 0; i < l2; ++i) {
        if (str[l1 - 1 - i] != with[l2 - 1 - i]) {
            return 0;
        }
    }
    return 1;
}

int str_suffixes(const char* str, const char* with) {
    if (str == NULL || with == NULL) return 0;
    if (str == with) return 1;
    size_t l1 = strlen(str);
    size_t l2 = strlen(with);
    if (l1 < l2) return 0;
    for (ssize_t i = 0; i < l2; ++i) {
        char s1 = str[l1 - 1 - i];
        if (s1 >= 'A' && s1 <= 'Z') s1 += ' ';
        char s2 = with[l2 - 1 - i];
        if (s2 >= 'A' && s2 <= 'Z') s2 += ' ';
        if (s1 != s2) {
            return 0;
        }
    }
    return 1;
}

int str_contains_case(const char* str, const char* with) {
    if (str == NULL || with == NULL) return 0;
    if (str == with) return 1;
    size_t l1 = strlen(str);
    size_t l2 = strlen(with);
    if (l1 < l2) return 0;
    int ml = 0;
    for (ssize_t i = 0; i < l1; i++) {
        if (str[i] == with[ml]) {
            if (++ml == l2) {
                return 1;
            }
        } else ml = 0;
    }
    return 0;
}

int str_contains(const char* str, const char* with) {
    if (str == NULL || with == NULL) return 0;
    if (str == with) return 1;
    size_t l1 = strlen(str);
    size_t l2 = strlen(with);
    if (l1 < l2) return 0;
    int ml = 0;
    for (ssize_t i = 0; i < l1; i++) {
        char s1 = str[i];
        if (s1 >= 'A' && s1 <= 'Z') s1 += ' ';
        char s2 = with[ml];
        if (s2 >= 'A' && s2 <= 'Z') s2 += ' ';
        if (s1 == s2) {
            if (++ml == l2) {
                return 1;
            }
        } else ml = 0;
    }
    return 0;
}

char* str_tolower(char* str) {
    if (str == NULL) return NULL;
    size_t l = strlen(str);
    for (ssize_t i = 0; i < l; i++) {
        if (str[i] >= 'A' && str[i] <= 'Z') str[i] += ' ';
    }
    return str;
}

char* str_toupper(char* str) {
    if (str == NULL) return NULL;
    size_t l = strlen(str);
    for (ssize_t i = 0; i < l; i++) {
        if (str[i] >= 'a' && str[i] <= 'z') str[i] -= ' ';
    }
    return str;
}

char* str_urlencode(char* str, struct mempool* pool) {
    if (str == NULL) return NULL;
    size_t sl = strlen(str);
    for (size_t i = 0; i < sl; i++) {
        char c = str[i];
        if (c == '\"' || c == '#' || c == '$' || c == '%' || c == '&' || c == '+' || c == '-' || c == ',' || c == '/' ||
            c == ':' || c == ';' || c == '=' || c == '?' || c == '@' || c == ' ' || c == '\t' || c == '>' || c == '<' ||
            c == '{' || c == '}' || c == '|' || c == '\\' || c == '^' || c == '~' || c == '[' || c == ']' || c == '`') {
            sl += 2;
            str = prealloc(pool, str, sl + 1);
            str[sl] = 0;
            memmove(str + i + 3, str + i + 1, sl - (i + 2));
            char sc[4];
            snprintf(sc + 1, 3, "%02X", (uint8_t) c);
            sc[0] = '%';
            memcpy(str + i - 1 + 1, sc, 3);
            i += (3 - 1);
        }
    }
    return str;
}

char* str_dup(char* str, ssize_t expand, struct mempool* pool) {
    if (str == NULL) return NULL;
    ssize_t s = strlen(str);
    if (-expand > s) return NULL;
    char* ns = pmalloc(pool, s + expand + 1);
    if (expand < 0) s += expand;
    memcpy(ns, str, s);
    ns[s] = 0;
    return ns;
}

char* str_urldecode(char* str) {
    if (str == NULL) return NULL;
    size_t sl = strlen(str);
    if (sl < 2) return str;
    for (size_t i = 0; i < sl - 2; i++) {
        char c = str[i];
        if (c == '%' && sl >= 2) {
            if (str[i + 1] == '%') {
                sl -= 1;
                memmove(str + i + 1, str + i + 2, sl - i - 1);
            } else {
                sl -= 2;
                char hex[3] = {str[i + 1], str[i + 2], 0};
                char c2 = strtoul(hex, NULL, 16);
                str[i] = c2;
                //printf("%i, %i, %i\n", i, sl, sl + 2);
                ssize_t ml = (ssize_t) sl - ((ssize_t) i + 2);
                if (ml > 0) memmove(str + i + 1, str + i + 3, ml);
            }
            i++;
        }
    }
    return str;
}

void str_split(char* str, char* delim, struct list* out) {
    if (strlen(delim) == 0) {
        return;
    }
    size_t si = strlen(str);
    size_t li = 0;
    for (size_t i = 0; i < si; i++) {
        if (str_prefixes(str + i, delim)) {
            list_add(out, str + li);
            str[i] = 0;
            i += strlen(delim) - 1;
            li = i + 1;
        }
    }
    if (li != si) {
        list_add(out, str + li);
    }
}

void str_split_case(char* str, char* delim, struct list* out) {
    if (strlen(delim) == 0) {
        return;
    }
    size_t si = strlen(str);
    size_t li = 0;
    for (size_t i = 0; i < si; i++) {
        if (str_prefixes_case(str + i, delim)) {
            list_add(out, str + li);
            str[i] = 0;
            i += strlen(delim) - 1;
            li = i + 1;
        }
    }
    if (li != si) {
        list_add(out, str + li);
    }
}


void str_split_set(char* str, char* delim, struct hashset* out) {
    if (strlen(delim) == 0) {
        return;
    }
    size_t si = strlen(str);
    size_t li = 0;
    for (size_t i = 0; i < si; i++) {
        if (str_prefixes(str + i, delim)) {
            hashset_add(out, str + li);
            str[i] = 0;
            i += strlen(delim) - 1;
            li = i + 1;
        }
    }
    if (li != si) {
        hashset_add(out, str + li);
    }
}

void str_split_set_case(char* str, char* delim, struct hashset* out) {
    if (strlen(delim) == 0) {
        return;
    }
    size_t si = strlen(str);
    size_t li = 0;
    for (size_t i = 0; i < si; i++) {
        if (str_prefixes_case(str + i, delim)) {
            hashset_add(out, str + li);
            str[i] = 0;
            i += strlen(delim) - 1;
            li = i + 1;
        }
    }
    if (li != si) {
        hashset_add(out, str + li);
    }
}

char* str_replace_case(char* str, char* from, char* to, struct mempool* pool) {
    size_t sl = strlen(str);
    size_t fl = strlen(from);
    size_t tl = strlen(to);
    size_t ml = 0;
    for (size_t i = 0; i < sl; i++) {
        char c = str[i];
        if (c == from[ml]) {
            if (++ml == fl) {
                if (tl == fl) {
                    memcpy(str + i - fl + 1, to, tl);
                } else if (tl < fl) {
                    memcpy(str + i - fl + 1, to, tl);
                    memmove(str + i + tl - fl + 1, str + i + fl - fl + 1, sl - i - fl + 1 + 1);
                } else {
                    sl += (tl - fl);
                    str = prealloc(pool, str, sl + 1);
                    str[sl] = 0;
                    memmove(str + i + tl - fl + 1, str + i + 1, sl - i - tl + fl);
                    memcpy(str + i - fl + 1, to, tl);
                }
                i += (tl - fl);
                ml = 0;
            }
        } else ml = 0;
    }
    return str;
}

char* str_replace(char* str, char* from, char* to, struct mempool* pool) {
    size_t sl = strlen(str);
    size_t fl = strlen(from);
    size_t tl = strlen(to);
    size_t ml = 0;
    for (size_t i = 0; i < sl; i++) {
        char c = str[i];
        if (c >= 'A' && c <= 'Z') c += ' ';
        char c2 = from[ml];
        if (c2 >= 'A' && c2 <= 'Z') c2 += ' ';
        if (c == c2) {
            if (++ml == fl) {
                if (tl == fl) {
                    memcpy(str + i - fl + 1, to, tl);
                } else if (tl < fl) {
                    memcpy(str + i - fl + 1, to, tl);
                    memmove(str + i + tl - fl + 1, str + i + fl - fl + 1, sl - i - fl + 1 + 1);
                } else {
                    sl += (tl - fl);
                    str = prealloc(pool, str, sl);
                    memmove(str + i + tl - fl - 1, str + i - 1, sl - i + 1 + 1);
                    memcpy(str + i - fl + 1, to, tl);
                }
                i += (tl - fl);
                ml = 0;
            }
        } else ml = 0;
    }
    return str;
}


int str_isunum(const char* str) {
    if (str == NULL) return 0;
    size_t len = strlen(str);
    if (len < 1) return 0;
    for (int i = 0; i < len; i++) {
        if (str[i] < '0' || str[i] > '9') {
            return 0;
        }
    }
    return 1;
}

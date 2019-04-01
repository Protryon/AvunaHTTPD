/*
 * xstring.h
 *
 *  Created on: Nov 17, 2015
 *      Author: root
 */

#ifndef XSTRING_H_
#define XSTRING_H_

#include <avuna/pmem.h>
#include <avuna/list.h>
#include <avuna/hash.h>
#include <string.h>
#include <stdlib.h>

char* str_trim(char* str);

int str_eq_case(const char* str1, const char* str2);

int str_eq(const char* str1, const char* str2);

int str_prefixes_case(const char* str, const char* with);

int str_prefixes(const char* str, const char* with);

int str_suffixes_case(const char* str, const char* with);

int str_suffixes(const char* str, const char* with);

int str_contains_case(const char* str, const char* with);

int str_contains(const char* str, const char* with);

char* str_tolower(char* str);

char* str_toupper(char* str);

char* str_urlencode(char* str, struct mempool* pool); // must be freed and str must be on heap

char* str_urldecode(char* str);

char* str_replace(char* str, char* from, char* to,
                  struct mempool* pool); // when strlen(to) > strlen(from), str MUST be heap allocated!

char* str_replace_case(char* str, char* from, char* to, struct mempool* pool);

// warning: both split functions here modify the string `str`
void str_split(char* str, char* delim, struct list* out);

void str_split_case(char* str, char* delim, struct list* out);

void str_split_set(char* str, char* delim, struct hashset* out);

void str_split_set_case(char* str, char* delim, struct hashset* out);

int str_isunum(const char* str);

char* str_dup(char* str, ssize_t expand, struct mempool* pool);

#endif /* XSTRING_H_ */

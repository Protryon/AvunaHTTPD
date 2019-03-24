
#ifndef OVERRIDE_H_
#define OVERRIDE_H_

#include <stdlib.h> 
#include "http.h"

#define OD_ACCEPTPATHINFO 0 // On|Off|Default
//^ Resources accept trailing pathname information
#define OD_ACTION 1 // action-type cgi-script [virtual]
//^ Activates a CGI script for a particular handler or content-type
#define OD_ADDALT 2 // string file [file] ...
//^ Alternate text to display for a file, instead of an icon selected by filename
#define OD_ADDALTBYENCODING 3 // string MIME-encoding [MIME-encoding] ...
//^ Alternate text to display for a file instead of an icon selected by MIME-encoding
#define OD_ADDALTBYTYPE 4 // string MIME-type [MIME-type] ...
//^ Alternate text to display for a file, instead of an icon selected by MIME content-type
#define OD_ADDCHARSET 5 // charset extension [extension] ...
//^ Maps the given filename extensions to the specified content charset
#define OD_ADDDEFAULTCHARSET 6 // On|Off|charset
//^ Default charset parameter to be added when a response content-type is text/plain or text/html
#define OD_ADDDESCRIPTION 7 // string file [file] ...
//^ Description to display for a file
#define OD_ADDENCODING 8 // encoding extension [extension] ...
//^ Maps the given filename extensions to the specified encoding type
#define OD_ADDHANDLER 9 // handler-name extension [extension] ...
//^ Maps the filename extensions to the specified handler
#define OD_ADDICON 10 // icon name [name] ...
//^ Icon to display for a file selected by name
#define OD_ADDICONBYENCODING 11 // icon MIME-encoding [MIME-encoding] ...
//^ Icon to display next to files selected by MIME content-encoding
#define OD_ADDICONBYTYPE 12 // icon MIME-type [MIME-type] ...
//^ Icon to display next to files selected by MIME content-type
#define OD_ADDINPUTFILTER 13 // filter[;filter...] extension [extension] ...
//^ Maps filename extensions to the filters that will process client requests
#define OD_ADDLANGUAGE 14 // language-tag extension [extension] ...
//^ Maps the given filename extension to the specified content language
#define OD_ADDOUTPUTFILTER 15 // filter[;filter...] extension [extension] ...
//^ Maps filename extensions to the filters that will process responses from the server
#define OD_ADDOUTPUTFILTERBYTYPE 16 // filter[;filter...] media-type [media-type] ...
//^ assigns an output filter to a particular media-type
#define OD_ADDTYPE 17 // media-type extension [extension] ...
//^ Maps the given filename extensions onto the specified content type
#define OD_ALLOW 18 // from all|host|env=[!]env-variable [host|env=[!]env-variable] ...
//^ Controls which hosts can access an area of the server
#define OD_ANONYMOUS 19 // user [user] ...
//^ Specifies userIDs that are allowed access without password verification
#define OD_ANONYMOUS_LOGEMAIL 20 // On|Off
//^ Sets whether the password entered will be logged in the error log
#define OD_ANONYMOUS_MUSTGIVEEMAIL 21 // On|Off
//^ Specifies whether blank passwords are allowed
#define OD_ANONYMOUS_NOUSERID 22 // On|Off
//^ Sets whether the userID field may be empty
#define OD_ANONYMOUS_VERIFYEMAIL 23 // On|Off
//^ Sets whether to check the password field for a correctly formatted email address
#define OD_AUTHBASICAUTHORITATIVE 24 // On|Off
//^ Sets whether authorization and authentication are passed to lower level modules
#define OD_AUTHBASICFAKE 25 // off|username [password]
//^ Fake basic authentication using the given expressions for username and password
#define OD_AUTHBASICPROVIDER 26 // provider-name [provider-name] ...
//^ Sets the authentication provider(s) for this location
#define OD_AUTHBASICUSEDIGESTALGORITHM 27 // MD5|Off
//^ Check passwords against the authentication providers as if Digest Authentication was in force instead of Basic Authentication.
#define OD_AUTHDBMGROUPFILE 28 // file-path
//^ Sets the name of the database file containing the list of user groups for authorization
#define OD_AUTHDBMTYPE 29 // default|SDBM|GDBM|NDBM|DB
//^ Sets the type of database file that is used to store passwords
#define OD_AUTHDBMUSERFILE 30 // file-path
//^ Sets the name of a database file containing the list of users and passwords for authentication
#define OD_AUTHDIGESTALGORITHM 31 // MD5|MD5-sess
//^ Selects the algorithm used to calculate the challenge and response hashes in digest authentication
#define OD_AUTHDIGESTDOMAIN 32 // URI [URI] ...
//^ URIs that are in the same protection space for digest authentication
#define OD_AUTHDIGESTNONCELIFETIME 33 // seconds
//^ How long the server nonce is valid
#define OD_AUTHDIGESTPROVIDER 34 // provider-name [provider-name] ...
//^ Sets the authentication provider(s) for this location
#define OD_AUTHDIGESTQOP 35 // none|auth|auth-int [auth|auth-int]
//^ Determines the quality-of-protection to use in digest authentication
#define OD_AUTHFORMAUTHORITATIVE 36 // On|Off
//^ Sets whether authorization and authentication are passed to lower level modules
#define OD_AUTHFORMPROVIDER 37 // provider-name [provider-name] ...
//^ Sets the authentication provider(s) for this location
#define OD_AUTHGROUPFILE 38 // file-path
//^ Sets the name of a text file containing the list of user groups for authorization
#define OD_AUTHLDAPAUTHORIZEPREFIX 39 // prefix
//^ Specifies the prefix for environment variables set during authorization
#define OD_AUTHLDAPBINDAUTHORITATIVE 40 // off|on
//^ Determines if other authentication providers are used when a user can be mapped to a DN but the server cannot successfully bind with the user's credentials.
#define OD_AUTHLDAPBINDDN 41 // distinguished-name
//^ Optional DN to use in binding to the LDAP server
#define OD_AUTHLDAPBINDPASSWORD 42 // password
//^ Password used in conjuction with the bind DN
#define OD_AUTHLDAPCOMPAREASUSER 43 // on|off
//^ Use the authenticated user's credentials to perform authorization comparisons
#define OD_AUTHLDAPCOMPAREDNONSERVER 44 // on|off
//^ Use the LDAP server to compare the DNs
#define OD_AUTHLDAPDEREFERENCEALIASES 45 // never|searching|finding|always
//^ When will the module de-reference aliases
#define OD_AUTHLDAPGROUPATTRIBUTE 46 // attribute
//^ LDAP attributes used to identify the user members of groups.
#define OD_AUTHLDAPGROUPATTRIBUTEISDN 47 // on|off
//^ Use the DN of the client username when checking for group membership
#define OD_AUTHLDAPINITIALBINDASUSER 48 // off|on
//^ Determines if the server does the initial DN lookup using the basic authentication users' own username, instead of anonymously or with hard-coded credentials for the server
#define OD_AUTHLDAPINITIALBINDPATTERN 49 // regex substitution
//^ Specifies the transformation of the basic authentication username to be used when binding to the LDAP server to perform a DN lookup
#define OD_AUTHLDAPMAXSUBGROUPDEPTH 50 // Number
//^ Specifies the maximum sub-group nesting depth that will be evaluated before the user search is discontinued.
#define OD_AUTHLDAPREMOTEUSERATTRIBUTE 51 // uid
//^ Use the value of the attribute returned during the user query to set the REMOTE_USER environment variable
#define OD_AUTHLDAPREMOTEUSERISDN 52 // on|off
//^ Use the DN of the client username to set the REMOTE_USER environment variable
#define OD_AUTHLDAPSEARCHASUSER 53 // on|off
//^ Use the authenticated user's credentials to perform authorization searches
#define OD_AUTHLDAPSUBGROUPATTRIBUTE 54 // attribute
//^ Specifies the attribute labels, one value per directive line, used to distinguish the members of the current group that are groups.
#define OD_AUTHLDAPSUBGROUPCLASS 55 // LdapObjectClass
//^ Specifies which LDAP objectClass values identify directory objects that are groups during sub-group processing.
#define OD_AUTHLDAPURL 56 // url [NONE|SSL|TLS|STARTTLS]
//^ URL specifying the LDAP search parameters
#define OD_AUTHMERGING 57 // Off | And | Or
//^ Controls the manner in which each configuration section's authorization logic is combined with that of preceding configuration sections.
#define OD_AUTHNAME 58 // auth-domain
//^ Authorization realm for use in HTTP authentication
#define OD_AUTHNCACHEPROVIDEFOR 59 // authn-provider [...]
//^ Specify which authn provider(s) to cache for
#define OD_AUTHNCACHETIMEOUT 60 // timeout (seconds)
//^ Set a timeout for cache entries
#define OD_AUTHTYPE 61 // None|Basic|Digest|Form
//^ Type of user authentication
#define OD_AUTHUSERFILE 62 // file-path
//^ Sets the name of a text file containing the list of users and passwords for authentication
#define OD_AUTHZDBMTYPE 63 // default|SDBM|GDBM|NDBM|DB
//^ Sets the type of database file that is used to store list of user groups
#define OD_AUTHZSENDFORBIDDENONFAILURE 64 // On|Off
//^ Send '403 FORBIDDEN' instead of '401 UNAUTHORIZED' if authentication succeeds but authorization fails
#define OD_BROWSERMATCH 65 // regex [!]env-variable[=value] [[!]env-variable[=value]] ...
//^ Sets environment variables conditional on HTTP User-Agent
#define OD_BROWSERMATCHNOCASE 66 // regex [!]env-variable[=value] [[!]env-variable[=value]] ...
//^ Sets environment variables conditional on User-Agent without respect to case
#define OD_BUFFERSIZE 67 // integer
//^ Maximum size in bytes to buffer by the buffer filter
#define OD_CACHEDEFAULTEXPIRE 68 // seconds
//^ The default duration to cache a document when no expiry date is specified.
#define OD_CACHEDETAILHEADER 69 // on|off
//^ Add an X-Cache-Detail header to the response.
#define OD_CACHEDISABLE 70 // url-string | on
//^ Disable caching of specified URLs
#define OD_CACHEHEADER 71 // on|off
//^ Add an X-Cache header to the response.
#define OD_CACHEIGNORENOLASTMOD 72 // On|Off
//^ Ignore the fact that a response has no Last Modified header.
#define OD_CACHELASTMODIFIEDFACTOR 73 // float
//^ The factor used to compute an expiry date based on the LastModified date.
#define OD_CACHEMAXEXPIRE 74 // seconds
//^ The maximum time in seconds to cache a document
#define OD_CACHEMAXFILESIZE 75 // bytes
//^ The maximum size (in bytes) of a document to be placed in the cache
#define OD_CACHEMINEXPIRE 76 // seconds
//^ The minimum time in seconds to cache a document
#define OD_CACHEMINFILESIZE 77 // bytes
//^ The minimum size (in bytes) of a document to be placed in the cache
#define OD_CACHEREADSIZE 78 // bytes
//^ The minimum size (in bytes) of the document to read and be cached before sending the data downstream
#define OD_CACHEREADTIME 79 // milliseconds
//^ The minimum time (in milliseconds) that should elapse while reading before data is sent downstream
#define OD_CACHESOCACHEMAXSIZE 80 // bytes
//^ The maximum size (in bytes) of an entry to be placed in the cache
#define OD_CACHESOCACHEMAXTIME 81 // seconds
//^ The maximum time (in seconds) for a document to be placed in the cache
#define OD_CACHESOCACHEMINTIME 82 // seconds
//^ The minimum time (in seconds) for a document to be placed in the cache
#define OD_CACHESOCACHEREADSIZE 83 // bytes
//^ The minimum size (in bytes) of the document to read and be cached before sending the data downstream
#define OD_CACHESOCACHEREADTIME 84 // milliseconds
//^ The minimum time (in milliseconds) that should elapse while reading before data is sent downstream
#define OD_CACHESTALEONERROR 85 // on|off
//^ Serve stale content in place of 5xx responses.
#define OD_CACHESTOREEXPIRED 86 // On|Off
//^ Attempt to cache responses that the server reports as expired
#define OD_CACHESTORENOSTORE 87 // On|Off
//^ Attempt to cache requests or responses that have been marked as no-store.
#define OD_CACHESTOREPRIVATE 88 // On|Off
//^ Attempt to cache responses that the server has marked as private
#define OD_CGIDSCRIPTTIMEOUT 89 // time[s|ms]
//^ The length of time to wait for more output from the CGI program
#define OD_CGIMAPEXTENSION 90 // cgi-path .extension
//^ Technique for locating the interpreter for CGI scripts
#define OD_CGIPASSAUTH 91 // On|Off
//^ Enables passing HTTP authorization headers to scripts as CGI variables
#define OD_CGIVAR 92 // variable rule
//^ Controls how some CGI variables are set
#define OD_CHARSETDEFAULT 93 // charset
//^ Charset to translate into
#define OD_CHARSETOPTIONS 94 // option [option] ...
//^ Configures charset translation behavior
#define OD_CHARSETSOURCEENC 95 // charset
//^ Source charset of files
#define OD_CHECKCASEONLY 96 // on|off
//^ Limits the action of the speling module to case corrections
#define OD_CHECKSPELLING 97 // on|off
//^ Enables the spelling module
#define OD_CONTENTDIGEST 98 // On|Off
//^ Enables the generation of Content-MD5 HTTP Response headers
#define OD_COOKIEDOMAIN 99 // domain
//^ The domain to which the tracking cookie applies
#define OD_COOKIEEXPIRES 100 // expiry-period
//^ Expiry time for the tracking cookie
#define OD_COOKIENAME 101 // token
//^ Name of the tracking cookie
#define OD_COOKIESTYLE 102 // Netscape|Cookie|Cookie2|RFC2109|RFC2965
//^ Format of the cookie header field
#define OD_COOKIETRACKING 103 // on|off
//^ Enables tracking cookie
#define OD_DEFAULTICON 104 // url-path
//^ Icon to display for files when no specific icon is configured
#define OD_DEFAULTLANGUAGE 105 // language-tag
//^ Defines a default language-tag to be sent in the Content-Language header field for all resources in the current context that have not been assigned a language-tag by some other means.
#define OD_DEFAULTTYPE 106 // media-type|none
//^ This directive has no effect other than to emit warnings if the value is not none. In prior versions, DefaultType would specify a default media type to assign to response content for which no other media type configuration could be found.
#define OD_DEFLATEINFLATELIMITREQUESTBODYVALUE 107 // 
//^ Maximum size of inflated request bodies
#define OD_DEFLATEINFLATERATIOBURST 108 // value
//^ Maximum number of times the inflation ratio for request bodies can be crossed
#define OD_DEFLATEINFLATERATIOLIMIT 109 // value
//^ Maximum inflation ratio for request bodies
#define OD_DENY 110 // from all|host|env=[!]env-variable [host|env=[!]env-variable] ...
//^ Controls which hosts are denied access to the server
#define OD_DIRECTORYCHECKHANDLER 111 // On|Off
//^ Toggle how this module responds when another handler is configured
#define OD_DIRECTORYINDEX 112 // disabled | local-url [local-url] ...
//^ List of resources to look for when the client requests a directory
#define OD_DIRECTORYINDEXREDIRECT 113 // on | off | permanent | temp | seeother | 3xx-code
//^ Configures an external redirect for directory indexes.
#define OD_DIRECTORYSLASH 114 // On|Off
//^ Toggle trailing slash redirects on or off
#define OD_START_ELSE 115
#define OD_END_ELSE 116
//^ Contains directives that apply only if the condition of a previous <If> or <ElseIf> section is not satisfied by a request at runtime
#define OD_START_ELSEI 117
#define OD_END_ELSEI 118
//^ Contains directives that apply only if a condition is satisfied by a request at runtime while the condition of a previous <If> or <ElseIf> section is not satisfied
#define OD_ENABLEMMAP 119 // On|Off
//^ Use memory-mapping to read files during delivery
#define OD_ENABLESENDFILE 120 // On|Off
//^ Use the kernel sendfile support to deliver files to the client
#define OD_ERROR 121 // message
//^ Abort configuration parsing with a custom error message
#define OD_ERRORDOCUMENT 122 // error-code document
//^ What the server will return to the client in case of an error
#define OD_EXAMPLE 123 // 
//^ Demonstration directive to illustrate the Apache module API
#define OD_EXPIRESACTIVE 124 // On|Off
//^ Enables generation of Expires headers
#define OD_EXPIRESBYTYPE 125 // MIME-type <code>seconds
//^ Value of the Expires header configured by MIME type
#define OD_EXPIRESDEFAULT 126 // <code>seconds
//^ Default algorithm for calculating expiration time
#define OD_FALLBACKRESOURCE 127 // disabled | local-url
//^ Define a default URL for requests that don't map to a file
#define OD_FILEETAG 128 // component ...
//^ File attributes used to create the ETag HTTP response header for static files
#define OD_START_FILE 129
#define OD_END_FILE 130
//^ Contains directives that apply to matched filenames
#define OD_START_FILESMATC 131
#define OD_END_FILESMATC 132
//^ Contains directives that apply to regular-expression matched filenames
#define OD_FILTERCHAIN 133 // [+=-@!]filter-name ...
//^ Configure the filter chain
#define OD_FILTERDECLARE 134 // filter-name [type]
//^ Declare a smart filter
#define OD_FILTERPROTOCOL 135 // filter-name [provider-name] proto-flags
//^ Deal with correct HTTP protocol handling
#define OD_FILTERPROVIDER 136 // filter-name provider-name expression
//^ Register a content filter
#define OD_FORCELANGUAGEPRIORITY 137 // None|Prefer|Fallback [Prefer|Fallback]
//^ Action to take if a single acceptable document is not found
#define OD_FORCETYPE 138 // media-type|None
//^ Forces all matching files to be served with the specified media type in the HTTP Content-Type header field
#define OD_H2COPYFILES 139 // on|off
//^ Determine file handling in responses
#define OD_H2PUSHRESOURCE 140 // [add] path [critical]
//^ Declares resources for early pushing to the client
#define OD_HEADER 141 // [condition] add|append|echo|edit|edit*|merge|set|setifempty|unset|note header [[expr=]value [replacement] [early|env=[!]varname|expr=expression]]
//^ Configure HTTP response headers
#define OD_HEADERNAME 142 // filename
//^ Name of the file that will be inserted at the top of the index listing
#define OD_START_I 143
#define OD_END_I 144
//^ Contains directives that apply only if a condition is satisfied by a request at runtime
#define OD_START_IFDEFIN 145
#define OD_END_IFDEFIN 146
//^ Encloses directives that will be processed only if a test is true at startup
#define OD_START_IFMODUL 147
#define OD_END_IFMODUL 148
//^ Encloses directives that are processed conditional on the presence or absence of a specific module
#define OD_START_IFVERSIO 149
#define OD_END_IFVERSIO 150
//^ contains version dependent configuration
#define OD_IMAPBASE 151 // map|referer|URL
//^ Default base for imagemap files
#define OD_IMAPDEFAULT 152 // error|nocontent|map|referer|URL
//^ Default action when an imagemap is called with coordinates that are not explicitly mapped
#define OD_IMAPMENU 153 // none|formatted|semiformatted|unformatted
//^ Action if no coordinates are given when calling an imagemap
#define OD_INDEXHEADINSERT 154 // "markup ..."
//^ Inserts text in the HEAD section of an index page.
#define OD_INDEXIGNORE 155 // file [file] ...
//^ Adds to the list of files to hide when listing a directory
#define OD_INDEXIGNORERESET 156 // ON|OFF
//^ Empties the list of files to hide when listing a directory
#define OD_INDEXOPTIONS 157 // [+|-]option [[+|-]option] ...
//^ Various configuration settings for directory indexing
#define OD_INDEXORDERDEFAULT 158 // Ascending|Descending Name|Date|Size|Description
//^ Sets the default ordering of the directory index
#define OD_INDEXSTYLESHEET 159 // url-path
//^ Adds a CSS stylesheet to the directory index
#define OD_INPUTSED 160 // sed-command
//^ Sed command to filter request data (typically POST data)
#define OD_ISAPIAPPENDLOGTOERRORS 161 // on|off
//^ Record HSE_APPEND_LOG_PARAMETER requests from ISAPI extensions to the error log
#define OD_ISAPIAPPENDLOGTOQUERY 162 // on|off
//^ Record HSE_APPEND_LOG_PARAMETER requests from ISAPI extensions to the query field
#define OD_ISAPIFAKEASYNC 163 // on|off
//^ Fake asynchronous support for ISAPI callbacks
#define OD_ISAPILOGNOTSUPPORTED 164 // on|off
//^ Log unsupported feature requests from ISAPI extensions
#define OD_ISAPIREADAHEADBUFFER 165 // size
//^ Size of the Read Ahead Buffer sent to ISAPI extensions
#define OD_LANGUAGEPRIORITY 166 // MIME-lang [MIME-lang] ...
//^ The precedence of language variants for cases where the client does not express a preference
#define OD_LDAPREFERRALHOPLIMIT 167 // number
//^ The maximum number of referral hops to chase before terminating an LDAP query.
#define OD_LDAPREFERRALS 168 // On|Off|default
//^ Enable referral chasing during queries to the LDAP server.
#define OD_LDAPTRUSTEDCLIENTCERT 169 // type directory-path/filename/nickname [password]
//^ Sets the file containing or nickname referring to a per connection client certificate. Not all LDAP toolkits support per connection client certificates.
#define OD_START_LIMI 170
#define OD_END_LIMI 171
//^ Restrict enclosed access controls to only certain HTTP methods
#define OD_START_LIMITEXCEP 172
#define OD_END_LIMITEXCEP 173
//^ Restrict access controls to all HTTP methods except the named ones
#define OD_LIMITREQUESTBODY 174 // bytes
//^ Restricts the total size of the HTTP request body sent from the client
#define OD_LIMITXMLREQUESTBODY 175 // bytes
//^ Limits the size of an XML-based request body
#define OD_LOGIOTRACKTTFB 176 // ON|OFF
//^ Enable tracking of time to first byte (TTFB)
#define OD_LUACODECACHE 177 // stat|forever|never
//^ Configure the compiled code cache.
#define OD_LUAHOOKACCESSCHECKER 178 // /path/to/lua/script.lua hook_function_name [early|late]
//^ Provide a hook for the access_checker phase of request processing
#define OD_LUAHOOKAUTHCHECKER 179 // /path/to/lua/script.lua hook_function_name [early|late]
//^ Provide a hook for the auth_checker phase of request processing
#define OD_LUAHOOKCHECKUSERID 180 // /path/to/lua/script.lua hook_function_name [early|late]
//^ Provide a hook for the check_user_id phase of request processing
#define OD_LUAHOOKFIXUPS 181 // /path/to/lua/script.lua hook_function_name
//^ Provide a hook for the fixups phase of a request processing
#define OD_LUAHOOKINSERTFILTER 182 // /path/to/lua/script.lua hook_function_name
//^ Provide a hook for the insert_filter phase of request processing
#define OD_LUAHOOKLOG 183 // /path/to/lua/script.lua log_function_name
//^ Provide a hook for the access log phase of a request processing
#define OD_LUAHOOKMAPTOSTORAGE 184 // /path/to/lua/script.lua hook_function_name
//^ Provide a hook for the map_to_storage phase of request processing
#define OD_LUAHOOKTYPECHECKER 185 // /path/to/lua/script.lua hook_function_name
//^ Provide a hook for the type_checker phase of request processing
#define OD_LUAINHERIT 186 // none|parent-first|parent-last
//^ Controls how parent configuration sections are merged into children
#define OD_LUAMAPHANDLER 187 // uri-pattern /path/to/lua/script.lua [function-name]
//^ Map a path to a lua handler
#define OD_LUAPACKAGECPATH 188 // /path/to/include/?.soa
//^ Add a directory to lua's package.cpath
#define OD_LUAPACKAGEPATH 189 // /path/to/include/?.lua
//^ Add a directory to lua's package.path
#define OD_LUAROOT 190 // /path/to/a/directory
//^ Specify the base path for resolving relative paths for mod_lua directives
#define OD_LUASCOPE 191 // once|request|conn|thread|server [min] [max]
//^ One of once, request, conn, thread -- default is once
#define OD_METADIR 192 // directory
//^ Name of the directory to find CERN-style meta information files
#define OD_METAFILES 193 // on|off
//^ Activates CERN meta-file processing
#define OD_METASUFFIX 194 // suffix
//^ File name suffix for the file containing CERN-style meta information
#define OD_MULTIVIEWSMATCH 195 // Any|NegotiatedOnly|Filters|Handlers [Handlers|Filters]
//^ The types of files that will be included when searching for a matching file with MultiViews
#define OD_OPTIONS 196 // [+|-]option [[+|-]option] ...
//^ Configures what features are available in a particular directory
#define OD_ORDER 197 // ordering
//^ Controls the default access state and the order in which Allow and Deny are evaluated.
#define OD_OUTPUTSED 198 // sed-command
//^ Sed command for filtering response content
#define OD_PASSENV 199 // env-variable [env-variable] ...
//^ Passes environment variables from the shell
#define OD_READMENAME 200 // filename
//^ Name of the file that will be inserted at the end of the index listing
#define OD_REDIRECT 201 // [status] [URL-path] URL
//^ Sends an external redirect asking the client to fetch a different URL
#define OD_REDIRECTMATCH 202 // [status] regex URL
//^ Sends an external redirect based on a regular expression match of the current URL
#define OD_REDIRECTPERMANENT 203 // URL-path URL
//^ Sends an external permanent redirect asking the client to fetch a different URL
#define OD_REDIRECTTEMP 204 // URL-path URL
//^ Sends an external temporary redirect asking the client to fetch a different URL
#define OD_REFLECTORHEADER 205 // inputheader [outputheader]
//^ Reflect an input header to the output headers
#define OD_REMOVECHARSET 206 // extension [extension] ...
//^ Removes any character set associations for a set of file extensions
#define OD_REMOVEENCODING 207 // extension [extension] ...
//^ Removes any content encoding associations for a set of file extensions
#define OD_REMOVEHANDLER 208 // extension [extension] ...
//^ Removes any handler associations for a set of file extensions
#define OD_REMOVEINPUTFILTER 209 // extension [extension] ...
//^ Removes any input filter associations for a set of file extensions
#define OD_REMOVELANGUAGE 210 // extension [extension] ...
//^ Removes any language associations for a set of file extensions
#define OD_REMOVEOUTPUTFILTER 211 // extension [extension] ...
//^ Removes any output filter associations for a set of file extensions
#define OD_REMOVETYPE 212 // extension [extension] ...
//^ Removes any content type associations for a set of file extensions
#define OD_REQUESTHEADER 213 // add|append|edit|edit*|merge|set|setifempty|unset header [[expr=]value [replacement] [early|env=[!]varname|expr=expression]]
//^ Configure HTTP request headers
#define OD_REQUIRE 214 // [not] entity-name [entity-name] ...
//^ Tests whether an authenticated user is authorized by an authorization provider.
#define OD_START_REQUIREALL 215
#define OD_END_REQUIREALL 216
//^ Enclose a group of authorization directives of which none must fail and at least one must succeed for the enclosing directive to succeed.
#define OD_START_REQUIREANY 217
#define OD_END_REQUIREANY 218
//^ Enclose a group of authorization directives of which one must succeed for the enclosing directive to succeed.
#define OD_START_REQUIRENONE 219
#define OD_END_REQUIRENONE 220
//^ Enclose a group of authorization directives of which none must succeed for the enclosing directive to not fail.
#define OD_REWRITEBASE 221 // URL-path
//^ Sets the base URL for per-directory rewrites
#define OD_REWRITECOND 222 // TestString CondPattern [flags]
//^ Defines a condition under which rewriting will take place
#define OD_REWRITEENGINE 223 // on|off
//^ Enables or disables runtime rewriting engine
#define OD_REWRITEOPTIONS 224 // Options
//^ Sets some special options for the rewrite engine
#define OD_REWRITERULE 225 // Pattern Substitution [flags]
//^ Defines rules for the rewriting engine
#define OD_RLIMITCPU 226 // seconds|max [seconds|max]
//^ Limits the CPU consumption of processes launched by Apache httpd children
#define OD_RLIMITMEM 227 // bytes|max [bytes|max]
//^ Limits the memory consumption of processes launched by Apache httpd children
#define OD_RLIMITNPROC 228 // number|max [number|max]
//^ Limits the number of processes that can be launched by processes launched by Apache httpd children
#define OD_SATISFY 229 // Any|All
//^ Interaction between host-level access control and user authentication
#define OD_SCRIPTINTERPRETERSOURCE 230 // Registry|Registry-Strict|Script
//^ Technique for locating the interpreter for CGI scripts
#define OD_SERVERSIGNATURE 231 // On|Off|EMail
//^ Configures the footer on server-generated documents
#define OD_SESSION 232 // On|Off
//^ Enables a session for the current directory or location
#define OD_SESSIONCOOKIENAME 233 // name attributes
//^ Name and attributes for the RFC2109 cookie storing the session
#define OD_SESSIONCOOKIENAME2 234 // name attributes
//^ Name and attributes for the RFC2965 cookie storing the session
#define OD_SESSIONCOOKIEREMOVE 235 // On|Off
//^ Control for whether session cookies should be removed from incoming HTTP headers
#define OD_SESSIONCRYPTOCIPHER 236 // name
//^ The crypto cipher to be used to encrypt the session
#define OD_SESSIONCRYPTOPASSPHRASE 237 // secret [ secret ... ]
//^ The key used to encrypt the session
#define OD_SESSIONDBDCOOKIENAME 238 // name attributes
//^ Name and attributes for the RFC2109 cookie storing the session ID
#define OD_SESSIONDBDCOOKIENAME2 239 // name attributes
//^ Name and attributes for the RFC2965 cookie storing the session ID
#define OD_SESSIONDBDCOOKIEREMOVE 240 // On|Off
//^ Control for whether session ID cookies should be removed from incoming HTTP headers
#define OD_SESSIONDBDDELETELABEL 241 // label
//^ The SQL query to use to remove sessions from the database
#define OD_SESSIONDBDINSERTLABEL 242 // label
//^ The SQL query to use to insert sessions into the database
#define OD_SESSIONDBDPERUSER 243 // On|Off
//^ Enable a per user session
#define OD_SESSIONDBDSELECTLABEL 244 // label
//^ The SQL query to use to select sessions from the database
#define OD_SESSIONDBDUPDATELABEL 245 // label
//^ The SQL query to use to update existing sessions in the database
#define OD_SESSIONENV 246 // On|Off
//^ Control whether the contents of the session are written to the HTTP_SESSION environment variable
#define OD_SESSIONEXCLUDE 247 // path
//^ Define URL prefixes for which a session is ignored
#define OD_SESSIONHEADER 248 // header
//^ Import session updates from a given HTTP response header
#define OD_SESSIONINCLUDE 249 // path
//^ Define URL prefixes for which a session is valid
#define OD_SESSIONMAXAGE 250 // maxage
//^ Define a maximum age in seconds for a session
#define OD_SETENV 251 // env-variable [value]
//^ Sets environment variables
#define OD_SETENVIF 252 // attribute regex [!]env-variable[=value] [[!]env-variable[=value]] ...
//^ Sets environment variables based on attributes of the request
#define OD_SETENVIFEXPR 253 // expr [!]env-variable[=value] [[!]env-variable[=value]] ...
//^ Sets environment variables based on an ap_expr expression
#define OD_SETENVIFNOCASE 254 // attribute regex [!]env-variable[=value] [[!]env-variable[=value]] ...
//^ Sets environment variables based on attributes of the request without respect to case
#define OD_SETHANDLER 255 // handler-name|none|expression
//^ Forces all matching files to be processed by a handler
#define OD_SETINPUTFILTER 256 // filter[;filter...]
//^ Sets the filters that will process client requests and POST input
#define OD_SETOUTPUTFILTER 257 // filter[;filter...]
//^ Sets the filters that will process responses from the server
#define OD_SSIERRORMSG 258 // message
//^ Error message displayed when there is an SSI error
#define OD_SSIETAG 259 // on|off
//^ Controls whether ETags are generated by the server.
#define OD_SSILASTMODIFIED 260 // on|off
//^ Controls whether Last-Modified headers are generated by the server.
#define OD_SSILEGACYEXPRPARSER 261 // on|off
//^ Enable compatibility mode for conditional expressions.
#define OD_SSITIMEFORMAT 262 // formatstring
//^ Configures the format in which date strings are displayed
#define OD_SSIUNDEFINEDECHO 263 // string
//^ String displayed when an unset variable is echoed
#define OD_SSLCIPHERSUITE 264 // cipher-spec
//^ Cipher Suite available for negotiation in SSL handshake
#define OD_SSLOPTIONS 265 // [+|-]option ...
//^ Configure various SSL engine run-time options
#define OD_SSLPROXYCIPHERSUITE 266 // cipher-spec
//^ Cipher Suite available for negotiation in SSL proxy handshake
#define OD_SSLRENEGBUFFERSIZE 267 // bytes
//^ Set the size for the SSL renegotiation buffer
#define OD_SSLREQUIRE 268 // expression
//^ Allow access only when an arbitrarily complex boolean expression is true
#define OD_SSLREQUIRESSL 269 // 
//^ Deny access when SSL is not used for the HTTP request
#define OD_SSLUSERNAME 270 // varname
//^ Variable name to determine user name
#define OD_SSLVERIFYCLIENT 271 // level
//^ Type of Client Certificate verification
#define OD_SSLVERIFYDEPTH 272 // number
//^ Maximum depth of CA Certificates in Client Certificate verification
#define OD_SUBSTITUTE 273 // s/pattern/substitution/[infq]
//^ Pattern to filter the response content
#define OD_SUBSTITUTEINHERITBEFORE 274 // on|off
//^ Change the merge order of inherited patterns
#define OD_SUBSTITUTEMAXLINELENGTH 275 // bytes(b|B|k|K|m|M|g|G)
//^ Set the maximum line size
#define OD_UNSETENV 276 // env-variable [env-variable] ...
//^ Removes variables from the environment
#define OD_XBITHACK 277 // on|off|full
//^ Parse SSI directives in files with the execute bit set
#define OD_XML2ENCDEFAULT 278 // name
//^ Sets a default encoding to assume when absolutely no information can be automatically detected
#define OD_XML2STARTPARSE 279 // element [element ...]
//^ Advise the parser to skip leading junk.

struct directive { 
    int id;
    void** args;
    size_t argc;
};

struct override {
	struct directive** dirs;
	size_t directive_count;
};

struct override* readOverride(char* data);

void freeOverride(struct override* override);

void parseOverride(struct override* override, struct request_session* reqsess);

#endif

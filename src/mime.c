/*
 * mime.c
 *
 *  Created on: Nov 24, 2015
 *      Author: root
 */

#include <avuna/mime.h>
#include <avuna/string.h>
#include <avuna/globals.h>
#include <avuna/streams.h>
#include <fcntl.h>

int loadMimes(const char* file) {
    int fd = open(file, O_RDONLY);
    if (fd < 0) return -1;
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    mime_map = hashmap_new(128, global_pool);
    char line[1024];
    while (readLine(fd, line, 1024) >= 0) {
        char* tl = str_trim(line);
        char* nl = NULL;
        int x = 0;
        char* type = NULL;
        while ((nl = strchr(tl, ' ')) != NULL || strlen(tl) > 0) {
            if (nl != NULL) {
                nl[0] = 0;
                nl++;
            }
            char* new_tl = str_dup(tl, 0, global_pool);
            if (x++ == 0) {
                type = new_tl;
            } else {
                hashmap_put(mime_map, new_tl, type);
            }
            tl = nl == NULL ? tl + strlen(tl) : nl;
        }
    }
    close(fd);
    return 0;
}

char* getMimeForExt(char* ext) {
    if (ext == NULL) return NULL;
    return hashmap_get(mime_map, ext);
}

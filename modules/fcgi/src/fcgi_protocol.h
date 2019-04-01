/*
 * fcgi.h
 *
 *  Created on: Nov 26, 2015
 *      Author: root
 */

#ifndef FCGI_H_
#define FCGI_H_

#include <stdlib.h>
#include <stdint.h>
#include <avuna/pmem.h>
#include <avuna/buffer.h>

#define FCGI_VERSION_1 1
#define FCGI_BEGIN_REQUEST 1
#define FCGI_ABORT_REQUEST 2
#define FCGI_END_REQUEST 3
#define FCGI_PARAMS 4
#define FCGI_STDIN 5
#define FCGI_STDOUT 6
#define FCGI_STDERR 7
#define FCGI_DATA 8
#define FCGI_GET_VALUES 9
#define FCGI_GET_VALUES_RESULT 10
#define FCGI_UNKNOWN_TYPE 11

struct fcgi_frame {
    uint8_t type;
    uint16_t request_id;
    uint16_t len;
    void* data;
};

void fcgi_writeFrame(struct buffer* buffer, struct fcgi_frame* frame);

void fcgi_writeParam(struct buffer* buffer, uint16_t reqid, const char* name, const char* value);

ssize_t fcgi_readFrame(struct buffer* buffer, struct fcgi_frame* frame, struct mempool* pool);

#endif /* FCGI_H_ */

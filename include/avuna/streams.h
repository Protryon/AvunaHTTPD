/*
 * streams.h
 *
 *  Created on: Nov 17, 2015
 *      Author: root
 */

#ifndef STREAMS_H_
#define STREAMS_H_

#include <stdlib.h>

ssize_t readLine(int fd, char* line, size_t len);

ssize_t writeLine(int fd, char* line, size_t len);

#endif /* STREAMS_H_ */

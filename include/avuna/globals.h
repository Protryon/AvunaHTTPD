/*
 * globals.h
 *
 *  Created on: Nov 19, 2015
 *      Author: root
 */

#ifndef GLOBALS_H_
#define GLOBALS_H_

#include <avuna/pmem.h>
#include <avuna/config.h>
#include <avuna/log.h>

struct config* cfg;
struct logsess* delog;
struct mempool* global_pool;

#endif /* GLOBALS_H_ */

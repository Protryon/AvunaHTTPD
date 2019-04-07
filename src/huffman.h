//
// Created by p on 4/6/19.
//

#ifndef AVUNA_HTTPD_HUFFMAN_H
#define AVUNA_HTTPD_HUFFMAN_H

#include <avuna/pmem.h>

uint8_t* huffman_decode(struct mempool* pool, uint8_t* input, size_t length, size_t* out_length);

#endif //AVUNA_HTTPD_HUFFMAN_H

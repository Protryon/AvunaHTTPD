//
// Created by p on 2/26/19.
//

#include <avuna/pmem_hooks.h>
#include <unistd.h>

void close_hook(void* arg) {
    close((int) arg);
}

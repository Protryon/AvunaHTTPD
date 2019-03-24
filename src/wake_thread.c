//
// Created by p on 3/23/19.
//

#include "wake_thread.h"
#include "work.h"
#include <unistd.h>
#include <string.h>
#include <errno.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
void wake_thread(struct wake_thread_arg* arg) {
    size_t revolving_initial = 0;
    int onec = 1;
    while (1) {
        queue_block(arg->server->prepared_connections);
        size_t count = arg->work_params->count;
        size_t total = arg->server->prepared_connections->size;
        size_t initial = 0;
        if (total < count) {
            initial = revolving_initial % (count - total);
            revolving_initial += total;
        }
        for (size_t i = initial; i < count; ++i) {
            struct work_param* param = arg->work_params->data[i];
            if (write(param->pipes[1], &onec, 1) < 1) {
                errlog(param->server->logsess, "Failed to write to wakeup pipe! Connection may hang. %s", strerror(errno));
            }
        }
    }
}
#pragma clang diagnostic pop
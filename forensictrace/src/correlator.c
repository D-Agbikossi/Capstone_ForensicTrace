/*
 * correlator.c — link events into chains: same-PID lookback, then cross-process
 * links from a child event to the parent's recent fork/clone/vfork/execve.
 */
#include "forensictrace.h"

#include <string.h>

#define FT_LOOKBACK 200

static int is_spawn_syscall(const char *name)
{
    return strcmp(name, "fork") == 0 || strcmp(name, "vfork") == 0 ||
           strcmp(name, "clone") == 0 || strcmp(name, "execve") == 0 ||
           strcmp(name, "execveat") == 0;
}

void ft_correlate(FTContext *c)
{
    int i;
    int j;
    int limit;

    if (!c) {
        return;
    }

    for (i = 0; i < c->count; i++) {
        c->parent_event[i] = -1;
        limit = i - FT_LOOKBACK;
        if (limit < 0) {
            limit = 0;
        }

        for (j = i - 1; j >= limit; j--) {
            if (c->events[j].pid == c->events[i].pid) {
                c->parent_event[i] = j;
                break;
            }
        }

        if (c->parent_event[i] >= 0) {
            continue;
        }

        /* Cross-process: child event → parent's fork/clone/vfork (or execve on PPID). */
        for (j = i - 1; j >= limit; j--) {
            Event *parent_ev = &c->events[j];

            if (parent_ev->pid != c->events[i].ppid) {
                continue;
            }
            if (is_spawn_syscall(parent_ev->syscall)) {
                c->parent_event[i] = j;
                break;
            }
        }
    }
}

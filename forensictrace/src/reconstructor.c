/* reconstructor.c — print human-readable incident timeline to stdout. */
#include "forensictrace.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static const char *type_label(EventType t)
{
    switch (t) {
    case EV_PROCESS:
        return "process";
    case EV_FILE:
        return "file";
    case EV_NETWORK:
        return "network";
    default:
        return "other";
    }
}

void ft_reconstruct(FTContext *c)
{
    uint64_t duration_ms;
    uint64_t base;
    int i;

    if (!c) {
        return;
    }

    if (c->end_ns > c->start_ns) {
        duration_ms = (c->end_ns - c->start_ns) / 1000000ULL;
    } else {
        duration_ms = 0;
    }

    printf("=== ForensicTrace Reconstructed Timeline ===\n");
    printf("Config: %s | Events: %d | Duration: %" PRIu64 " ms\n\n",
           c->config, c->count, duration_ms);

    if (c->count == 0) {
        printf("(no events captured)\n");
        return;
    }

    base = c->events[0].ts_ns;

    printf("%-5s %-10s %-9s %-8s %-8s %-12s %s\n",
           "#", "Delta(ms)", "Type", "PID", "PPID", "Syscall", "Target");
    printf("---------------------------------------------------------------------------------\n");

    for (i = 0; i < c->count; i++) {
        Event *e = &c->events[i];
        double d = (double)(e->ts_ns - base) / 1e6;
        const char *target = e->target[0] ? e->target : e->detail;

        printf("%-5d %-10.3f %-9s %-8d %-8d %-12s %s\n",
               e->id, d, type_label(e->type), (int)e->pid, (int)e->ppid,
               e->syscall, target);
    }
    printf("---------------------------------------------------------------------------------\n");
}

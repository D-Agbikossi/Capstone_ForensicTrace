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
    uint64_t base_ts;
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

    printf("#     Delta(ms)  Type      PID      PPID     Syscall      Target\n");
    printf("---------------------------------------------------------------------------------\n");

    base_ts = c->events[0].ts_ns;
    for (i = 0; i < c->count; i++) {
        double delta_ms = (double)(c->events[i].ts_ns - base_ts) / 1e6;
        const Event *e = &c->events[i];

        printf("%-5d %-10.3f %-9s %-8d %-8d %-12s %s\n",
               e->id,
               delta_ms,
               type_label(e->type),
               (int)e->pid,
               (int)e->ppid,
               e->syscall,
               e->target[0] ? e->target : e->detail);
    }
    printf("---------------------------------------------------------------------------------\n");
}

const char *ft_event_type_str(EventType t)
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

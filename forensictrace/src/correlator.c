#include "forensictrace.h"

#define FT_LOOKBACK 200

void ft_correlate(FTContext *c)
{
    int i;
    int j;
    int start;

    if (!c) {
        return;
    }

    for (i = 0; i < c->count; i++) {
        c->parent_event[i] = -1;
        start = i - FT_LOOKBACK;
        if (start < 0) {
            start = 0;
        }
        for (j = i - 1; j >= start; j--) {
            if (c->events[j].pid == c->events[i].pid) {
                c->parent_event[i] = j;
                break;
            }
        }
    }
}

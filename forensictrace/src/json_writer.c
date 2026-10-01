#include "forensictrace.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static void json_escape(FILE *fp, const char *s)
{
    const unsigned char *p;

    if (!s) {
        return;
    }
    for (p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '"':
            fputs("\\\"", fp);
            break;
        case '\\':
            fputs("\\\\", fp);
            break;
        case '\b':
            fputs("\\b", fp);
            break;
        case '\f':
            fputs("\\f", fp);
            break;
        case '\n':
            fputs("\\n", fp);
            break;
        case '\r':
            fputs("\\r", fp);
            break;
        case '\t':
            fputs("\\t", fp);
            break;
        default:
            if (*p < 0x20) {
                fprintf(fp, "\\u%04x", *p);
            } else {
                fputc(*p, fp);
            }
            break;
        }
    }
}

void ft_write_json(FTContext *c)
{
    FILE *fp;
    long pos;
    int i;

    if (!c || !c->output_path[0]) {
        return;
    }

    fp = fopen(c->output_path, "w");
    if (!fp) {
        perror("fopen");
        return;
    }

    fprintf(fp, "{\n");
    fprintf(fp, "  \"config\": \"");
    json_escape(fp, c->config);
    fprintf(fp, "\",\n");
    fprintf(fp, "  \"event_count\": %d,\n", c->count);

    if (c->end_ns > c->start_ns) {
        fprintf(fp, "  \"duration_ns\": %" PRIu64 ",\n",
                c->end_ns - c->start_ns);
    } else {
        fprintf(fp, "  \"duration_ns\": 0,\n");
    }

    fprintf(fp, "  \"events\": [\n");
    for (i = 0; i < c->count; i++) {
        const Event *e = &c->events[i];
        int parent = c->parent_event[i];

        fprintf(fp, "    {\n");
        fprintf(fp, "      \"id\": %d,\n", e->id);
        fprintf(fp, "      \"ts_ns\": %" PRIu64 ",\n", e->ts_ns);
        fprintf(fp, "      \"type\": \"");
        json_escape(fp, ft_event_type_str(e->type));
        fprintf(fp, "\",\n");
        fprintf(fp, "      \"syscall\": \"");
        json_escape(fp, e->syscall);
        fprintf(fp, "\",\n");
        fprintf(fp, "      \"pid\": %d,\n", (int)e->pid);
        fprintf(fp, "      \"ppid\": %d,\n", (int)e->ppid);
        fprintf(fp, "      \"target\": \"");
        json_escape(fp, e->target);
        fprintf(fp, "\",\n");
        fprintf(fp, "      \"detail\": \"");
        json_escape(fp, e->detail);
        fprintf(fp, "\",\n");
        fprintf(fp, "      \"parent_event\": %d\n", parent);
        fprintf(fp, "    }%s\n", (i + 1 < c->count) ? "," : "");
    }
    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");

    fflush(fp);
    pos = ftell(fp);
    if (pos >= 0) {
        c->storage_bytes = pos;
    }
    fclose(fp);
}

/* json_writer.c — serialise experiment + events + parent_event indices to JSON. */
#include "forensictrace.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static const char *type_name(EventType t)
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

static void json_escape(FILE *f, const char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;

        switch (c) {
        case '"':
            fputs("\\\"", f);
            break;
        case '\\':
            fputs("\\\\", f);
            break;
        case '\n':
            fputs("\\n", f);
            break;
        case '\r':
            fputs("\\r", f);
            break;
        case '\t':
            fputs("\\t", f);
            break;
        default:
            if (c < 0x20) {
                fprintf(f, "\\u%04x", c);
            } else {
                fputc(c, f);
            }
            break;
        }
    }
}

/* Create missing parent directories for output_path (mkdir -p behaviour). */
static int ensure_parent_dirs(const char *filepath)
{
    char path[1024];
    size_t len;
    size_t i;

    if (!filepath || !filepath[0]) {
        return -1;
    }

    len = strlen(filepath);
    if (len >= sizeof(path)) {
        return -1;
    }
    memcpy(path, filepath, len + 1);

    for (i = len; i > 0; i--) {
        if (path[i] == '/') {
            path[i] = '\0';
            break;
        }
    }
    if (i == 0) {
        return 0;
    }
    if (path[0] == '\0') {
        return 0;
    }

    for (i = 1; path[i] != '\0'; i++) {
        if (path[i] != '/') {
            continue;
        }
        path[i] = '\0';
        if (path[0] != '\0' && mkdir(path, 0755) != 0 && errno != EEXIST) {
            return -1;
        }
        path[i] = '/';
    }
    if (mkdir(path, 0755) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

int ft_write_json(FTContext *c)
{
    FILE *f;

    if (!c || !c->output_path[0]) {
        return -1;
    }

    if (ensure_parent_dirs(c->output_path) != 0) {
        fprintf(stderr, "[ForensicTrace] cannot create output directory for %s: %s\n",
                c->output_path, strerror(errno));
        return -1;
    }

    f = fopen(c->output_path, "w");
    if (!f) {
        fprintf(stderr, "[ForensicTrace] cannot write %s: %s\n",
                c->output_path, strerror(errno));
        return -1;
    }

    fprintf(f, "{\n");
    fprintf(f, "  \"config\": \"");
    json_escape(f, c->config);
    fprintf(f, "\",\n");
    fprintf(f, "  \"event_count\": %d,\n", c->count);
    fprintf(f, "  \"truncated\": %s,\n", c->truncated ? "true" : "false");
    fprintf(f, "  \"duration_ns\": %llu,\n",
            (unsigned long long)(c->end_ns - c->start_ns));
    fprintf(f, "  \"events\": [\n");

    for (int i = 0; i < c->count; i++) {
        Event *e = &c->events[i];

        fprintf(f, "    {\n");
        fprintf(f, "      \"id\": %d,\n", e->id);
        fprintf(f, "      \"ts_ns\": %llu,\n", (unsigned long long)e->ts_ns);
        fprintf(f, "      \"type\": \"%s\",\n", type_name(e->type));
        fprintf(f, "      \"syscall\": \"%s\",\n", e->syscall);
        fprintf(f, "      \"pid\": %d,\n", e->pid);
        fprintf(f, "      \"ppid\": %d,\n", e->ppid);
        fprintf(f, "      \"target\": \"");
        json_escape(f, e->target);
        fprintf(f, "\",\n");
        fprintf(f, "      \"detail\": \"");
        json_escape(f, e->detail);
        fprintf(f, "\",\n");
        fprintf(f, "      \"parent_event\": %d\n", c->parent_event[i]);
        fprintf(f, "    }%s\n", (i < c->count - 1) ? "," : "");
    }

    fprintf(f, "  ]\n");
    fprintf(f, "}\n");

    if (fflush(f) != 0 || ferror(f)) {
        fprintf(stderr, "[ForensicTrace] error writing %s\n", c->output_path);
        fclose(f);
        return -1;
    }
    fclose(f);

    f = fopen(c->output_path, "rb");
    if (!f) {
        fprintf(stderr, "[ForensicTrace] cannot read back %s\n", c->output_path);
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    c->storage_bytes = ftell(f);
    fclose(f);

    if (c->storage_bytes <= 0) {
        fprintf(stderr, "[ForensicTrace] output file is empty: %s\n", c->output_path);
        return -1;
    }
    return 0;
}

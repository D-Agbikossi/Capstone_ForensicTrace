#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "forensictrace.h"

static void usage(void) {
    fprintf(stderr,
        "ForensicTrace - ptrace-based incident reconstruction prototype\n"
        "\n"
        "Usage: forensictrace --config <A|B|C|D> --output <file.json> [--verbose] -- <cmd> [args...]\n"
        "\n"
        "Configurations:\n"
        "  A  Process events only\n"
        "  B  Process + file events\n"
        "  C  Process + file + network events\n"
        "  D  All events (full syscall trace)\n"
        "\n"
        "Example:\n"
        "  forensictrace --config B --output /tmp/run.json -- /bin/ls /tmp\n");
}

int main(int argc, char *argv[]) {
    const char *config  = NULL;
    const char *output  = NULL;
    int         verbose = 0;
    int         cmd_idx = -1;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage(); return 0;
        } else if (!strcmp(argv[i], "--config") && i + 1 < argc) {
            config = argv[++i];
        } else if (!strcmp(argv[i], "--output") && i + 1 < argc) {
            output = argv[++i];
        } else if (!strcmp(argv[i], "--verbose") || !strcmp(argv[i], "-v")) {
            verbose = 1;
        } else if (!strcmp(argv[i], "--")) {
            cmd_idx = i + 1; break;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(); return 1;
        }
    }

    if (!config || !output || cmd_idx < 0 || cmd_idx >= argc) {
        usage(); return 1;
    }
    if (strcmp(config, "A") && strcmp(config, "B") &&
        strcmp(config, "C") && strcmp(config, "D")) {
        fprintf(stderr, "Invalid config '%s' (must be A, B, C, or D)\n", config);
        return 1;
    }

    printf("[ForensicTrace]\n");
    printf("  config  : %s\n", config);
    printf("  output  : %s\n", output);
    printf("  command : %s\n", argv[cmd_idx]);

    FTContext *c = ft_ctx_create(config, output, verbose);
    if (!c) { fprintf(stderr, "out of memory\n"); return 1; }

    if (ft_collect(c, &argv[cmd_idx]) < 0) {
        fprintf(stderr, "collection failed\n");
        ft_ctx_destroy(c);
        return 1;
    }

    ft_normalize(c);
    ft_correlate(c);
    ft_reconstruct(c);

    if (ft_write_json(c) != 0) {
        fprintf(stderr, "[ForensicTrace] failed to write experiment JSON\n");
        ft_ctx_destroy(c);
        return 1;
    }

    if (ft_integrity_write(c) != 0) {
        fprintf(stderr, "[ForensicTrace] failed to write integrity sidecar\n");
        ft_ctx_destroy(c);
        return 1;
    }

    printf("\n[ForensicTrace] %d events written to %s (%ld bytes)\n",
           c->count, output, c->storage_bytes);
    if (c->truncated) {
        fprintf(stderr,
                "[ForensicTrace] note: trace was truncated (see truncated in JSON)\n");
    }

    ft_ctx_destroy(c);
    return 0;
}

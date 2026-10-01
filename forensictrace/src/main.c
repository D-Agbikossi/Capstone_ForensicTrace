#include "forensictrace.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(FILE *fp)
{
    fprintf(fp,
            "ForensicTrace — Linux syscall evidence collector (MVP)\n\n"
            "Usage:\n"
            "  forensictrace --config <A|B|C|D> --output <path> [--verbose|-v] -- <cmd> [args...]\n\n"
            "Options:\n"
            "  --config A|B|C|D   Evidence profile (A=process, B=+file, C=+network, D=all)\n"
            "  --output PATH      Write experiment JSON to PATH (creates .sha256 sidecar)\n"
            "  --verbose, -v      Log each captured event on stderr\n"
            "  --help, -h         Show this help\n"
            "  --                 End of options; remainder is the traced command\n\n"
            "Example:\n"
            "  forensictrace --config B --output /tmp/run.json -- /bin/ls /tmp\n");
}

FTContext *ft_ctx_create(const char *config, const char *output, int verbose)
{
    FTContext *c;

    c = calloc(1, sizeof(*c));
    if (!c) {
        return NULL;
    }
    snprintf(c->config, sizeof(c->config), "%s", config ? config : "A");
    if (output) {
        snprintf(c->output_path, sizeof(c->output_path), "%s", output);
    }
    c->verbose = verbose;
    return c;
}

void ft_ctx_destroy(FTContext *c)
{
    free(c);
}

int main(int argc, char **argv)
{
    const char *config = NULL;
    const char *output = NULL;
    int verbose = 0;
    int dashdash = -1;
    int i;
    FTContext *ctx;
    char *const *target;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(stderr);
            return 0;
        }
        if (strcmp(argv[i], "--") == 0) {
            dashdash = i;
            break;
        }
        if (strcmp(argv[i], "--config") == 0) {
            if (i + 1 >= argc) {
                print_usage(stderr);
                return 1;
            }
            config = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--output") == 0) {
            if (i + 1 >= argc) {
                print_usage(stderr);
                return 1;
            }
            output = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            verbose = 1;
            continue;
        }
        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        print_usage(stderr);
        return 1;
    }

    if (!config || !output || dashdash < 0 || dashdash + 1 >= argc) {
        print_usage(stderr);
        return 1;
    }

    if (strcmp(config, "A") != 0 && strcmp(config, "B") != 0 &&
        strcmp(config, "C") != 0 && strcmp(config, "D") != 0) {
        fprintf(stderr, "Invalid config: %s (use A, B, C, or D)\n", config);
        return 1;
    }

    target = &argv[dashdash + 1];

    ctx = ft_ctx_create(config, output, verbose);
    if (!ctx) {
        fprintf(stderr, "Out of memory\n");
        return 1;
    }

    fprintf(stderr, "[ForensicTrace]\n");
    fprintf(stderr, "  config  : %s\n", config);
    fprintf(stderr, "  output  : %s\n", output);
    fprintf(stderr, "  command : %s\n", target[0]);

    if (ft_collect(ctx, target) != 0) {
        ft_ctx_destroy(ctx);
        return 1;
    }

    ft_normalize(ctx);
    ft_correlate(ctx);
    ft_reconstruct(ctx);
    ft_write_json(ctx);
    ft_integrity_write(ctx);

    fprintf(stderr, "\n[ForensicTrace] %d events written to %s (%ld bytes)\n",
            ctx->count, ctx->output_path, ctx->storage_bytes);

    ft_ctx_destroy(ctx);
    return 0;
}

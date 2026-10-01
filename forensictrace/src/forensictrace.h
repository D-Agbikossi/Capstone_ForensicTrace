#ifndef FORENSICTRACE_H
#define FORENSICTRACE_H

#include <stdint.h>
#include <sys/types.h>

#define FT_MAX_EVENTS  20000
#define FT_MAX_TRACEES 64
#define FT_STR           512

typedef enum {
    EV_PROCESS = 0,
    EV_FILE    = 1,
    EV_NETWORK = 2,
    EV_OTHER   = 3
} EventType;

typedef struct {
    int       id;
    uint64_t  ts_ns;
    EventType type;
    char      syscall[32];
    pid_t     pid;
    pid_t     ppid;
    int       dir;
    long      ret;
    char      target[FT_STR];
    char      detail[FT_STR];
} Event;

typedef struct {
    Event events[FT_MAX_EVENTS];
    int   count;
    int   parent_event[FT_MAX_EVENTS];

    char  config[8];
    char  output_path[1024];
    int   verbose;

    uint64_t start_ns;
    uint64_t end_ns;
    long     storage_bytes;
} FTContext;

FTContext *ft_ctx_create(const char *config, const char *output, int verbose);
void       ft_ctx_destroy(FTContext *c);

int  ft_collect(FTContext *c, char *const argv[]);
void ft_normalize(FTContext *c);
void ft_correlate(FTContext *c);
void ft_reconstruct(FTContext *c);
void ft_write_json(FTContext *c);
void ft_integrity_write(FTContext *c);

int  ft_config_accepts(const char *config, const char *syscall_name);

const char *ft_event_type_str(EventType t);

#endif

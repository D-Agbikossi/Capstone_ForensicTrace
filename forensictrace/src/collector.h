/* Legacy draft header — not used by Makefile build; see forensictrace.h. */
#ifndef COLLECTOR_H
#define COLLECTOR_H

#include <sys/types.h>
#include <stdint.h>

#define MAX_EVENTS 10000

typedef enum {
    EVENT_PROCESS,
    EVENT_FILE,
    EVENT_NETWORK,
    EVENT_SYSCALL
} EventType;

typedef struct {
    int event_id;
    uint64_t timestamp;
    EventType type;
    char syscall_name[32];
    pid_t pid;
    pid_t ppid;
    char executable[256];
    char extra[512];
} Event;

typedef struct {
    Event events[MAX_EVENTS];
    int event_count;
    char config[8];
    char output_path[512];
    int verbose;
} Collector;

Collector *collector_create(const char *config, const char *output, int verbose);
int collector_run(Collector *c, char *const argv[]);
void collector_destroy(Collector *c);
int collector_event_count(Collector *c);
void collector_write_json(Collector *c, const char *path);

#endif
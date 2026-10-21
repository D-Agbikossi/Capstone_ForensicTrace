#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <linux/limits.h>

#include "forensictrace.h"

#ifndef __WALL
#define __WALL 0x40000000
#endif

typedef struct {
    pid_t pid;
    int   in_syscall;
    int   pending_init;   /* suppress next stop signal (new fork child) */
} Tracee;

static Tracee g_tracees[FT_MAX_TRACEES];
static int    g_tracee_count = 0;

static Tracee *tracee_find(pid_t pid) {
    for (int i = 0; i < g_tracee_count; i++)
        if (g_tracees[i].pid == pid) return &g_tracees[i];
    return NULL;
}

static Tracee *tracee_add(pid_t pid, int pending_init) {
    if (g_tracee_count >= FT_MAX_TRACEES) return NULL;
    Tracee *t = &g_tracees[g_tracee_count++];
    t->pid = pid;
    t->in_syscall = 0;
    t->pending_init = pending_init;
    return t;
}

static void tracee_remove(pid_t pid) {
    for (int i = 0; i < g_tracee_count; i++) {
        if (g_tracees[i].pid == pid) {
            g_tracees[i] = g_tracees[--g_tracee_count];
            return;
        }
    }
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int read_string(pid_t pid, unsigned long addr, char *out, size_t outlen) {
    if (addr == 0 || outlen == 0) { if (outlen) out[0] = '\0'; return -1; }

    struct iovec local  = { .iov_base = out, .iov_len = outlen - 1 };
    struct iovec remote = { .iov_base = (void*)addr, .iov_len = outlen - 1 };
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n > 0) { out[n] = '\0'; return 0; }

    size_t i = 0;
    while (i + sizeof(long) <= outlen - 1) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
        if (errno != 0) { out[i] = '\0'; return (i > 0) ? 0 : -1; }
        memcpy(out + i, &word, sizeof(long));
        for (size_t j = 0; j < sizeof(long); j++)
            if (out[i + j] == '\0') return 0;
        i += sizeof(long);
    }
    out[outlen - 1] = '\0';
    return 0;
}

static void fd_to_path(pid_t pid, int fd, char *out, size_t outlen) {
    char link[64], path[PATH_MAX];
    snprintf(link, sizeof(link), "/proc/%d/fd/%d", pid, fd);
    ssize_t n = readlink(link, path, sizeof(path) - 1);
    if (n < 0) { snprintf(out, outlen, "fd:%d", fd); return; }
    path[n] = '\0';
    strncpy(out, path, outlen - 1);
    out[outlen - 1] = '\0';
}

static void classify_event(Event *e, long syscall_num,
                           unsigned long a0, unsigned long a1,
                           unsigned long a2, unsigned long a3,
                           pid_t pid, pid_t ppid) {
    e->pid  = pid;
    e->ppid = ppid;

    switch (syscall_num) {
    case SYS_execve:
        snprintf(e->syscall, sizeof(e->syscall), "execve");
        e->type = EV_PROCESS;
        read_string(pid, a0, e->target, sizeof(e->target));
        break;
    case SYS_execveat:
        snprintf(e->syscall, sizeof(e->syscall), "execveat");
        e->type = EV_PROCESS;
        read_string(pid, a1, e->target, sizeof(e->target));
        break;

    case SYS_open:
        snprintf(e->syscall, sizeof(e->syscall), "open");
        e->type = EV_FILE;
        read_string(pid, a0, e->target, sizeof(e->target));
        snprintf(e->detail, sizeof(e->detail), "flags=0x%lx", a1);
        break;
    case SYS_openat:
        snprintf(e->syscall, sizeof(e->syscall), "openat");
        e->type = EV_FILE;
        read_string(pid, a1, e->target, sizeof(e->target));
        snprintf(e->detail, sizeof(e->detail), "dirfd=%ld flags=0x%lx",
                 (long)a0, a2);
        break;
    case SYS_close:
        snprintf(e->syscall, sizeof(e->syscall), "close");
        e->type = EV_FILE;
        fd_to_path(pid, (int)a0, e->target, sizeof(e->target));
        break;
    case SYS_read:
        snprintf(e->syscall, sizeof(e->syscall), "read");
        e->type = EV_FILE;
        fd_to_path(pid, (int)a0, e->target, sizeof(e->target));
        break;
    case SYS_write:
        snprintf(e->syscall, sizeof(e->syscall), "write");
        e->type = EV_FILE;
        fd_to_path(pid, (int)a0, e->target, sizeof(e->target));
        break;
    case SYS_unlink:
        snprintf(e->syscall, sizeof(e->syscall), "unlink");
        e->type = EV_FILE;
        read_string(pid, a0, e->target, sizeof(e->target));
        break;
    case SYS_unlinkat:
        snprintf(e->syscall, sizeof(e->syscall), "unlinkat");
        e->type = EV_FILE;
        read_string(pid, a1, e->target, sizeof(e->target));
        break;
    case SYS_chmod:
        snprintf(e->syscall, sizeof(e->syscall), "chmod");
        e->type = EV_FILE;
        read_string(pid, a0, e->target, sizeof(e->target));
        break;
    case SYS_fchmodat:
        snprintf(e->syscall, sizeof(e->syscall), "fchmodat");
        e->type = EV_FILE;
        read_string(pid, a1, e->target, sizeof(e->target));
        break;

    case SYS_connect:
        snprintf(e->syscall, sizeof(e->syscall), "connect");
        e->type = EV_NETWORK;
        {
            unsigned char sa[128];
            struct iovec local  = { .iov_base = sa, .iov_len = sizeof(sa) };
            struct iovec remote = { .iov_base = (void*)a1, .iov_len = sizeof(sa) };
            ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
            if (n >= 8 && sa[0] == 2 /* AF_INET */) {
                unsigned int port = ((unsigned)sa[2] << 8) | sa[3];
                snprintf(e->target, sizeof(e->target),
                         "%u.%u.%u.%u:%u",
                         sa[4], sa[5], sa[6], sa[7], port);
            } else if (n >= 8 && sa[0] == 10 /* AF_INET6 */) {
                snprintf(e->target, sizeof(e->target), "ipv6:[...]");
            } else {
                snprintf(e->target, sizeof(e->target), "sockfd=%ld", (long)a0);
            }
        }
        break;
    case SYS_accept:
        snprintf(e->syscall, sizeof(e->syscall), "accept");
        e->type = EV_NETWORK;
        snprintf(e->target, sizeof(e->target), "sockfd=%ld", (long)a0);
        break;
    case SYS_accept4:
        snprintf(e->syscall, sizeof(e->syscall), "accept4");
        e->type = EV_NETWORK;
        snprintf(e->target, sizeof(e->target), "sockfd=%ld", (long)a0);
        break;
    case SYS_sendto:
        snprintf(e->syscall, sizeof(e->syscall), "sendto");
        e->type = EV_NETWORK;
        fd_to_path(pid, (int)a0, e->target, sizeof(e->target));
        break;
    case SYS_recvfrom:
        snprintf(e->syscall, sizeof(e->syscall), "recvfrom");
        e->type = EV_NETWORK;
        fd_to_path(pid, (int)a0, e->target, sizeof(e->target));
        break;

    case SYS_clone:
        snprintf(e->syscall, sizeof(e->syscall), "clone");
        e->type = EV_PROCESS;
        break;
    case SYS_fork:
        snprintf(e->syscall, sizeof(e->syscall), "fork");
        e->type = EV_PROCESS;
        break;
    case SYS_vfork:
        snprintf(e->syscall, sizeof(e->syscall), "vfork");
        e->type = EV_PROCESS;
        break;

    case SYS_exit:
        snprintf(e->syscall, sizeof(e->syscall), "exit");
        e->type = EV_PROCESS;
        snprintf(e->target, sizeof(e->target), "code=%ld", (long)a0);
        break;
    case SYS_exit_group:
        snprintf(e->syscall, sizeof(e->syscall), "exit_group");
        e->type = EV_PROCESS;
        snprintf(e->target, sizeof(e->target), "code=%ld", (long)a0);
        break;

    default:
        snprintf(e->syscall, sizeof(e->syscall), "syscall_%ld", syscall_num);
        e->type = EV_OTHER;
        break;
    }
    (void)a3;
}

static void record_event(FTContext *c, const Event *e) {
    if (c->count >= FT_MAX_EVENTS) {
        if (!c->truncated) {
            c->truncated = 1;
            fprintf(stderr,
                    "[ForensicTrace] warning: event cap %d reached; further events dropped\n",
                    FT_MAX_EVENTS);
        }
        return;
    }
    if (!ft_config_accepts(c->config, e->syscall)) return;

    Event *dst = &c->events[c->count];
    *dst = *e;
    dst->id = c->count + 1;
    c->count++;

    if (c->verbose) {
        fprintf(stderr, "[FT] #%-4d %-11s pid=%-6d %s\n",
                dst->id, dst->syscall, dst->pid, dst->target);
    }
}

static void handle_syscall_stop(FTContext *c, pid_t pid,
                                const struct user_regs_struct *regs) {
    Tracee *t = tracee_find(pid);
    if (!t) return;

    if (!t->in_syscall) {
        t->in_syscall = 1;

        Event e;
        memset(&e, 0, sizeof(e));
        e.ts_ns = now_ns();
        e.dir   = 1;

        pid_t ppid = 0;
        char statpath[64], buf[512];
        snprintf(statpath, sizeof(statpath), "/proc/%d/stat", pid);
        FILE *fp = fopen(statpath, "r");
        if (fp) {
            if (fgets(buf, sizeof(buf), fp)) {
                char *rp = strrchr(buf, ')');
                if (rp) sscanf(rp + 2, "%*c %d", &ppid);
            }
            fclose(fp);
        }

        classify_event(&e, (long)regs->orig_rax,
                       regs->rdi, regs->rsi, regs->rdx, regs->r10,
                       pid, ppid);
        record_event(c, &e);
    } else {
        t->in_syscall = 0;
    }
}

int ft_collect(FTContext *c, char *const argv[]) {
    c->start_ns = now_ns();

    pid_t child = fork();
    if (child < 0) { perror("fork"); return -1; }

    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("PTRACE_TRACEME"); _exit(1);
        }
        raise(SIGSTOP);            /* let parent set options */
        execvp(argv[0], argv);
        perror("execvp");
        _exit(127);
    }

    int status;
    waitpid(child, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "child did not stop as expected\n");
        return -1;
    }

    long options = PTRACE_O_TRACESYSGOOD  |
                   PTRACE_O_TRACEFORK     |
                   PTRACE_O_TRACEVFORK    |
                   PTRACE_O_TRACECLONE    |
                   PTRACE_O_TRACEEXEC     |
                   PTRACE_O_EXITKILL;
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, options) < 0)
        perror("PTRACE_SETOPTIONS");

    tracee_add(child, 0);
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);

    while (g_tracee_count > 0) {
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid < 0) {
            if (errno == ECHILD) break;
            perror("waitpid");
            break;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            tracee_remove(pid);
            continue;
        }
        if (!WIFSTOPPED(status)) continue;

        int sig   = WSTOPSIG(status);
        int event = (status >> 16) & 0xffff;

        /* New child from fork/vfork/clone */
        if (sig == SIGTRAP &&
            (event == PTRACE_EVENT_FORK  ||
             event == PTRACE_EVENT_VFORK ||
             event == PTRACE_EVENT_CLONE)) {
            unsigned long new_pid = 0;
            if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &new_pid) == 0)
                tracee_add((pid_t)new_pid, 1);
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            continue;
        }

        /* PTRACE_EVENT_EXEC — nothing to record, just continue */
        if (sig == SIGTRAP && event == PTRACE_EVENT_EXEC) {
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            continue;
        }

        /* New tracee's initial stop: suppress the synthetic signal */
        Tracee *t = tracee_find(pid);
        if (t && t->pending_init) {
            t->pending_init = 0;
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            continue;
        }

        /* Syscall stop (SIGTRAP | 0x80 with TRACESYSGOOD) */
        if (sig == (SIGTRAP | 0x80)) {
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == 0)
                handle_syscall_stop(c, pid, &regs);
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            continue;
        }

        /* Otherwise, deliver the signal to the tracee */
        ptrace(PTRACE_SYSCALL, pid, NULL, (void*)(long)sig);
    }

    c->end_ns = now_ns();
    return 0;
}

FTContext *ft_ctx_create(const char *config, const char *output, int verbose) {
    FTContext *c = calloc(1, sizeof(FTContext));
    if (!c) return NULL;
    snprintf(c->config, sizeof(c->config), "%s", config);
    snprintf(c->output_path, sizeof(c->output_path), "%s", output);
    c->verbose = verbose;
    for (int i = 0; i < FT_MAX_EVENTS; i++) c->parent_event[i] = -1;
    return c;
}

void ft_ctx_destroy(FTContext *c) { free(c); }

int ft_config_accepts(const char *config, const char *syscall_name) {
    EventType t;

    if (!strcmp(syscall_name, "execve")   || !strcmp(syscall_name, "execveat") ||
        !strcmp(syscall_name, "clone")    || !strcmp(syscall_name, "fork")     ||
        !strcmp(syscall_name, "vfork")    || !strcmp(syscall_name, "exit")     ||
        !strcmp(syscall_name, "exit_group")) {
        t = EV_PROCESS;
    } else if (!strncmp(syscall_name, "open", 4)    ||
               !strncmp(syscall_name, "close", 5)   ||
               !strncmp(syscall_name, "read", 4)    ||
               !strncmp(syscall_name, "write", 5)   ||
               !strncmp(syscall_name, "unlink", 6)  ||
               !strncmp(syscall_name, "chmod", 5)   ||
               !strncmp(syscall_name, "fchmod", 6)) {
        t = EV_FILE;
    } else if (!strncmp(syscall_name, "connect", 7)  ||
               !strncmp(syscall_name, "accept", 6)   ||
               !strncmp(syscall_name, "sendto", 6)   ||
               !strncmp(syscall_name, "recvfrom", 8)) {
        t = EV_NETWORK;
    } else {
        t = EV_OTHER;
    }

    if (!strcmp(config, "A")) return t == EV_PROCESS;
    if (!strcmp(config, "B")) return t == EV_PROCESS || t == EV_FILE;
    if (!strcmp(config, "C")) return t == EV_PROCESS || t == EV_FILE ||
                                     t == EV_NETWORK;
    if (!strcmp(config, "D")) return 1;
    return 0;
}

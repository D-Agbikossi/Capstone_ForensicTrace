#include "forensictrace.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    pid_t pid;
    int   in_syscall;
    int   pending_init;
} Tracee;

static Tracee tracees[FT_MAX_TRACEES];
static int tracee_count;

static uint64_t monotonic_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int find_tracee(pid_t pid)
{
    int i;

    for (i = 0; i < tracee_count; i++) {
        if (tracees[i].pid == pid) {
            return i;
        }
    }
    return -1;
}

static int add_tracee(pid_t pid)
{
    if (tracee_count >= FT_MAX_TRACEES) {
        return -1;
    }
    tracees[tracee_count].pid = pid;
    tracees[tracee_count].in_syscall = 0;
    tracees[tracee_count].pending_init = 1;
    tracee_count++;
    return 0;
}

static void remove_tracee(pid_t pid)
{
    int idx = find_tracee(pid);
    int i;

    if (idx < 0) {
        return;
    }
    for (i = idx; i < tracee_count - 1; i++) {
        tracees[i] = tracees[i + 1];
    }
    tracee_count--;
}

static ssize_t read_remote_mem(pid_t pid, unsigned long addr, void *buf, size_t len)
{
    struct iovec local;
    struct iovec remote;
    ssize_t n;

    local.iov_base = buf;
    local.iov_len = len;
    remote.iov_base = (void *)addr;
    remote.iov_len = len;

    n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n >= 0) {
        return n;
    }

    /* Fallback: PTRACE_PEEKDATA */
    {
        size_t i;
        long word;
        unsigned char *out = buf;

        for (i = 0; i + sizeof(long) <= len; i += sizeof(long)) {
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
            if (errno != 0) {
                return (ssize_t)i;
            }
            memcpy(out + i, &word, sizeof(long));
        }
        if (i < len) {
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
            if (errno != 0) {
                return (ssize_t)i;
            }
            memcpy(out + i, &word, len - i);
        }
        return (ssize_t)len;
    }
}

static int read_cstring(pid_t pid, unsigned long addr, char *out, size_t out_len)
{
    size_t i;
    unsigned char chunk[256];
    ssize_t n;

    if (out_len == 0) {
        return -1;
    }
    out[0] = '\0';

    for (i = 0; i < 4096; i += sizeof(chunk)) {
        n = read_remote_mem(pid, addr + i, chunk, sizeof(chunk));
        if (n <= 0) {
            break;
        }
        size_t j;
        for (j = 0; j < (size_t)n; j++) {
            if (chunk[j] == '\0') {
                size_t copy = i + j;
                if (copy >= out_len) {
                    copy = out_len - 1;
                }
                read_remote_mem(pid, addr, out, copy + 1);
                out[copy] = '\0';
                return 0;
            }
        }
    }
    return -1;
}

static void fd_path(pid_t pid, int fd, char *out, size_t out_len)
{
    char linkpath[64];
    char target[PATH_MAX];
    ssize_t n;

    if (fd < 0) {
        snprintf(out, out_len, "fd=%d", fd);
        return;
    }
    snprintf(linkpath, sizeof(linkpath), "/proc/%d/fd/%d", (int)pid, fd);
    n = readlink(linkpath, target, sizeof(target) - 1);
    if (n < 0) {
        snprintf(out, out_len, "/proc/%d/fd/%d", (int)pid, fd);
        return;
    }
    target[n] = '\0';
    snprintf(out, out_len, "%.*s", (int)(out_len > 0 ? out_len - 1 : 0), target);
}

typedef struct {
    const char *name;
    EventType   type;
} SyscallMeta;

static int meta_for_nr(long nr, SyscallMeta *m)
{
    switch (nr) {
    case SYS_execve:
        m->name = "execve";
        m->type = EV_PROCESS;
        return 1;
    case SYS_execveat:
        m->name = "execveat";
        m->type = EV_PROCESS;
        return 1;
    case SYS_clone:
        m->name = "clone";
        m->type = EV_PROCESS;
        return 1;
    case SYS_fork:
        m->name = "fork";
        m->type = EV_PROCESS;
        return 1;
    case SYS_vfork:
        m->name = "vfork";
        m->type = EV_PROCESS;
        return 1;
    case SYS_exit:
        m->name = "exit";
        m->type = EV_PROCESS;
        return 1;
    case SYS_exit_group:
        m->name = "exit_group";
        m->type = EV_PROCESS;
        return 1;
    case SYS_open:
        m->name = "open";
        m->type = EV_FILE;
        return 1;
    case SYS_openat:
        m->name = "openat";
        m->type = EV_FILE;
        return 1;
    case SYS_close:
        m->name = "close";
        m->type = EV_FILE;
        return 1;
    case SYS_read:
        m->name = "read";
        m->type = EV_FILE;
        return 1;
    case SYS_write:
        m->name = "write";
        m->type = EV_FILE;
        return 1;
    case SYS_unlink:
        m->name = "unlink";
        m->type = EV_FILE;
        return 1;
    case SYS_unlinkat:
        m->name = "unlinkat";
        m->type = EV_FILE;
        return 1;
    case SYS_chmod:
        m->name = "chmod";
        m->type = EV_FILE;
        return 1;
    case SYS_fchmodat:
        m->name = "fchmodat";
        m->type = EV_FILE;
        return 1;
    case SYS_connect:
        m->name = "connect";
        m->type = EV_NETWORK;
        return 1;
    case SYS_accept:
        m->name = "accept";
        m->type = EV_NETWORK;
        return 1;
    case SYS_accept4:
        m->name = "accept4";
        m->type = EV_NETWORK;
        return 1;
    case SYS_sendto:
        m->name = "sendto";
        m->type = EV_NETWORK;
        return 1;
    case SYS_recvfrom:
        m->name = "recvfrom";
        m->type = EV_NETWORK;
        return 1;
    default:
        return 0;
    }
}

int ft_config_accepts(const char *config, const char *syscall_name)
{
    int is_process = 0;
    int is_file = 0;
    int is_network = 0;

    if (!config || !syscall_name) {
        return 0;
    }

    if (strcmp(syscall_name, "execve") == 0 ||
        strcmp(syscall_name, "execveat") == 0 ||
        strcmp(syscall_name, "clone") == 0 ||
        strcmp(syscall_name, "fork") == 0 ||
        strcmp(syscall_name, "vfork") == 0 ||
        strcmp(syscall_name, "exit") == 0 ||
        strcmp(syscall_name, "exit_group") == 0) {
        is_process = 1;
    }
    if (strcmp(syscall_name, "open") == 0 ||
        strcmp(syscall_name, "openat") == 0 ||
        strcmp(syscall_name, "close") == 0 ||
        strcmp(syscall_name, "read") == 0 ||
        strcmp(syscall_name, "write") == 0 ||
        strcmp(syscall_name, "unlink") == 0 ||
        strcmp(syscall_name, "unlinkat") == 0 ||
        strcmp(syscall_name, "chmod") == 0 ||
        strcmp(syscall_name, "fchmodat") == 0) {
        is_file = 1;
    }
    if (strcmp(syscall_name, "connect") == 0 ||
        strcmp(syscall_name, "accept") == 0 ||
        strcmp(syscall_name, "accept4") == 0 ||
        strcmp(syscall_name, "sendto") == 0 ||
        strcmp(syscall_name, "recvfrom") == 0) {
        is_network = 1;
    }

    if (strcmp(config, "A") == 0) {
        return is_process;
    }
    if (strcmp(config, "B") == 0) {
        return is_process || is_file;
    }
    if (strcmp(config, "C") == 0) {
        return is_process || is_file || is_network;
    }
    if (strcmp(config, "D") == 0) {
        return 1;
    }
    return 0;
}

static void fill_event_fields(FTContext *c, Event *ev, pid_t pid, long nr,
                              const struct user_regs_struct *regs)
{
    SyscallMeta meta;
    char sc_name[32];

    ev->ts_ns = monotonic_ns();
    ev->pid = pid;
    ev->ppid = 0;
    {
        char statpath[64];
        FILE *sf;

        snprintf(statpath, sizeof(statpath), "/proc/%d/stat", (int)pid);
        sf = fopen(statpath, "r");
        if (sf) {
            int dummy;
            if (fscanf(sf, "%d %*s %*c %d", &dummy, &ev->ppid) != 2) {
                ev->ppid = 0;
            }
            fclose(sf);
        }
    }
    ev->dir = 1;
    ev->ret = 0;
    ev->target[0] = '\0';
    ev->detail[0] = '\0';

    if (meta_for_nr(nr, &meta)) {
        snprintf(sc_name, sizeof(sc_name), "%s", meta.name);
        ev->type = meta.type;
    } else {
        snprintf(sc_name, sizeof(sc_name), "syscall_%ld", nr);
        ev->type = EV_OTHER;
    }
    snprintf(ev->syscall, sizeof(ev->syscall), "%s", sc_name);

    if (!ft_config_accepts(c->config, ev->syscall)) {
        return;
    }

    switch (nr) {
    case SYS_execve:
        read_cstring(pid, regs->rdi, ev->target, sizeof(ev->target));
        break;
    case SYS_execveat:
        read_cstring(pid, regs->rsi, ev->target, sizeof(ev->target));
        snprintf(ev->detail, sizeof(ev->detail), "dirfd=%ld", (long)regs->rdi);
        break;
    case SYS_exit:
    case SYS_exit_group:
        snprintf(ev->target, sizeof(ev->target), "code=%ld", (long)regs->rdi);
        break;
    case SYS_open:
        read_cstring(pid, regs->rdi, ev->target, sizeof(ev->target));
        snprintf(ev->detail, sizeof(ev->detail), "flags=0%lo", (unsigned long)regs->rsi);
        break;
    case SYS_openat:
        read_cstring(pid, regs->rsi, ev->target, sizeof(ev->target));
        snprintf(ev->detail, sizeof(ev->detail), "dirfd=%ld flags=0%lo",
                 (long)regs->rdi, (unsigned long)regs->rdx);
        break;
    case SYS_close:
        fd_path(pid, (int)regs->rdi, ev->target, sizeof(ev->target));
        break;
    case SYS_read:
    case SYS_write:
        fd_path(pid, (int)regs->rdi, ev->target, sizeof(ev->target));
        snprintf(ev->detail, sizeof(ev->detail), "count=%ld", (long)regs->rdx);
        break;
    case SYS_unlink:
        read_cstring(pid, regs->rdi, ev->target, sizeof(ev->target));
        break;
    case SYS_unlinkat:
        read_cstring(pid, regs->rsi, ev->target, sizeof(ev->target));
        snprintf(ev->detail, sizeof(ev->detail), "dirfd=%ld", (long)regs->rdi);
        break;
    case SYS_chmod:
        read_cstring(pid, regs->rdi, ev->target, sizeof(ev->target));
        snprintf(ev->detail, sizeof(ev->detail), "mode=0%lo", (unsigned long)regs->rsi);
        break;
    case SYS_fchmodat:
        read_cstring(pid, regs->rsi, ev->target, sizeof(ev->target));
        snprintf(ev->detail, sizeof(ev->detail), "dirfd=%ld mode=0%lo",
                 (long)regs->rdi, (unsigned long)regs->rdx);
        break;
    case SYS_connect: {
        int sockfd = (int)regs->rdi;
        struct sockaddr_in sin;
        ssize_t got;

        got = read_remote_mem(pid, regs->rsi, &sin, sizeof(sin));
        if (got >= (ssize_t)sizeof(sin) && sin.sin_family == AF_INET) {
            unsigned char *b = (unsigned char *)&sin.sin_addr.s_addr;
            unsigned port = ntohs(sin.sin_port);
            snprintf(ev->target, sizeof(ev->target), "%u.%u.%u.%u:%u",
                     b[0], b[1], b[2], b[3], port);
        } else {
            snprintf(ev->target, sizeof(ev->target), "sockfd=%d", sockfd);
        }
        break;
    }
    case SYS_accept:
    case SYS_accept4:
        snprintf(ev->target, sizeof(ev->target), "sockfd=%d", (int)regs->rdi);
        break;
    case SYS_sendto:
    case SYS_recvfrom:
        fd_path(pid, (int)regs->rdi, ev->target, sizeof(ev->target));
        break;
    default:
        snprintf(ev->target, sizeof(ev->target), "%s", sc_name);
        break;
    }
}

static int record_event(FTContext *c, Event *partial, long nr)
{
    Event *ev;
    SyscallMeta meta;
    char sc_check[32];

    if (meta_for_nr(nr, &meta)) {
        snprintf(sc_check, sizeof(sc_check), "%s", meta.name);
    } else {
        snprintf(sc_check, sizeof(sc_check), "syscall_%ld", nr);
    }

    if (!ft_config_accepts(c->config, sc_check)) {
        return 0;
    }

    if (c->count >= FT_MAX_EVENTS) {
        return 0;
    }

    ev = &c->events[c->count];
    *ev = *partial;
    ev->id = c->count + 1;
    c->count++;

    if (c->verbose) {
        fprintf(stderr, "[event] %s pid=%d %s %s\n",
                ev->syscall, (int)ev->pid, ev->target, ev->detail);
    }
    return 1;
}

static void handle_syscall_stop(FTContext *c, pid_t pid, Tracee *t)
{
    struct user_regs_struct regs;
    long nr;
    Event ev;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        return;
    }

    nr = (long)regs.orig_rax;

    if (!t->in_syscall) {
        memset(&ev, 0, sizeof(ev));
        fill_event_fields(c, &ev, pid, nr, &regs);

        if (ft_config_accepts(c->config, ev.syscall)) {
            record_event(c, &ev, nr);
        }
        t->in_syscall = 1;
    } else {
        t->in_syscall = 0;
    }
}

static int is_syscall_stop(int status)
{
    return WIFSTOPPED(status) &&
           ((status >> 8) & 0xff) == (SIGTRAP | 0x80);
}

static long ptrace_cont_signal(int status)
{
    int sig;

    if (!WIFSTOPPED(status)) {
        return 0;
    }
    sig = WSTOPSIG(status);
    if (sig == SIGTRAP || sig == (SIGTRAP | 0x80)) {
        return 0;
    }
    return (long)sig;
}

static int is_ptrace_event(int status)
{
    return WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP &&
           ((status >> 16) & 0xffff) != 0;
}

static int handle_ptrace_event(FTContext *c, pid_t pid, int status)
{
    unsigned long msg = 0;
    unsigned int ev;

    (void)c;
    if (!is_ptrace_event(status)) {
        return 0;
    }

    ev = (status >> 16) & 0xffff;
    if (ev == PTRACE_EVENT_FORK ||
        ev == PTRACE_EVENT_VFORK ||
        ev == PTRACE_EVENT_CLONE) {
        if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &msg) == 0 && msg != 0) {
            add_tracee((pid_t)msg);
        }
        return 1;
    }
    if (ev == PTRACE_EVENT_EXEC) {
        return 1;
    }
    return 0;
}

int ft_collect(FTContext *c, char *const argv[])
{
    pid_t child;
    int status;
    pid_t pid;
    int idx;

    if (!c || !argv || !argv[0]) {
        return -1;
    }

    tracee_count = 0;
    c->count = 0;
    c->start_ns = monotonic_ns();

    child = fork();
    if (child < 0) {
        perror("fork");
        return -1;
    }

    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            _exit(127);
        }
        raise(SIGSTOP);
        execvp(argv[0], argv);
        _exit(127);
    }

    if (waitpid(child, &status, __WALL) < 0) {
        perror("waitpid");
        return -1;
    }

    if (ptrace(PTRACE_SETOPTIONS, child, NULL,
               PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                   PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                   PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL) < 0) {
        perror("PTRACE_SETOPTIONS");
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return -1;
    }

    add_tracee(child);
    tracees[0].pending_init = 0;

    if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0) {
        perror("PTRACE_SYSCALL");
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return -1;
    }

    while (tracee_count > 0) {
        pid = waitpid(-1, &status, __WALL);
        if (pid < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            remove_tracee(pid);
            continue;
        }

        if (!WIFSTOPPED(status)) {
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            continue;
        }

        idx = find_tracee(pid);
        if (idx < 0) {
            add_tracee(pid);
            idx = find_tracee(pid);
        }

        if (handle_ptrace_event(c, pid, status)) {
            if (idx >= 0) {
                tracees[idx].pending_init = 0;
            }
            ptrace(PTRACE_SYSCALL, pid, NULL, (void *)ptrace_cont_signal(status));
            continue;
        }

        if (is_syscall_stop(status)) {
            if (idx >= 0) {
                handle_syscall_stop(c, pid, &tracees[idx]);
            }
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            continue;
        }

        if (idx >= 0 && tracees[idx].pending_init) {
            tracees[idx].pending_init = 0;
            ptrace(PTRACE_SYSCALL, pid, NULL, (void *)ptrace_cont_signal(status));
            continue;
        }

        ptrace(PTRACE_SYSCALL, pid, NULL, (void *)ptrace_cont_signal(status));
    }

    c->end_ns = monotonic_ns();
    return 0;
}

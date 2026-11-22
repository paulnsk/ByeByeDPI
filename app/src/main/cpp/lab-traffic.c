#define _POSIX_C_SOURCE 200809L
#include <android/log.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include "lab-traffic.h"
#include "packets.h"

enum { MAX_FD = 8192 };
struct flow {
    unsigned id;
    int type;
    unsigned port;
    char ip[INET6_ADDRSTRLEN];
    uint64_t up, down, last_log, started;
    char host[254];
    const char *first_tls, *finished;
    int tcp, error;
    unsigned char tls_start[6];
    unsigned tls_bytes;
    int tls_expected, tls_observed, read_ended;
    int media, hello_wait;
};

static struct flow flows[MAX_FD];
static unsigned next_id;
static int hello_wait_ms;
static pthread_mutex_t flows_lock = PTHREAD_MUTEX_INITIALIZER;
static char journal_dir[PATH_MAX];

int __real_connect(int fd, const struct sockaddr *addr, socklen_t len);
int __real_close(int fd);
ssize_t __real_recv(int fd, void *buf, size_t size, int flags);
ssize_t __real_recvfrom(int fd, void *buf, size_t size, int flags,
                        struct sockaddr *addr, socklen_t *len);
ssize_t __real_send(int fd, const void *buf, size_t size, int flags);
ssize_t __real_sendto(int fd, const void *buf, size_t size, int flags,
                      const struct sockaddr *addr, socklen_t len);

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void lab_set_journal_dir(const char *path) {
    if (path && strlen(path) < sizeof(journal_dir)) strcpy(journal_dir, path);
}

static void journal(const struct flow *f) {
    enum { DAY_LIMIT = 512 * 1024, DAYS = 8 };
    static time_t last_hour = -1;
    static unsigned known, unknown;
    if (!journal_dir[0] || f->type != SOCK_STREAM || f->port != 443 ||
        (!f->host[0] && f->tcp != -1)) return;
    time_t now = time(NULL);
    time_t day = now / 86400;
    time_t hour = now / 3600;
    if (now <= 0) return;
    if (hour != last_hour) {
        known = unknown = 0;
        last_hour = hour;
    }
    unsigned *count = f->host[0] ? &known : &unknown;
    if (*count >= (f->host[0] ? 54 : 10)) return;
    ++*count;

    char path[PATH_MAX];
    int length = snprintf(path, sizeof(path), "%s/flow-%02d.jsonl", journal_dir, (int)(day % DAYS));
    if (length < 0 || length >= (int)sizeof(path)) return;
    struct stat st;
    int append = stat(path, &st) == 0 && st.st_mtime / 86400 == day;
    if (append && st.st_size > DAY_LIMIT - 640) return;
    FILE *file = fopen(path, append ? "a" : "w");
    if (!file) return;
    fprintf(file, "{\"t\":%" PRId64 ",\"duration_ms\":%" PRIu64
        ",\"peer\":\"%s\",\"sni\":\"%s\",\"tcp\":%d,\"tls\":\"%s\",\"end\":\"%s\","
        "\"errno\":%d,\"up\":%" PRIu64 ",\"down\":%" PRIu64 "}\n",
        (int64_t)now, monotonic_ms() - f->started, f->ip, f->host, f->tcp,
        f->first_tls ? f->first_tls : "", f->finished ? f->finished : "close",
        f->error, f->up, f->down);
    fclose(file);
}

static void emit(const struct flow *f, const char *event, int error) {
    __android_log_print(ANDROID_LOG_INFO, "BbdLab",
        "flow event=%s id=%u proto=%s peer=%s port=%u up=%" PRIu64 " down=%" PRIu64 " errno=%d",
        event, f->id, f->type == SOCK_DGRAM ? "udp" : "tcp", f->ip,
        f->port, f->up, f->down, error);
}

static int valid_fd(int fd) { return fd >= 0 && fd < MAX_FD; }

static void begin_flow(int fd, const struct sockaddr *addr, socklen_t len, int error) {
    if (!valid_fd(fd) || !addr || len < sizeof(addr->sa_family)) return;
    struct flow f = {0};
    const void *ip;
    if (addr->sa_family == AF_INET && len >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *v4 = (const void *)addr;
        f.port = ntohs(v4->sin_port);
        ip = &v4->sin_addr;
    } else if (addr->sa_family == AF_INET6 && len >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *v6 = (const void *)addr;
        f.port = ntohs(v6->sin6_port);
        ip = &v6->sin6_addr;
    } else {
        return;
    }
    if (f.port != 443 && f.port != 80 && f.port != 53 && f.port != 853) return;
    if (!inet_ntop(addr->sa_family, ip, f.ip, sizeof(f.ip))) return;
    socklen_t type_len = sizeof(f.type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &f.type, &type_len) != 0 ||
        (f.type != SOCK_STREAM && f.type != SOCK_DGRAM)) return;

    pthread_mutex_lock(&flows_lock);
    f.id = ++next_id;
    f.last_log = f.started = monotonic_ms();
    if (error == 0 || error == EINPROGRESS || error == EALREADY) {
        if (flows[fd].id) emit(&flows[fd], "reconnect", 0);
        flows[fd] = f;
        emit(&f, "connect", error);
    } else {
        f.tcp = -1;
        f.error = error;
        f.finished = "connect_error";
        journal(&f);
        emit(&f, "connect_error", error);
    }
    pthread_mutex_unlock(&flows_lock);
}

static void stage(const struct flow *f, const char *event, int error) {
    __android_log_print(ANDROID_LOG_INFO, "BbdLab",
        "stage event=%s id=%u errno=%d", event, f->id, error);
}

void lab_tcp_status(int fd, int error) {
    if (!valid_fd(fd)) return;
    pthread_mutex_lock(&flows_lock);
    struct flow *f = &flows[fd];
    if (f->id && f->type == SOCK_STREAM) {
        f->tcp = error == 0 ? 1 : -1;
        f->error = error;
        stage(f, error == 0 ? "tcp_ready" : "tcp_failed", error);
    }
    pthread_mutex_unlock(&flows_lock);
}

static int domain_suffix(const char *host, size_t len, const char *suffix) {
    size_t n = strlen(suffix);
    return len >= n && (len == n || host[len - n - 1] == '.')
        && memcmp(host + len - n, suffix, n) == 0;
}

void lab_client_hello(int fd, const char *data, size_t len) {
    if (!valid_fd(fd) || !is_tls_chello(data, len)) return;
    char *host = NULL;
    int n = parse_tls(data, len, &host);
    if (n <= 0 || n > 253 || !host) return;
    for (int i = 0; i < n; i++) {
        char c = host[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.'))
            return;
    }
    if (!domain_suffix(host, n, "googlevideo.com") &&
        !domain_suffix(host, n, "youtube.com") &&
        !domain_suffix(host, n, "youtubei.googleapis.com")) return;
    pthread_mutex_lock(&flows_lock);
    struct flow *f = &flows[fd];
    if (f->id && f->type == SOCK_STREAM && !f->tls_expected) {
        memcpy(f->host, host, (size_t)n);
        f->host[n] = '\0';
        f->tls_expected = 1;
        f->media = n > 3 && host[0] == 'r' && host[1] == 'r'
            && host[2] >= '0' && host[2] <= '9' && domain_suffix(host, n, "googlevideo.com");
        __android_log_print(ANDROID_LOG_INFO, "BbdLab",
            "hello id=%u sni=%.*s bytes=%zu", f->id, n, host, len);
    }
    pthread_mutex_unlock(&flows_lock);
}

int lab_set_hello_wait(const char *value) {
    char *end;
    long parsed = strtol(value, &end, 10);
    if (!*value || *end || parsed < 250 || parsed > 10000) return -1;
    hello_wait_ms = (int)parsed;
    return 0;
}

int lab_arm_hello_wait(int fd) {
    if (!hello_wait_ms || !valid_fd(fd)) return 0;
    pthread_mutex_lock(&flows_lock);
    struct flow *f = &flows[fd];
    int wait = 0;
    if (f->id && f->media && !f->hello_wait && !f->down && f->up) {
        f->hello_wait = 1;
        wait = hello_wait_ms;
        stage(f, "hello_wait", 0);
    }
    pthread_mutex_unlock(&flows_lock);
    return wait;
}

int lab_has_hello_wait(int fd) {
    if (!hello_wait_ms || !valid_fd(fd)) return 0;
    pthread_mutex_lock(&flows_lock);
    const struct flow *f = &flows[fd];
    int pending = f->id && f->hello_wait == 1;
    pthread_mutex_unlock(&flows_lock);
    return pending;
}

int lab_finish_hello_wait(int fd, int timed_out) {
    if (!hello_wait_ms || !valid_fd(fd)) return 0;
    pthread_mutex_lock(&flows_lock);
    struct flow *f = &flows[fd];
    int pending = f->id && f->hello_wait == 1;
    if (pending) {
        f->hello_wait = 2;
        if (timed_out) stage(f, "hello_timeout", 0);
    }
    pthread_mutex_unlock(&flows_lock);
    return pending;
}

static void account_receive(int fd, const void *data, ssize_t size, int error) {
    if (!valid_fd(fd)) return;
    pthread_mutex_lock(&flows_lock);
    struct flow *f = &flows[fd];
    if (f->id && f->type == SOCK_STREAM) {
        if (size > 0 && f->tls_expected && !f->tls_observed) {
            size_t take = sizeof(f->tls_start) - f->tls_bytes;
            if (take > (size_t)size) take = (size_t)size;
            memcpy(f->tls_start + f->tls_bytes, data, take);
            f->tls_bytes += take;
            if (f->tls_bytes == sizeof(f->tls_start)) {
                const unsigned char *h = f->tls_start;
                const char *event = "first_tls_other";
                if (h[1] == 3 && h[2] <= 4) {
                    if (h[0] == 22 && h[5] == 2) event = "server_hello";
                    else if (h[0] == 21) event = "tls_alert";
                }
                stage(f, event, 0);
                f->first_tls = event;
                f->tls_observed = 1;
            }
        } else if (size <= 0 && !f->read_ended &&
                   (size == 0 || (error != EAGAIN && error != EWOULDBLOCK && error != EINTR))) {
            stage(f, size == 0 ? "read_eof" : "read_error", size == 0 ? 0 : error);
            f->finished = size == 0 ? "read_eof" : "read_error";
            if (size < 0) f->error = error;
            f->read_ended = 1;
        }
    }
    pthread_mutex_unlock(&flows_lock);
}

static void account(int fd, ssize_t size, int incoming) {
    if (!valid_fd(fd) || size <= 0) return;
    pthread_mutex_lock(&flows_lock);
    struct flow *f = &flows[fd];
    if (f->id) {
        int first_down = incoming && f->down == 0;
        int first_up = !incoming && f->up == 0 && f->tls_expected;
        if (incoming) f->down += (uint64_t)size;
        else f->up += (uint64_t)size;
        uint64_t now = monotonic_ms();
        if (first_up || first_down || now - f->last_log >= 1000) {
            emit(f, first_up ? "first_up" : first_down ? "first_down" : "bytes", 0);
            f->last_log = now;
        }
    }
    pthread_mutex_unlock(&flows_lock);
}

int __wrap_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    int result = __real_connect(fd, addr, len);
    int saved = errno;
    begin_flow(fd, addr, len, result < 0 ? saved : 0);
    if (result == 0) lab_tcp_status(fd, 0);
    errno = saved;
    return result;
}

int __wrap_close(int fd) {
    int saved = errno;
    if (valid_fd(fd)) {
        pthread_mutex_lock(&flows_lock);
        if (flows[fd].id) {
            journal(&flows[fd]);
            emit(&flows[fd], "close", 0);
            flows[fd].id = 0;
        }
        pthread_mutex_unlock(&flows_lock);
    }
    errno = saved;
    return __real_close(fd);
}

ssize_t __wrap_recv(int fd, void *buf, size_t size, int flags) {
    ssize_t count = __real_recv(fd, buf, size, flags);
    int saved = errno;
    if (!(flags & MSG_PEEK)) {
        account_receive(fd, buf, count, saved);
        account(fd, count, 1);
    }
    errno = saved;
    return count;
}

ssize_t __wrap_recvfrom(int fd, void *buf, size_t size, int flags,
                        struct sockaddr *addr, socklen_t *len) {
    ssize_t count = __real_recvfrom(fd, buf, size, flags, addr, len);
    int saved = errno;
    if (!(flags & MSG_PEEK)) {
        account_receive(fd, buf, count, saved);
        account(fd, count, 1);
    }
    errno = saved;
    return count;
}

ssize_t __wrap_send(int fd, const void *buf, size_t size, int flags) {
    ssize_t count = __real_send(fd, buf, size, flags);
    int saved = errno;
    account(fd, count, 0);
    errno = saved;
    return count;
}

ssize_t __wrap_sendto(int fd, const void *buf, size_t size, int flags,
                      const struct sockaddr *addr, socklen_t len) {
    ssize_t count = __real_sendto(fd, buf, size, flags, addr, len);
    int saved = errno;
    account(fd, count, 0);
    errno = saved;
    return count;
}

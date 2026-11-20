#define _POSIX_C_SOURCE 200809L
#include <android/log.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

enum { MAX_FD = 8192 };
struct flow {
    unsigned id;
    int type;
    unsigned port;
    char ip[INET6_ADDRSTRLEN];
    uint64_t up, down, last_log;
};

static struct flow flows[MAX_FD];
static unsigned next_id;
static pthread_mutex_t flows_lock = PTHREAD_MUTEX_INITIALIZER;

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
    f.last_log = monotonic_ms();
    if (error == 0 || error == EINPROGRESS || error == EALREADY) {
        if (flows[fd].id) emit(&flows[fd], "reconnect", 0);
        flows[fd] = f;
        emit(&f, "connect", error);
    } else {
        emit(&f, "connect_error", error);
    }
    pthread_mutex_unlock(&flows_lock);
}

static void account(int fd, ssize_t size, int incoming) {
    if (!valid_fd(fd) || size <= 0) return;
    pthread_mutex_lock(&flows_lock);
    struct flow *f = &flows[fd];
    if (f->id) {
        int first_down = incoming && f->down == 0;
        if (incoming) f->down += (uint64_t)size;
        else f->up += (uint64_t)size;
        uint64_t now = monotonic_ms();
        if (first_down || now - f->last_log >= 1000) {
            emit(f, first_down ? "first_down" : "bytes", 0);
            f->last_log = now;
        }
    }
    pthread_mutex_unlock(&flows_lock);
}

int __wrap_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    int result = __real_connect(fd, addr, len);
    int saved = errno;
    begin_flow(fd, addr, len, result < 0 ? saved : 0);
    errno = saved;
    return result;
}

int __wrap_close(int fd) {
    int saved = errno;
    if (valid_fd(fd)) {
        pthread_mutex_lock(&flows_lock);
        if (flows[fd].id) {
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
    if (!(flags & MSG_PEEK)) account(fd, count, 1);
    errno = saved;
    return count;
}

ssize_t __wrap_recvfrom(int fd, void *buf, size_t size, int flags,
                        struct sockaddr *addr, socklen_t *len) {
    ssize_t count = __real_recvfrom(fd, buf, size, flags, addr, len);
    int saved = errno;
    if (!(flags & MSG_PEEK)) account(fd, count, 1);
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

/* Test-only Linux syscall fault/trace library, loaded only in isolated children. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int fsync(int fd) {
    const char *root = getenv("NEXUS_CAS_SYNC_ROOT");
    const char *target = getenv("NEXUS_CAS_SYNC_TARGET");
    const char *trace = getenv("NEXUS_CAS_SYNC_TRACE");
    const char *fault = getenv("NEXUS_CAS_SYNC_FAULT");
    char descriptor[64], path[4096];
    struct stat info;
    snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", fd);
    ssize_t count = readlink(descriptor, path, sizeof(path) - 1);
    if (!root || !target || !trace || count < 0 || fstat(fd, &info)) {
        return syscall(SYS_fsync, fd);
    }
    path[count] = '\0';
    size_t root_len = strlen(root), path_len = strlen(path);
    int inside = strncmp(path, root, root_len) == 0 &&
                 (path[root_len] == '/' || path[root_len] == '\0');
    int ancestor = S_ISDIR(info.st_mode) && strncmp(root, path, path_len) == 0 &&
                   (path_len == 1 || root[path_len] == '/' || root[path_len] == '\0');
    if (!inside && !ancestor) return syscall(SYS_fsync, fd);
    int visible = access(target, F_OK) == 0;
    int directory = S_ISDIR(info.st_mode);
    char parent[4096];
    snprintf(parent, sizeof(parent), "%s", target);
    char *slash = strrchr(parent, '/');
    if (slash) *slash = '\0';
    int fail = fault && (
        (strcmp(fault, "published-dir") == 0 && directory && visible && strcmp(path, parent) == 0) ||
        (strcmp(fault, "prepare-dir") == 0 && directory && !visible && strcmp(path, parent) == 0) ||
        (strcmp(fault, "staged-file") == 0 && !directory && inside && !visible) ||
        (strcmp(fault, "existing-file") == 0 && !directory && strcmp(path, target) == 0));
    char event[8192];
    int length = snprintf(event, sizeof(event), "%c|%d|%d|%s\n",
                          directory ? 'D' : 'F', visible, fail, path);
    int log = open(trace, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (log < 0 || write(log, event, length) != length) _exit(91);
    close(log);
    if (fault && strcmp(fault, "pause-file") == 0 && !directory && inside) {
        const char *marker = getenv("NEXUS_CAS_SYNC_MARKER");
        int notice = marker ? open(marker, O_WRONLY | O_CREAT | O_CLOEXEC, 0600) : -1;
        if (notice < 0 || write(notice, "1", 1) != 1) _exit(92);
        close(notice);
        for (;;) pause();
    }
    if (fail) {
        errno = EIO;
        return -1;
    }
    return syscall(SYS_fsync, fd);
}

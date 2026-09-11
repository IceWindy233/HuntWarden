#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t stopping = 0;
static pid_t *children = NULL;
static long child_count = 0;

static void stop_handler(int signal_number) {
    (void)signal_number;
    stopping = 1;
}

static void terminate_children(void) {
    for (long index = 0; index < child_count; index++) {
        if (children[index] > 0) kill(children[index], SIGTERM);
    }
    while (waitpid(-1, NULL, 0) > 0 || errno == EINTR) {}
}

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    char *end = NULL;
    long requested = strtol(argv[1], &end, 10);
    if (!end || *end != '\0' || requested < 1 || requested > 10000) return 64;
    children = calloc((size_t)requested, sizeof(pid_t));
    if (!children) return 70;
    signal(SIGTERM, stop_handler);
    signal(SIGINT, stop_handler);
    for (long index = 0; index < requested; index++) {
        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "fork stopped at %ld/%ld: %s\n", index, requested, strerror(errno));
            terminate_children();
            return 71;
        }
        if (pid == 0) {
            signal(SIGTERM, SIG_DFL);
            signal(SIGINT, SIG_DFL);
            prctl(PR_SET_PDEATHSIG, SIGTERM);
            prctl(PR_SET_NAME, "hw-load-worker");
            for (;;) pause();
            _exit(0);
        }
        children[child_count++] = pid;
    }
    FILE *ready = fopen("/run/huntwarden-load-processes.ready", "w");
    if (!ready) {
        terminate_children();
        return 72;
    }
    fprintf(ready, "%ld\n", child_count);
    fclose(ready);
    while (!stopping) pause();
    terminate_children();
    free(children);
    return 0;
}

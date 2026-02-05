/* shell.c */
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <fcntl.h>
#include <ucontext.h>
#include <stdint.h>

#define BUFSIZE         128
#define FILENAME_LEN    64
#define MAXARGS         32
#define RD_PIPE         0
#define WR_PIPE         1
#define OPT_PIPERD      1   // reads from pipe
#define OPT_PIPEWR      2   // writes to pipe
#define OPT_BGTASK      4   // background task
#define OPT_RDROUT      8   // redirected output
#define OPT_RDRIN       16  // redirected input
#define MAX_BG_TASKS    32

// shell child process/task struct
typedef struct task_t {
    pid_t pid;
    char *argv[MAXARGS];
    uint8_t opt;
    char *filename;
} task_t;

// background task list struct
typedef struct bg_list_t {
    pid_t bg_tasks[MAX_BG_TASKS];
    uint8_t bg_task_count;
} bg_list_t;

// globals
bg_list_t bg_list;
ucontext_t uc;

int
bg_list_remove(bg_list_t *bg_list, pid_t bg_pid)
{
    for (int i = 0; i < MAX_BG_TASKS; ++i) {
        if (bg_list->bg_tasks[i] == bg_pid) {
            bg_list->bg_tasks[i] = 0;
            return bg_list->bg_task_count--;
        }
    }
    return -1;
}

int
bg_list_add(bg_list_t *bg_list, pid_t bg_pid)
{
    if (bg_list->bg_task_count == MAX_BG_TASKS)
        return -1;
    for (int i = 0; i < MAX_BG_TASKS; ++i) {
        if (bg_list->bg_tasks[i] == 0) {
            bg_list->bg_tasks[i] = bg_pid;
            return ++bg_list->bg_task_count;
        }
    }
    return -1;
}

void
bg_list_check(bg_list_t *bg_list)
{
    pid_t bg_pid;
    int id, rc, wstatus;
    for (int i = 0; i < MAX_BG_TASKS; ++i) {
        if ((bg_pid = waitpid(bg_list->bg_tasks[i], &wstatus, WNOHANG)) > 0) {
            if ((id = bg_list_remove(bg_list, bg_pid)) != -1) {
                if (WIFEXITED(wstatus) && ((rc = WEXITSTATUS(wstatus))) != 0)
                    printf("[%d] %d exit %d\n", id, bg_pid, rc); 
                else
                    printf("[%d] %d done\n", id, bg_pid);
            }
        }
    }
    return;
}

void
sig_handler(int sig)
{
    pid_t pid, bg_id;
    switch (sig) {
        case SIGUSR1:
            if (setcontext(&uc) < 0)
                perror("setcontext");
            return;
        case SIGINT:
            putchar('\n');
            if (setcontext(&uc) < 0)
                perror("setcontext");
            return;
    }
}

int
count_tasks(char *cmd)
{
    if (cmd[0] == '\n')
        return 0;
    int ntasks = 1;
    for (int i = 0; i < strlen(cmd); ++i) {
        if (cmd[i] == '\n') {
            return ntasks;
        } else if (cmd[i] == '\'' || cmd[i] == '\"') {
            char delim = cmd[i] == '\'' ? '\'' : '\"';
            while (cmd[++i] != delim)
                ;
            continue;
        } else if (cmd[i] == '|') {
            ++ntasks;
        } else if (cmd[i] == '&') {
            while (cmd[++i] == ' ')
                ;
            if (cmd[i] == '\n')
                return ntasks;
            ++ntasks;
        }
    }
    return ntasks;
}

int
parse_command(char *cmd, task_t tasks[], int ntasks)
{
    int cur = 0, prev = 0, len = strlen(cmd);
    if (cmd[0] == ' ') {
        while (cmd[++cur] == ' ')
            ;
        prev = cur;
    }
    for (int tn = 0; tn < ntasks; ++tn) {
        int argc = 0;
        while (1) {
            if (cmd[cur] == '\n') {
                if (prev < cur)
                    tasks[tn].argv[argc++] = strndup(cmd + prev, cur - prev);
                if (!(tasks[tn].opt & (OPT_RDROUT | OPT_RDRIN)))
                    tasks[tn].filename = NULL;
                tasks[tn].argv[argc] = NULL;
                goto success;
            } else if (cmd[cur] == '\'' || cmd[cur] == '\"') {
                char delim = (cmd[cur] == '\'') ? '\'' : '\"';
                while (cmd[++cur] != delim)
                    ;
                ++prev;
                tasks[tn].argv[argc++] = strndup(cmd + prev, cur - prev);
                while (cmd[++cur] == ' ')
                    ;
                prev = cur;
                continue;
            } else if (cmd[cur] == ' ') {
                tasks[tn].argv[argc++] = strndup(cmd + prev, cur - prev);
                while (cmd[++cur] == ' ')
                    ;
                prev = cur;
                continue;
            } else if (cmd[cur] == '|' || cmd[cur] == '&' ||
                       cmd[cur] == '>' || cmd[cur] == '<') {
                if (prev < cur)
                    tasks[tn].argv[argc++] = strndup(cmd + prev, cur - prev);
                switch (cmd[cur]) {
                    case '|':
                        tasks[tn].opt |= OPT_PIPEWR;
                        tasks[tn + 1].opt |= OPT_PIPERD;
                        break;
                    case '&':
                        tasks[tn].opt |= OPT_BGTASK;
                        for (int tmp = tn - 1; tmp >= 0; --tmp) {
                            if (tasks[tmp].opt & OPT_BGTASK)
                                break;
                            tasks[tmp].opt |= OPT_BGTASK;
                        }
                        break;
                    default:
                        if (cmd[cur] == '>')
                            tasks[tn].opt |= OPT_RDROUT;
                        else
                            tasks[tn].opt |= OPT_RDRIN;
                        while (cmd[++cur] == ' ')
                            ;
                        prev = cur;
                        while (!(cmd[cur] == ' ' || cmd[cur] == '\n' ||
                                 cmd[cur] == '|' || cmd[cur] == '&' ||
                                 cmd[cur] == '<' || cmd[cur] == '>')) {
                            ++cur;
                        }
                        tasks[tn].filename = strndup(cmd + prev, cur - prev);
                        break;
                }
                if (!(tasks[tn].opt & (OPT_RDROUT | OPT_RDRIN)))
                    tasks[tn].filename = NULL;
                while (cmd[++cur] == ' ')
                    ;
                prev = cur;
                tasks[tn].argv[argc] = NULL;
                break;
            }
            ++cur;
        }
    }
    success:
        return 0;
    fail:
        return -1;
}

void
spawn_tasks(task_t tasks[], int ntasks)
{
    int pending = ntasks;
    int rc, fd, id, pipefds[2];
    while (pending--) {
        if (tasks[pending].opt & OPT_PIPERD) {
            if (pipe(pipefds) < 0) {
               fprintf(stderr, "pipe: %s %s\n", tasks[pending].argv[0], 
                       tasks[pending - 1].argv[0]);
               --pending;
               continue;
            }
            assert(tasks[pending - 1].opt & OPT_PIPEWR);
        }
        tasks[pending].pid = fork();
        switch (tasks[pending].pid) {
            case -1:
                perror(tasks[pending].argv[0]);
                break;
            case 0:
                signal(SIGINT, SIG_DFL);
                rc = ~-1;
                fd = ~-1;
                if (tasks[pending].opt & OPT_PIPERD) {
                    rc = close(STDIN_FILENO);
                    fd = dup(pipefds[RD_PIPE]);
                    close(pipefds[RD_PIPE]);
                    close(pipefds[WR_PIPE]);
                } else if (tasks[pending].opt & OPT_RDRIN) {
                    fd = open(tasks[pending].filename, O_RDONLY);
                    rc = close(STDIN_FILENO);
                    dup2(fd, STDIN_FILENO);
                } else if (tasks[pending].opt & OPT_PIPEWR) {
                    rc = close(STDOUT_FILENO);
                    fd = dup(pipefds[WR_PIPE]);
                    close(pipefds[RD_PIPE]);
                    close(pipefds[WR_PIPE]);
                } else if (tasks[pending].opt & OPT_RDROUT) {
                    fd = open(tasks[pending].filename, O_WRONLY | O_CREAT |
                              O_TRUNC, S_IRWXU);
                    rc = close(STDOUT_FILENO);
                    dup2(fd, STDOUT_FILENO);
                }
                if (fd < 0 || rc < 0) {
                    perror(tasks[pending].argv[0]);
                    exit(EXIT_FAILURE);
                }
                if (execvp(tasks[pending].argv[0], tasks[pending].argv) < 0) {
                    perror(tasks[pending].argv[0]);
                    kill(getppid(), SIGUSR1);
                    exit(EXIT_FAILURE);
                }
            default:
                if (tasks[pending].opt & OPT_BGTASK)
                    if ((id = bg_list_add(&bg_list, tasks[pending].pid)) != -1)
                        printf("[%d] %d\n", id, tasks[pending].pid);
                if (tasks[pending].opt & OPT_PIPEWR) {
                    close(pipefds[RD_PIPE]);
                    close(pipefds[WR_PIPE]);
                }
                break;
        }
    }
    for (int i = 0; i < ntasks; ++i) {
        if (tasks[i].opt & OPT_BGTASK)
            continue;
        if (waitpid(tasks[i].pid, NULL, 0) < 0)
            perror(tasks[i].argv[0]);
    }
    return;
}

void
free_tasks(task_t tasks[], int ntasks)
{
    for (int i = 0; i < ntasks; ++i) {
        if (tasks[i].opt & (OPT_RDROUT | OPT_RDRIN))
            free(tasks[i].filename);
        for (int j = 0; tasks[i].argv[j] != NULL; ++j)
            free(tasks[i].argv[j]);
    }
}

void 
run_shell()
{
    while (1) {
        getcontext(&uc);
        bg_list_check(&bg_list);
        char buf[BUFSIZE];
        printf("$ ");
        fflush(stdout);
        if (fgets(buf, BUFSIZE, stdin) == NULL && feof(stdin)) {
            putchar('\n');
            goto end;
        }
        int ntasks;
        if ((ntasks = count_tasks(buf)) == 0)
            continue;
        task_t tasks[ntasks];
        memset(tasks, 0, sizeof(task_t) * ntasks);
        if (parse_command(buf, tasks, ntasks) < 0)
            continue;
        spawn_tasks(tasks, ntasks);
        free_tasks(tasks, ntasks);
    }
    end:
        return;
}

int
main(int argc, char *argv[])
{
    memset((void *)&bg_list, 0, sizeof(bg_list));
    signal(SIGINT, sig_handler);
    signal(SIGUSR1, sig_handler);
    run_shell();
    exit(0);
}

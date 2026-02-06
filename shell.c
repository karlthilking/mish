/* shell.c */
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <fcntl.h>
#include <ucontext.h>
#include <stdint.h>

#define BUFSIZE         128
#define MAXARGS         32
#define RD_PIPE         0
#define WR_PIPE         1
/* task options so task.opt is either 0 or the logical or of one or more options */
#define OPT_PIPERD      1   // reads from pipe
#define OPT_PIPEWR      2   // writes to pipe
#define OPT_BGTASK      4   // background task
#define OPT_RDROUT      8   // redirected output
#define OPT_RDRIN       16  // redirected input
/* indices reserved for specific purposes in fd array in spawn_tasks */
#define IX_PIPERD       0   // index for pipe reader fd
#define IX_PIPEWR       1   // index for pipe writer fd
#define IX_RDROUT       2   // index for redirected output fd
#define IX_RDRIN        3   // index for redirected input fd
#define MAX_BG_TASKS    32
#define PIPE_UNUSED     0   // if pipefd1 and pipefd2 are not used/valid fds
#define PIPE_USED1      1   // if pipefd1 is being used
#define PIPE_USED2      2   // if pipefd2 is being used
#define PIPE_READ1      4   // if child process has to read and write using pipes, this
                            // flag indicates if they should use pipe1 for reading

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
static int recv_sigint; // 1: received SIGINT, 0: no signal

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

// check to see if any background tasks have completed, if so, report
// exit info
int
bg_list_check(bg_list_t *bg_list)
{
    pid_t bg_pid;
    int id, rc, wstatus;
    int removed = 0;
    for (int i = 0; i < MAX_BG_TASKS; ++i) {
        if ((bg_pid = waitpid(bg_list->bg_tasks[i], &wstatus, WNOHANG)) > 0 &&
            ((id = bg_list_remove(bg_list, bg_pid))) != -1) {
            if (!removed++)
                putchar('\n');
            if (WIFEXITED(wstatus) && (rc = WEXITSTATUS(wstatus)) != 0) {
                if (rc == ENOENT || rc == EBADF || rc == EACCES)
                    continue;
                printf("[%d] %d exit %d\n", id, bg_pid, rc);
            } else {
                printf("[%d] %d done\n", id, bg_pid);
            }
        }
    }
    return removed;
}

void *
sighandler(int sig)
{
    if (sig == SIGINT) {
        printf("\n$ ");
        fflush(stdout);
        recv_sigint = 1;
    }
    return NULL;
}

int
count_tasks(char *cmd)
{
    if (cmd[0] == '\n')
        return 0;
    int ntasks = 1;
    for (size_t i = 0; i < strlen(cmd); ++i) {
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
    int cur = 0, prev = 0;
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
                goto end;
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
            } else if (cmd[cur] == '>' || cmd[cur] == '<') {
                if (prev < cur)
                    tasks[tn].argv[argc++] = strndup(cmd + prev, cur - prev);
                switch (cmd[cur]) {
                    case '>':
                        tasks[tn].opt |= OPT_RDROUT;
                        break;
                    case '<':
                        tasks[tn].opt |= OPT_RDRIN;
                        break;
                }
                while (cmd[++cur] == ' ')
                    ;
                prev = cur;
                while (!(cmd[cur] == ' ' || cmd[cur] == '\n' ||
                         cmd[cur] == '|' || cmd[cur] == '&' ||
                         cmd[cur] == '<' || cmd[cur] == '>')) {
                    ++cur;
                }
                tasks[tn].filename = strndup(cmd + prev, cur - prev);
                if (cmd[cur] == '\n')
                    break;
                else if (cmd[cur] != ' ')
                    continue;
                while (cmd[++cur] == ' ')
                    ;
                prev = cur;
                continue;
            } else if (cmd[cur] == '|' || cmd[cur] == '&') {
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
                }
                while (cmd[++cur] == ' ')
                    ;
                prev = cur;
                tasks[tn].argv[argc] = NULL;
                if (!(tasks[tn].opt & (OPT_RDRIN | OPT_RDROUT)))
                    tasks[tn].filename = NULL;
                break;
            }
            ++cur;
        }
    }
    end:
        return 0;
}

void
spawn_tasks(task_t tasks[], int ntasks)
{
    int pending = ntasks;
    int bgid, pipefd1[2], pipefd2[2], fds[4];
    int pipe_status = PIPE_UNUSED;
    while (pending--) {
        if (tasks[pending].opt & OPT_PIPERD) {
            if (pipe_status == PIPE_UNUSED || pipe_status & PIPE_USED2) {
                assert(!(pipe_status & PIPE_USED1));
                if (pipe(pipefd1) < 0 || fcntl(pipefd1[0], F_SETFD, FD_CLOEXEC) < 0 ||
                    fcntl(pipefd1[1], F_SETFD, FD_CLOEXEC) < 0) {
                    fprintf(stderr, "pipe %s %s: %s\n", 
                            tasks[pending].argv[0],
                            tasks[pending - 1].argv[0], 
                            strerror(errno));
                    --pending;
                    continue;
                }
                // pipe1 is going to be used and this task is reading from it
                pipe_status |= PIPE_USED1 | PIPE_READ1;
            } else {
                assert(!(pipe_status & PIPE_USED2) && (pipe_status & PIPE_USED1));
                if (pipe(pipefd2) < 0 || fcntl(pipefd2[0], F_SETFD, FD_CLOEXEC) < 0 ||
                    fcntl(pipefd2[1], F_SETFD, FD_CLOEXEC) < 0) {
                    fprintf(stderr, "pipe %s %s: %s\n", 
                            tasks[pending].argv[0], 
                            tasks[pending - 1].argv[0], 
                            strerror(errno));
                    --pending;
                    continue;
                }
                pipe_status |= PIPE_USED2;
            }
            // if current task reads from a pipe, then it must be true that the next
            // task is the one writing to same pipe
            assert(tasks[pending - 1].opt & OPT_PIPEWR);
        }
        tasks[pending].pid = fork();
        switch (tasks[pending].pid) {
            case -1:
                perror(tasks[pending].argv[0]);
                break;
            case 0:
                signal(SIGINT, SIG_DFL);
                // dup2 implicitly calls close on the newfd (second argument)
                if (tasks[pending].opt & OPT_PIPERD) {
                    if (pipe_status & PIPE_READ1) {
                        if (dup2(pipefd1[RD_PIPE], STDIN_FILENO) < 0)
                            err(errno, "dup2");
                    } else if (dup2(pipefd2[RD_PIPE], STDIN_FILENO) < 0) {
                        err(errno, "dup2");
                    }
                }
                if (tasks[pending].opt & OPT_PIPEWR) {
                    if (!(pipe_status ^ (PIPE_USED1 | PIPE_USED2)) || 
                        !(pipe_status & PIPE_USED2)) {
                        if (dup2(pipefd1[WR_PIPE], STDOUT_FILENO) < 0)
                            err(errno, "dup2");
                    } else if (dup2(pipefd2[WR_PIPE], STDOUT_FILENO) < 0) {
                        err(errno, "dup2");
                    }
                }
                if (tasks[pending].opt & OPT_RDRIN) {
                    if ((fds[IX_RDRIN] = open(tasks[pending].filename,
                                              O_RDONLY)) < 0) {
                        err(errno, "open");
                    }
                    if (fcntl(fds[IX_RDRIN], F_SETFD, FD_CLOEXEC) < 0)
                        err(errno, "fcntl");
                    if (dup2(fds[IX_RDRIN], STDIN_FILENO) < 0)
                        err(errno, "dup2");
                }
                if (tasks[pending].opt & OPT_RDROUT) {
                    if ((fds[IX_RDROUT] = open(tasks[pending].filename,
                                               O_WRONLY | O_CREAT | O_TRUNC, 
                                               S_IRWXU)) < 0) {
                        err(errno, "open");
                    }
                    if (fcntl(fds[IX_RDROUT], F_SETFD, FD_CLOEXEC) < 0)
                        err(errno, "fcntl");
                    if (dup2(fds[IX_RDROUT], STDOUT_FILENO) < 0)
                        err(errno, "dup2");
                }
                if (execvp(tasks[pending].argv[0], tasks[pending].argv) < 0) {
                    // if execvp fails then the FD_CLOEXEC flag does not do anything
                    // (the fd is left open) so the child process is reponsible for
                    // closing any of its fds before reporting the error
                    if (tasks[pending].opt & OPT_RDRIN) {
                        close(fds[IX_RDRIN]);
                    } else if (tasks[pending].opt & OPT_RDROUT) {
                        close(fds[IX_RDROUT]);
                    } else if (tasks[pending].opt & OPT_PIPERD) {
                        if (pipe_status & PIPE_READ1)
                            close(pipefd1[RD_PIPE]);
                        else
                            close(pipefd2[RD_PIPE]);
                    } else if (tasks[pending].opt & OPT_PIPEWR) {
                        if (!(pipe_status ^ (PIPE_USED1 | PIPE_USED2)) ||
                            !(pipe_status & PIPE_USED2))
                            close(pipefd1[WR_PIPE]);
                        else
                            close(pipefd2[WR_PIPE]);
                    }
                    err(errno, tasks[pending].argv[0]);
                }
                break;
            default:
                if (tasks[pending].opt & OPT_BGTASK)
                    if ((bgid = bg_list_add(&bg_list, tasks[pending].pid)) != -1)
                        printf("[%d] %d\n", bgid, tasks[pending].pid);
                if (tasks[pending].opt & OPT_PIPEWR) {
                    if (!(pipe_status ^ (PIPE_USED1 | PIPE_USED2)) ||
                        !(pipe_status & PIPE_USED2)) {
                        close(pipefd1[RD_PIPE]);
                        close(pipefd1[WR_PIPE]);
                        pipe_status ^= PIPE_USED1;
                    } else {
                        close(pipefd2[RD_PIPE]);
                        close(pipefd2[WR_PIPE]);
                        pipe_status ^= PIPE_USED2;
                    }
                }
                if ((tasks[pending].opt & OPT_PIPERD) && (pipe_status & PIPE_READ1))
                    pipe_status ^= PIPE_READ1;
                break;
        }
    }
    int wstatus, rc;
    for (int i = 0; i < ntasks; ++i) {
        if (tasks[i].opt & OPT_BGTASK)
            continue;
        if (waitpid(tasks[i].pid, &wstatus, 0) < 0)
            perror(tasks[i].argv[0]);
        if (WIFEXITED(wstatus) && ((rc = WEXITSTATUS(wstatus))) != 0) {
            // child processes that fail before exec or from exec return the current errno
            // so an exit status of ENOENT and EBADF indicate that the program was never
            // executed; thus, don't report the exit status of a child process than never
            // started execution
            if (rc == ENOENT || rc == EBADF || rc == EACCES)
                continue;
            printf("%s exit %d\n", tasks[i].argv[0], WEXITSTATUS(wstatus));
        }
    }
    return;
}

// task argv strings and filenames (for tasks with input or output redirection) use
// strndup to allocate these strings; strndup calls malloc internally so each string
// must be freed before the task is deallocated
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
        if (recv_sigint) {
            recv_sigint = 0;
        } else {
            printf("$ ");
            fflush(stdout);
        }
        if (bg_list.bg_task_count && bg_list_check(&bg_list) > 0) {
            printf("$ ");
            fflush(stdout);
        }
        char buf[BUFSIZE];
        if (fgets(buf, BUFSIZE, stdin) == NULL && feof(stdin)) {
            putchar('\n');
            goto end;
        }
        int ntasks;
        if ((ntasks = count_tasks(buf)) == 0) {
            // when recv_sigint is 1 (SIGINT was received) typically the
            // shell should not print reprompt because the sighandler will
            // handle the reprompt, but if a user sends a interrupt followed
            // by a newline (ntasks == 0), the shell will hang and not
            // reprompt so when ntasks == 0 toggle recv_sigint off anyways
            if (recv_sigint)
                recv_sigint = 0;
            continue;
        }
        task_t tasks[ntasks];
        memset((void *)tasks, 0, sizeof(task_t) * ntasks);
        if (parse_command(buf, tasks, ntasks) < 0)
            continue;
        spawn_tasks(tasks, ntasks);
        free_tasks(tasks, ntasks);
    }
    end:
        return;
}

int
main(void)
{
    memset((void *)&bg_list, 0, sizeof(bg_list));
    recv_sigint = 0;
    signal(SIGINT, (void *)&sighandler);
    run_shell();
    exit(0);
}

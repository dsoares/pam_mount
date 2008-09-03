/*
 *	Copyright © Jan Engelhardt, 2006 - 2008
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libHX/defs.h>
#include <libHX/deque.h>
#include <libHX/misc.h>
#include "misc.h"
#include "pam_mount.h"
#include "spawn.h"

/* Variables */
static struct sigaction saved_handler = {.sa_handler = SIG_DFL};

//-----------------------------------------------------------------------------
/**
 * spawn_build_pipes -
 * @fd_request:	user array to tell us which pipe sets to create
 * @p:		result array
 *
 * Create some pipes.
 * Explicitly initialize the @p array with -1 so that we can call close()
 * on all of them without any side effects.
 */
static inline int spawn_build_pipes(const int **fd_request, int (*p)[2])
{
	unsigned int x, y;
	for (x = 0; x < 3; ++x)
		for (y = 0; y < 2; ++y)
			p[x][y] = -1;

	if (fd_request[0] != NULL && pipe(p[0]) < 0)
		return -errno;
	if (fd_request[1] != NULL && pipe(p[1]) < 0)
		return -errno;
	if (fd_request[2] != NULL && pipe(p[2]) < 0)
		return -errno;
	return 1;
}

/**
 * spawn_close_pipes -
 * @p:	pipe fds to close
 *
 * In @p, there might be some fds that are -1 (due to the p[x][y] = -1 in
 * spawn_build_pipes()). That is ok, as closing -1 does not do anything.
 */
static void spawn_close_pipes(int (*p)[2])
{
	if (p[0][0] >= 0)
		close(p[0][0]);
	if (p[0][1] >= 0)
		close(p[0][1]);
	if (p[1][0] >= 0)
		close(p[1][0]);
	if (p[1][1] >= 0)
		close(p[1][1]);
	if (p[2][0] >= 0)
		close(p[2][0]);
	if (p[2][1] >= 0)
		close(p[2][1]);
}

/**
 * spawn_start -
 * @argv:	program and arguments
 * @pid:	resulting PID
 * @fd_stdin:	if non-%NULL, assign stdin
 * @fd_stdout:	if non-%NULL, assign stdout
 * @fd_stderr:	if non-%NULL, assign stderr
 * @setup:	child process setup function
 * @user:	username (used for FUSE)
 *
 * Sets up pipes and runs the specified program.
 *
 * Side effects: Saves the old %SIGCHLD handler before and overrides it with
 * %SIG_DFL. This is needed because otherwise GDM's signal handler would
 * trigger with pam_mount's child processes.
 *
 * On success, returns true and the handler is NOT reset. Every [successful]
 * call to spawn_start() must be followed by spawn_restore_sigchld(). This is
 * usually done after waitpid(), when we are sure there are no more
 * processes that were created by pam_mount that could potentially confuse GDM.
 *
 * On failure, this function returns false and the original %SIGCHLD handler
 * will be restored.
 */
static bool __spawn_start(const char *const *argv, pid_t *pid, int *fd_stdin,
    int *fd_stdout, int *fd_stderr, void (*setup)(const char *),
    const char *user)
{
	const int *fd_rq[] = {fd_stdin, fd_stdout, fd_stderr};
	int pipes[3][2], ret;

	if ((ret = spawn_build_pipes(fd_rq, pipes)) < 0) {
		l0g("pipe(): %s\n", strerror(-ret));
		return false;
	}

	spawn_set_sigchld();
	if ((*pid = fork()) < 0) {
		l0g("fork(): %s\n", strerror(errno));
		spawn_restore_sigchld();
		spawn_close_pipes(pipes);
		return false;
	} else if (*pid == 0) {
		if (setup != NULL)
			(*setup)(user);
		if (fd_stdin != NULL)
			dup2(pipes[0][0], STDIN_FILENO);
		if (fd_stdout != NULL)
			dup2(pipes[1][1], STDOUT_FILENO);
		if (fd_stderr != NULL)
			dup2(pipes[2][1], STDERR_FILENO);
		spawn_close_pipes(pipes);
		execvp(*argv, const_cast(char * const *, argv));
		l0g("execvp: %s\n", strerror(errno));
		_exit(-1);
	}
	
	if (fd_stdin != NULL) {
		*fd_stdin = pipes[0][1];
		close(pipes[0][0]);
	}
	if (fd_stdout != NULL) {
		*fd_stdout = pipes[1][0];
		close(pipes[1][1]);
	}
	if (fd_stderr != NULL) {
		*fd_stderr = pipes[2][0];
		close(pipes[2][1]);
	}

	return true;
}

bool spawn_start(struct HXdeque *argq, pid_t *pid, int *fd_stdin,
    int *fd_stdout, int *fd_stderr, void (*setup)(const char *),
    const char *user)
{
	char **argv = reinterpret_cast(char **, HXdeque_to_vec(argq, NULL));
	const struct HXdeque_node *n;
	bool ret;

	ret = __spawn_start(const_cast(const char * const *, argv),
	      pid, fd_stdin, fd_stdout, fd_stderr, setup, user);
	free(argv);
	for (n = argq->first; n != NULL; n = n->next)
		hmc_free(n->ptr);
	HXdeque_free(argq);
	return ret;
}

/**
 * spawn_synchronous - like system(), but uses argz array
 */
int spawn_synchronous(const char *const *argv)
{
	pid_t pid;
	int ret;

	if (!__spawn_start(argv, &pid, NULL, NULL, NULL, NULL, NULL))
		return false;
	waitpid(pid, &ret, 0);
	spawn_restore_sigchld();
	return ret;
}

/**
 * spawn_set_sigchld -
 *
 * Save the old SIGCHLD handler and then set SIGCHLD to SIG_DFL. This is used
 * against GDM which does not reap childs as we wanted in its SIGCHLD handler,
 * so we install our own handler. Returns the value from sigaction().
 */
int spawn_set_sigchld(void)
{
	struct sigaction nh;

	if (saved_handler.sa_handler != SIG_DFL) {
		w4rn("saved_handler already grabbed, not overwriting\n");
		return 0;
	}

	memset(&nh, 0, sizeof(nh));
	nh.sa_handler = SIG_DFL;
	sigemptyset(&nh.sa_mask);
	return sigaction(SIGCHLD, &nh, &saved_handler);
}

/**
 * spawn_restore_sigchld -
 *
 * Restore the SIGCHLD handler that was saved during spawn_set_sigchld().
 * Returns the value from sigaction().
 */
int spawn_restore_sigchld(void)
{
	int ret;
	if ((ret = sigaction(SIGCHLD, &saved_handler, NULL)) == -1)
		l0g("%s: sigaction: %s\n", __func__, strerror(errno));
	else
		saved_handler.sa_handler = NULL;
	return ret;
}

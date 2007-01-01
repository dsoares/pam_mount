/*=============================================================================
spawn.c
  Copyright © Jan Engelhardt <jengelh [at] gmx de>, 2006 - 2007

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of
  the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this program; if not, write to:
  Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
  Boston, MA  02110-1301  USA

  -- For details, see the file named "LICENSE.LGPL2"
=============================================================================*/
#include <errno.h>
#include <glib.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include "compiler.h"
#include "misc.h"
#include "spawn.h"

// Variables
static struct sigaction saved_handler = {.sa_handler = SIG_DFL};

//-----------------------------------------------------------------------------
/*  spawn_apS

    Wrapper around that glib funky prototype spawn thing. Saves the old
    %SIGCHLD handler before installing our own (just %SIG_DFL actually).

    On success, returns 1 and the handler is NOT reset. Every [successful] call
    to spawn_apS() must be followed by spawn_restore_sigchld(). This is usually
    done after waitpid(), when we are sure there are no more pam_mount-created
    childs that could potentially confuse GDM.

    On failure, this function returns 0 and the original %SIGCHLD handler will
    be restored.

    All of this mess is required because GDM gets confused when the waitpid()
    from its %SIGCHLD handler sees a PID it did not spawn (note: pam_mount
    creates some). The workaround is to put GDM's %SIGCHLD handler back and
    set our own. Since pam_mount will explicitly wait for the exact PID it
    spawned, GDM childs are not touched. Afterwards, the handler is set back
    to its original value (see semantics above) so that GDM can handle its
    zombies.
*/
int spawn_apS(const char *wd, const char *const *argv, const char *const *envp,
 GSpawnFlags flags, GSpawnChildSetupFunc cs, void *data, int *pid, int *istdin,
 int *istdout, int *istderr, GError **err)
{
    spawn_set_sigchld();
    if(g_spawn_async_with_pipes(wd, const_cast(char **, argv),
      const_cast(char **, envp), flags, cs, data, pid, istdin,
      istdout, istderr, err))
            return 1;
    spawn_restore_sigchld();
    return 0;
}


/*  spawn_set_sigchld

    Save the old SIGCHLD handler and then set SIGCHLD to SIG_DFL. This is used
    against GDM which does not reap childs as we wanted in its SIGCHLD handler,
    so we install our own handler. Returns the value from sigaction().
*/
int spawn_set_sigchld(void) {
    struct sigaction nh;

    if(saved_handler.sa_handler != SIG_DFL) {
        w4rn("%s: saved_handler already grabbed, not overwriting\n");
        return 0;
    }

    memset(&nh, 0, sizeof(nh));
    nh.sa_handler = SIG_DFL;
    sigemptyset(&nh.sa_mask);
    return sigaction(SIGCHLD, &nh, &saved_handler);
}


/*  spawn_restore_sigchld

    Restore the SIGCHLD handler that was saved during spawn_set_sigchld().
    Returns the value from sigaction().
*/
int spawn_restore_sigchld(void) {
    int ret;
    if((ret = sigaction(SIGCHLD, &saved_handler, NULL)) == -1)
        l0g("%s: sigaction: %s\n", __FUNCTION__, strerror(errno));
    else
        saved_handler.sa_handler = NULL;
    return ret;
}

//=============================================================================

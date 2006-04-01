/*=============================================================================
spawn.c
  Copyright © Jan Engelhardt <jengelh [at] gmx de>, 2006

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
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include "misc.h"
#include "spawn.h"

// Variables
static struct sigaction saved_handler = {.sa_handler = SIG_DFL};

//-----------------------------------------------------------------------------
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

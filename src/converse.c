#include <config.h>
#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include <pam_mount.h>

/* adapted from pam_unix/support.c */
static int converse(pam_handle_t * pamh, int ctrl, int nargs,
		    struct pam_message **message,
		    struct pam_response **response)
{
    int retval;
    struct pam_conv *conv;

    w4rn("pam_mount: %s\n", "enter converse");

    retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
    if (retval == PAM_SUCCESS) {

	retval = conv->conv(nargs, (const struct pam_message **) message,
			    response, conv->appdata_ptr);

	w4rn("pam_mount: %s\n", "returned from app's conversation fn");
    }

    w4rn("pam_mount: %s\n", "leave converse");

    return retval;		/* propagate error status */
}

/* adapted from pam_unix/support.c (_unix_read_password) */
int read_password(pam_handle_t * pamh, const char *prompt1, char **pass)
{
    int retval;
    char *token;

    w4rn("pam_mount: %s\n", "enter read_password");

    /*
     * make sure nothing inappropriate gets returned
     */

    *pass = token = NULL;

    {
	struct pam_message msg, *pmsg;
	struct pam_response *resp;

	pmsg = &msg;
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = prompt1;

	/* so call the conversation */
	resp = NULL;
	retval = converse(pamh, 0, 1, &pmsg, &resp);

	/* w4rn ("pam_mount: read_password got: %s\n", resp->resp); */

	if (resp != NULL) {
	    if (retval == PAM_SUCCESS) {	/* a good conversation */
		token = x_strdup(resp->resp);
	    }

	    _pam_drop_reply(resp, 1);
	} else {
	    retval = (retval == PAM_SUCCESS)
		? PAM_AUTHTOK_RECOVER_ERR : retval;
	}
    }

    if (retval != PAM_SUCCESS) {
	return retval;
    }

    *pass = token;

    w4rn("pam_mount: %s\n", "leave read_password");
    return PAM_SUCCESS;
}

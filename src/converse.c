#include <string.h>
#include <config.h>
#include <security/pam_modules.h>

/* ============================ converse () ================================ */ 
/* PRE:    pamh points to a valid pam_handle_t structure
 *         nargs >= 0
 * POST:   response points to a structure containing PAM's (user's) 
 *         response to message
 * FN VAL: any PAM error code encountered or PAM_SUCCESS
 * NOTE:   adapted from pam_unix/support.c */
static int converse(pam_handle_t * pamh, int nargs,
		    const struct pam_message **message,
		    struct pam_response **response)
{
    int retval;
    struct pam_conv *conv;

    w4rn("pam_mount: %s\n", "enter converse");

    retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
    if (retval == PAM_SUCCESS) {

	retval = conv->conv(nargs, message, response, conv->appdata_ptr);

	w4rn("pam_mount: %s\n", "returned from app's conversation fn");
    }

    w4rn("pam_mount: %s\n", "leave converse");

    return retval;		/* propagate error status */
}

/* ============================ read_password () =========================== */ 
/* PRE:    pamh points to a valid pam_handle_t structure
 *         prompt points to a valid string != NULL
 * POST:   pass points to the volume password
 * FN VAL: any PAM error code encountered or PAM_SUCCESS
 * NOTE:   adapted from pam_unix/support.c (_unix_read_password)
 *         fn used to implement try_first_pass when "fist pass" failed */
int read_password(pam_handle_t * pamh, char *prompt1, char **pass)
{
    int retval;
    char *token;

    w4rn("pam_mount: %s\n", "enter read_password");

    /*
     * make sure nothing inappropriate gets returned
     */

    *pass = token = NULL;

    {
	struct pam_message msg;
	const struct pam_message *pmsg = &msg;
	struct pam_response *resp;

	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = prompt1;

	/* so call the conversation */
	resp = NULL;
	retval = converse(pamh, 1, &pmsg, &resp);

	/* w4rn ("pam_mount: read_password got: %s\n", resp->resp); */

	if (resp != NULL) {
	    if (retval == PAM_SUCCESS) {	/* a good conversation */
		token = strdup(resp->resp);
	    }

	    /* FIXME: Not in openpam _pam_drop_reply(resp, 1); */
	} else {
	    /* FIXME: not in openpam: retval = (retval == PAM_SUCCESS)
		? PAM_AUTHTOK_RECOVER_ERR : retval;
*/
		return PAM_SUCCESS;
	}
    }

    if (retval != PAM_SUCCESS) {
	return retval;
    }

    *pass = token;

    w4rn("pam_mount: %s\n", "leave read_password");
    return PAM_SUCCESS;
}

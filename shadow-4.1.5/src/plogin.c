/*
 * Copyright (c) 1989 - 1994, Julianne Frances Haugh
 * Copyright (c) 1996 - 2001, Marek Michałkiewicz
 * Copyright (c) 2001 - 2006, Tomasz Kłoczko
 * Copyright (c) 2007 - 2011, Nicolas François
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the copyright holders or contributors may not be used to
 *    endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <config.h>

#ident "$Id: plogin.c 3549 2011-11-06 18:38:51Z nekral-guest $"

#include <errno.h>
#include <grp.h>
#ifndef USE_PAM
#include <lastlog.h>
#endif				/* !USE_PAM */
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <assert.h>
#include "defines.h"
#include "faillog.h"
#include "failure.h"
#include "getdef.h"
#include "prototypes.h"
#include "pwauth.h"
/*@-exitarg@*/
#include "exitcodes.h"

#include <stdlib.h> // grantpt, unlockpt
#include <fcntl.h> // to set non blocking i/o
#include <unistd.h> // read/write
#include <sys/ioctl.h> // for setting the terminal window size
#include <signal.h> // catch window size changes
#include <string.h> // strsignal
#include <termios.h> // tcgetattr

#ifdef USE_PAM
#include "pam_defs.h"

static pam_handle_t *pamh = NULL;

#define PAM_FAIL_CHECK if (retcode != PAM_SUCCESS) { \
	fprintf(stderr,"\n%s\n",pam_strerror(pamh, retcode)); \
	SYSLOG((LOG_ERR,"%s",pam_strerror(pamh, retcode))); \
	(void) pam_end(pamh, retcode); \
	exit(1); \
   }
#define PAM_END { retcode = pam_close_session(pamh,0); \
		(void) pam_end(pamh,retcode); }

#endif				/* USE_PAM */

#ifndef USE_PAM
/*
 * Needed for MkLinux DR1/2/2.1 - J.
 */
#ifndef LASTLOG_FILE
#define LASTLOG_FILE "/var/log/lastlog"
#endif
#endif				/* !USE_PAM */

/*
 * Global variables
 */
const char *Prog;

static const char *hostname = "";
static /*@null@*/ /*@only@*/char *username = NULL;
static int reason = PW_LOGIN;

#ifndef USE_PAM
static struct lastlog ll;
#endif				/* !USE_PAM */
static bool pflg = false;
static bool fflg = false;

#ifdef RLOGIN
static bool rflg = false;
#else				/* RLOGIN */
#define rflg false
#endif				/* !RLOGIN */
static bool hflg = false;
static bool preauth_flag = false;

static bool amroot;
static unsigned int timeout;

/*
 * External identifiers.
 */

extern char **newenvp;
extern size_t newenvc;
extern char **environ;

#ifndef	ALARM
#define	ALARM	60
#endif

#ifndef	RETRIES
#define	RETRIES	3
#endif

/* local function prototypes */
static void usage (void);
static void setup_tty (void);
static void process_flags (int argc, char *const *argv);
static /*@observer@*/const char *get_failent_user (/*@returned@*/const char *user);
#ifndef USE_PAM
static void update_utmp (const char *user,
                         const char *tty,
                         const char *host,
                         /*@null@*/const struct utmp *utent);
#endif				/* ! USE_PAM */

#ifndef USE_PAM
static struct faillog faillog;

static void bad_time_notify (void);
static void check_nologin (bool login_to_root);
#else
static void get_pam_user (char **ptr_pam_user);
#endif

static void init_env (void);
static RETSIGTYPE alarm_handler (int);


#ifdef HAVE_SETGROUPS
static int ngroups;
static /*@null@*/ /*@only@*/GETGROUPS_T *grouplist;
#endif

static bool is_newgrp = true;

#ifdef WITH_AUDIT
static char audit_buf[80];
#endif

/* local function prototypes */
static int check_perms (const struct group *grp,
                         struct passwd *pwd,
                         const char *groupname, unsigned int uid);

/*
 * usage - print login command usage and exit
 *
 * login [ name ]
 * login -r hostname	(for rlogind)
 * login -h hostname	(for telnetd, etc.)
 * login -f name	(for pre-authenticated login: datakit, xterm, etc.)
 */
static void usage (void)
{
	fprintf (stderr, _("Usage: %s [-p] [name]\n"), Prog);
	if (!amroot) {
		exit (1);
	}
	fprintf (stderr, _("       %s [-p] [-h host] [-f name]\n"), Prog);
#ifdef RLOGIN
	fprintf (stderr, _("       %s [-p] -r host\n"), Prog);
#endif				/* RLOGIN */
	exit (1);
}

static void setup_tty (void)
{
	TERMIO termio;

	if (GTTY (0, &termio) == 0) {	/* get terminal characteristics */
		int erasechar;
		int killchar;

		/*
		 * Add your favorite terminal modes here ...
		 */
		termio.c_lflag |= ISIG | ICANON | ECHO | ECHOE;
		termio.c_iflag |= ICRNL;

#if defined(ECHOKE) && defined(ECHOCTL)
		termio.c_lflag |= ECHOKE | ECHOCTL;
#endif
#if defined(ECHOPRT) && defined(NOFLSH) && defined(TOSTOP)
		termio.c_lflag &= ~(ECHOPRT | NOFLSH | TOSTOP);
#endif
#ifdef ONLCR
		termio.c_oflag |= ONLCR;
#endif

		/* leave these values unchanged if not specified in login.defs */
		erasechar = getdef_num ("ERASECHAR", (int) termio.c_cc[VERASE]);
		killchar = getdef_num ("KILLCHAR", (int) termio.c_cc[VKILL]);
		termio.c_cc[VERASE] = (cc_t) erasechar;
		termio.c_cc[VKILL] = (cc_t) killchar;
		/* Make sure the values were valid.
		 * getdef_num cannot validate this.
		 */
		if (erasechar != (int) termio.c_cc[VERASE]) {
			fprintf (stderr,
			         _("configuration error - cannot parse %s value: '%d'"),
			         "ERASECHAR", erasechar);
			exit (1);
		}
		if (killchar != (int) termio.c_cc[VKILL]) {
			fprintf (stderr,
			         _("configuration error - cannot parse %s value: '%d'"),
			         "KILLCHAR", killchar);
			exit (1);
		}

		/*
		 * ttymon invocation prefers this, but these settings
		 * won't come into effect after the first username login 
		 */
		(void) STTY (0, &termio);
	}
}


#ifndef USE_PAM
/*
 * Tell the user that this is not the right time to login at this tty
 */
static void bad_time_notify (void)
{
	(void) puts (_("Invalid login time"));
	(void) fflush (stdout);
}

static void check_nologin (bool login_to_root)
{
	char *fname;

	/*
	 * Check to see if system is turned off for non-root users.
	 * This would be useful to prevent users from logging in
	 * during system maintenance. We make sure the message comes
	 * out for root so she knows to remove the file if she's
	 * forgotten about it ...
	 */
	fname = getdef_str ("NOLOGINS_FILE");
	if ((NULL != fname) && (access (fname, F_OK) == 0)) {
		FILE *nlfp;

		/*
		 * Cat the file if it can be opened, otherwise just
		 * print a default message
		 */
		nlfp = fopen (fname, "r");
		if (NULL != nlfp) {
			int c;
			while ((c = getc (nlfp)) != EOF) {
				if (c == '\n') {
					(void) putchar ('\r');
				}

				(void) putchar (c);
			}
			(void) fflush (stdout);
			(void) fclose (nlfp);
		} else {
			(void) puts (_("\nSystem closed for routine maintenance"));
		}
		/*
		 * Non-root users must exit. Root gets the message, but
		 * gets to login.
		 */

		if (!login_to_root) {
			closelog ();
			exit (0);
		}
		(void) puts (_("\n[Disconnect bypassed -- root login allowed.]"));
	}
}
#endif				/* !USE_PAM */

static void process_flags (int argc, char *const *argv)
{
	int arg;
	int flag;
	return;
	/*
	 * Check the flags for proper form. Every argument starting with
	 * "-" must be exactly two characters long. This closes all the
	 * clever rlogin, telnet, and getty holes.
	 */
	for (arg = 1; arg < argc; arg++) {
		if (argv[arg][0] == '-' && strlen (argv[arg]) > 2) {
			usage ();
		}
		if (strcmp(argv[arg], "--") == 0) {
			break; /* stop checking on a "--" */
		}
	}

	/*
	 * Process options.
	 */
	while ((flag = getopt (argc, argv, "d:fh:pr:")) != EOF) {
		switch (flag) {
		case 'd':
			/* "-d device" ignored for compatibility */
			break;
		case 'f':
			fflg = true;
			break;
		case 'h':
			hflg = true;
			hostname = optarg;
			reason = PW_TELNET;
			break;
#ifdef	RLOGIN
		case 'r':
			rflg = true;
			hostname = optarg;
			reason = PW_RLOGIN;
			break;
#endif				/* RLOGIN */
		case 'p':
			pflg = true;
			break;
		default:
			usage ();
		}
	}

#ifdef RLOGIN
	/*
	 * Neither -h nor -f should be combined with -r.
	 */

	if (rflg && (hflg || fflg)) {
		usage ();
	}
#endif				/* RLOGIN */

	/*
	 * Allow authentication bypass only if real UID is zero.
	 */

	if ((rflg || fflg || hflg) && !amroot) {
		fprintf (stderr, _("%s: Permission denied.\n"), Prog);
		exit (1);
	}

	/*
	 *  Get the user name.
	 */
/*
	if (optind < argc) {
		assert (NULL == username);
		username = xstrdup (argv[optind]);
		strzero (argv[optind]);
		++optind;
	}
*/

#ifdef	RLOGIN
	if (rflg && (NULL != username)) {
		usage ();
	}
#endif				/* RLOGIN */
	if (fflg && (NULL == username)) {
		usage ();
	}

}


static void init_env (void)
{
#ifndef USE_PAM
	char *cp;
#endif
	char *tmp;

	tmp = getenv ("LANG");
	if (NULL != tmp) {
		addenv ("LANG", tmp);
	}

	/*
	 * Add the timezone environmental variable so that time functions
	 * work correctly.
	 */
	tmp = getenv ("TZ");
	if (NULL != tmp) {
		addenv ("TZ", tmp);
	}
#ifndef USE_PAM
	else {
		cp = getdef_str ("ENV_TZ");
		if (NULL != cp) {
			addenv (('/' == *cp) ? tz (cp) : cp, NULL);
		}
	}
#endif				/* !USE_PAM */
	/* 
	 * Add the clock frequency so that profiling commands work
	 * correctly.
	 */
	tmp = getenv ("HZ");
	if (NULL != tmp) {
		addenv ("HZ", tmp);
	}
#ifndef USE_PAM
	else {
		cp = getdef_str ("ENV_HZ");
		if (NULL != cp) {
			addenv (cp, NULL);
		}
	}
#endif				/* !USE_PAM */
}


static RETSIGTYPE alarm_handler (unused int sig)
{
	fprintf (stderr, _("\nLogin timed out after %u seconds.\n"), timeout);
	exit (1);
}

#ifdef USE_PAM
/*
 * get_pam_user - Get the username according to PAM
 *
 * ptr_pam_user shall point to a malloc'ed string (or NULL).
 */
static void get_pam_user (char **ptr_pam_user)
{
	int retcode;
	void *ptr_user;

	assert (NULL != ptr_pam_user);

	fprintf(stdout,"\nGetting item\n");
	retcode = pam_get_item (pamh, PAM_USER, (const void **)&ptr_user);
	fprintf(stdout,"\nGot item\n");
	PAM_FAIL_CHECK;

	if (NULL != *ptr_pam_user) {
		free (*ptr_pam_user);
	}
	if (NULL != ptr_user) {
		*ptr_pam_user = xstrdup ((const char *)ptr_user);
	} else {
		*ptr_pam_user = NULL;
	}
}
#endif

/*
 * get_failent_user - Return a string that can be used to log failure
 *                    from an user.
 *
 * This will be either the user argument, or "UNKNOWN".
 *
 * It is quite common to mistyped the password for username, and passwords
 * should not be logged.
 */
static /*@observer@*/const char *get_failent_user (/*@returned@*/const char *user)
{
	const char *failent_user = "UNKNOWN";
	bool log_unkfail_enab = getdef_bool("LOG_UNKFAIL_ENAB");

	if ((NULL != user) && ('\0' != user[0])) {
		if (   log_unkfail_enab
		    || (getpwnam (user) != NULL)) {
			failent_user = user;
		}
	}

	return failent_user;
}

#ifndef USE_PAM
/*
 * update_utmp - Update or create an utmp entry in utmp, wtmp, utmpw, and
 *               wtmpx
 *
 *	utent should be the utmp entry returned by get_current_utmp (or
 *	NULL).
 */
static void update_utmp (const char *user,
                         const char *tty,
                         const char *host,
                         /*@null@*/const struct utmp *utent)
{
	struct utmp  *ut  = prepare_utmp  (user, tty, host, utent);
#ifdef USE_UTMPX
	struct utmpx *utx = prepare_utmpx (user, tty, host, utent);
#endif				/* USE_UTMPX */

	(void) setutmp  (ut);	/* make entry in the utmp & wtmp files */
	free (ut);

#ifdef USE_UTMPX
	(void) setutmpx (utx);	/* make entry in the utmpx & wtmpx files */
	free (utx);
#endif				/* USE_UTMPX */
}
#endif				/* ! USE_PAM */

/*
 * find_matching_group - search all groups of a given group id for
 *                       membership of a given username
 */
static /*@null@*/struct group *find_matching_group (const char *name, gid_t gid)
{
	struct group *gr;
	char **look;
	bool notfound = true;

	setgrent ();
	while ((gr = getgrent ()) != NULL) {
		if (gr->gr_gid != gid) {
			continue;
		}

		/*
		 * A group with matching GID was found.
		 * Test for membership of 'name'.
		 */
		look = gr->gr_mem;
		while ((NULL != *look) && notfound) {
			notfound = (strcmp (*look, name) != 0);
			look++;
		}
		if (!notfound) {
			break;
		}
	}
	endgrent ();
	return gr;
}

/*
 * check_perms - check if the user is allowed to switch to this group
 *
 *	If needed, the user will be authenticated.
 *
 *	It will not return if the user could not be authenticated.
 */
static int check_perms (const struct group *grp,
                         struct passwd *pwd,
                         const char *groupname, unsigned int uid)
{
	bool needspasswd = false;
	struct spwd *spwd;
	char *cp;
	const char *cpasswd;

	/*
	 * see if she is a member of this group (i.e. in the list of
	 * members of the group, or if the group is her primary group).
	 *
	 * If she isn't a member, she needs to provide the group password.
	 * If there is no group password, she will be denied access
	 * anyway.
	 *
	 */
	if (   (grp->gr_gid != pwd->pw_gid)
	    && !is_on_list (grp->gr_mem, pwd->pw_name)) {
		needspasswd = true;
	}

	/*
	 * If she does not have either a shadowed password, or a regular
	 * password, and the group has a password, she needs to give the
	 * group password.
	 */
	spwd = xgetspnam (pwd->pw_name);
	if (NULL != spwd) {
		pwd->pw_passwd = spwd->sp_pwdp;
	}

	if ((pwd->pw_passwd[0] == '\0') && (grp->gr_passwd[0] != '\0')) {
		needspasswd = true;
	}

	/*
	 * Now I see about letting her into the group she requested. If she
	 * is the root user, I'll let her in without having to prompt for
	 * the password. Otherwise I ask for a password if she flunked one
	 * of the tests above.
	 */
	if ((uid != 0) && needspasswd) {
		/*
		 * get the password from her, and set the salt for
		 * the decryption from the group file.
		 */
		cp = getpass (_("Password: "));
		if (NULL == cp) {
			goto failure;
		}

		/*
		 * encrypt the key she gave us using the salt from the
		 * password in the group file. The result of this encryption
		 * must match the previously encrypted value in the file.
		 */
		cpasswd = pw_encrypt (cp, grp->gr_passwd);
		strzero (cp);

		if (grp->gr_passwd[0] == '\0' ||
		    strcmp (cpasswd, grp->gr_passwd) != 0) {
#ifdef WITH_AUDIT
			snprintf (audit_buf, sizeof(audit_buf),
			          "authentication new-gid=%lu",
			          (unsigned long) grp->gr_gid);
			audit_logger (AUDIT_GRP_AUTH, Prog,
			              audit_buf, NULL,
			              (unsigned int) uid, 0);
#endif
			SYSLOG ((LOG_INFO,
				 "Invalid password for group '%s' from '%s'",
				 groupname, pwd->pw_name));
			(void) sleep (1);
			(void) fputs (_("Invalid password.\n"), stderr);
			goto failure;
		}
#ifdef WITH_AUDIT
		snprintf (audit_buf, sizeof(audit_buf),
		          "authentication new-gid=%lu",
		          (unsigned long) grp->gr_gid);
		audit_logger (AUDIT_GRP_AUTH, Prog,
		              audit_buf, NULL,
		              (unsigned int) uid, 1);
#endif
	}

	return 0;

failure:
	/* The closelog is probably unnecessary, but it does no
	 * harm.  -- JWP
	 */
	closelog ();
#ifdef WITH_AUDIT
	if (groupname) {
		snprintf (audit_buf, sizeof(audit_buf),
		          "changing new-group=%s", groupname);
		audit_logger (AUDIT_CHGRP_ID, Prog,
		              audit_buf, NULL,
		              (unsigned int) uid, 0);
	} else {
		audit_logger (AUDIT_CHGRP_ID, Prog,
		              "changing", NULL,
		              (unsigned int) uid, 0);
	}
#endif
	return -1;
}

/*
 * newgrp - change the invokers current real and effective group id
 */
int handle_group (unsigned int uid, unsigned int new_gid)
{
	bool initflag = false;
	int i,ret;
	bool cflag = false;
	int err = 0;
	gid_t gid;
	char *cp;
	const char *name, *prog;
	char *group = NULL;
	char *command = NULL;
	char **envp = environ;
	struct passwd *pwd;
	/*@null@*/struct group *grp;

#ifdef SHADOWGRP
	struct sgrp *sgrp;
#endif

#ifdef WITH_AUDIT
	audit_help_open ();
#endif

	/*
	 * Save my name for error messages and save my real gid incase of
	 * errors. If there is an error i have to exec a new login shell for
	 * the user since her old shell won't have fork'd to create the
	 * process. Skip over the program name to the next command line
	 * argument.
	 *
	 * This historical comment, and the code itself, suggest that the
	 * behavior of the system/shell on which it was written differed
	 * significantly from the one I am using. If this process was
	 * started from a shell (including the login shell), it was fork'ed
	 * and exec'ed as a child by that shell. In order to get the user
	 * back to that shell, it is only necessary to exit from this
	 * process which terminates the child of the fork. The parent shell,
	 * which is blocked waiting for a signal, will then receive a
	 * SIGCHLD and will continue; any changes made to the process
	 * persona or the environment after the fork never occurred in the
	 * parent process.
	 *
	 * Bottom line: we want to save the name and real gid for messages,
	 * but we do not need to restore the previous process persona and we
	 * don't need to re-exec anything.  -- JWP
	 */
	OPENLOG ("newgrp");

	pwd = xgetpwuid(uid);
	if (NULL == pwd) {
		fprintf (stderr, _("%s: Cannot determine your user name.\n"),
		         Prog);
#ifdef WITH_AUDIT
		audit_logger (AUDIT_CHGRP_ID, Prog,
		              "changing", NULL,
		              (unsigned int) uid, 0);
#endif
		SYSLOG ((LOG_WARN, "Cannot determine the user name of the caller (UID %lu)",
		         (unsigned long) uid));
		closelog ();
		return -1;
	}
	name = pwd->pw_name;

	/*
	 * Parse the command line. There are two accepted flags. The first
	 * is "-", which for newgrp means to re-create the entire
	 * environment as though a login had been performed, and "-c", which
	 * for sg causes a command string to be executed.
	 *
	 * The next argument, if present, must be the new group name. Any
	 * remaining remaining arguments will be used to execute a command
	 * as the named group. If the group name isn't present, I just use
	 * the login group ID of the current user.
	 *
	 * The valid syntax are
	 *      newgrp [-] [groupid]
	 *      newgrp [-l] [groupid]
	 *      sg [-]
	 *      sg [-] groupid [[-c command]
	 */
/*
	if (   (argc > 0)
	    && (   (strcmp (argv[0], "-")  == 0)
	        || (strcmp (argv[0], "-l") == 0))) {
		argc--;
		argv++;
		initflag = true;
	}
*/
//	if (!is_newgrp) {
//		/*
//		 * Do the command line for everything that is
//		 * not "newgrp".
//		 */
//		if ((argc > 0) && (argv[0][0] != '-')) {
//			group = argv[0];
//			argc--;
//			argv++;
//		} else {
//			usage ();
//			closelog ();
//			exit (EXIT_FAILURE);
//		}
//		if (argc > 0) {
//
//			/*
//			 * skip -c if specified so both forms work:
//			 * "sg group -c command" (as in the man page) or
//			 * "sg group command" (as in the usage message).
//			 */
//			if ((argc > 1) && (strcmp (argv[0], "-c") == 0)) {
//				command = argv[1];
//			} else {
//				command = argv[0];
//			}
//			cflag = true;
//		}
//	} else {
//		/*
//		 * Do the command line for "newgrp". It's just making sure
//		 * there aren't any flags and getting the new group name.
//		 */
//		if ((argc > 0) && (argv[0][0] == '-')) {
//			usage ();
//			goto failure;
//		} else if (argv[0] != (char *) 0) {
//			group = argv[0];
//		} else {
//			/*
//			 * get the group file entry for her login group id.
//			 * the entry must exist, simply to be annoying.
//			 *
//			 * Perhaps in the past, but the default behavior now depends on the
//			 * group entry, so it had better exist.  -- JWP
//			 */
//			grp = xgetgrgid (pwd->pw_gid);
//			if (NULL == grp) {
//				fprintf (stderr,
//				         _("%s: GID '%lu' does not exist\n"),
//				         Prog, (unsigned long) pwd->pw_gid);
//				SYSLOG ((LOG_CRIT, "GID '%lu' does not exist",
//				        (unsigned long) pwd->pw_gid));
//				goto failure;
//			} else {
//				group = grp->gr_name;
//			}
//		}
//	}

#ifdef HAVE_SETGROUPS
	/*
	 * get the current users groupset. The new group will be added to
	 * the concurrent groupset if there is room, otherwise you get a
	 * nasty message but at least your real and effective group id's are
	 * set.
	 */
	/* don't use getgroups(0, 0) - it doesn't work on some systems */
	i = 16;
	for (;;) {
		grouplist = (GETGROUPS_T *) xmalloc (i * sizeof (GETGROUPS_T));
		ngroups = getgroups (i, grouplist);
		if (i > ngroups && !(ngroups == -1 && errno == EINVAL)) {
			break;
		}
		/* not enough room, so try allocating a larger buffer */
		free (grouplist);
		i *= 2;
	}
	if (ngroups < 0) {
		perror ("getgroups");
#ifdef WITH_AUDIT
		if (group) {
			snprintf (audit_buf, sizeof(audit_buf),
			          "changing new-group=%s", group);
			audit_logger (AUDIT_CHGRP_ID, Prog,
			              audit_buf, NULL,
			              (unsigned int) uid, 0);
		} else {
			audit_logger (AUDIT_CHGRP_ID, Prog,
			              "changing", NULL,
			              (unsigned int) uid, 0);
		}
#endif
		return -1;
	}
#endif				/* HAVE_SETGROUPS */

	/*
	 * now we put her in the new group. The password file entry for her
	 * current user id has been gotten. If there was no optional group
	 * argument she will have her real and effective group id set to the
	 * set to the value from her password file entry.
	 *
	 * If run as newgrp, or as sg with no command, this process exec's
	 * an interactive subshell with the effective GID of the new group.
	 * If run as sg with a command, that command is exec'ed in this
	 * subshell. When this process terminates, either because the user
	 * exits, or the command completes, the parent of this process
	 * resumes with the current GID.
	 *
	 * If a group is explicitly specified on the command line, the
	 * interactive shell or command is run with that effective GID.
	 * Access will be denied if no entry for that group can be found in
	 * /etc/group. If the current user name appears in the members list
	 * for that group, access will be granted immediately; if not, the
	 * user will be challenged for that group's password. If the
	 * password response is incorrect, if the specified group does not
	 * have a password, or if that group has been locked by gpasswd -R,
	 * access will be denied. This is true even if the group specified
	 * has the user's login GID (as shown in /etc/passwd). If no group
	 * is explicitly specified on the command line, the effect is
	 * exactly the same as if a group name matching the user's login GID
	 * had been explicitly specified. Root, however, is never
	 * challenged for passwords, and is always allowed access.
	 *
	 * The previous behavior was to allow access to the login group if
	 * no explicit group was specified, irrespective of the group
	 * control file(s). This behavior is usually not desirable. A user
	 * wishing to return to the login group has only to exit back to the
	 * login shell. Generating yet more shell levels in order to
	 * provide a convenient "return" to the default group has the
	 * undesirable side effects of confusing the user, scrambling the
	 * history file, and consuming system resources. The default now is
	 * to lock out such behavior. A sys admin can allow it by explicitly
	 * including the user's name in the member list of the user's login
	 * group.  -- JWP
	 */
	grp = getgrgid (new_gid); /* local, no need for xgetgrnam */
	if (NULL == grp) {
		fprintf (stderr, _("%s: group '%u' does not exist\n"), Prog, new_gid);
		goto failure;
	}

	group = grp->gr_name;

	/*
	 * For splitted groups (due to limitations of NIS), check all
	 * groups of the same GID like the requested group for
	 * membership of the current user.
	 */
	grp = find_matching_group (name, grp->gr_gid);
	if (NULL == grp) {
		/*
		 * No matching group found. As we already know that
		 * the group exists, this happens only in the case
		 * of a requested group where the user is not member.
		 *
		 * Re-read the group entry for further processing.
		 */
		grp = xgetgrnam (group);
		assert (NULL != grp);
	}
#ifdef SHADOWGRP
	sgrp = getsgnam (group);
	if (NULL != sgrp) {
		grp->gr_passwd = sgrp->sg_passwd;
		grp->gr_mem = sgrp->sg_mem;
	}
#endif

	/*
	 * Check if the user is allowed to access this group.
	 */
	ret = check_perms (grp, pwd, group, uid);
	closelog ();
	return ret;

	/*@notreached@*/
      failure:

	/*
	 * The previous code, when run as newgrp, re-exec'ed the shell in
	 * the current process with the original gid on error conditions.
	 * See the comment above. This historical behavior now has the
	 * effect of creating unlogged extraneous shell layers when the
	 * command line has an error or there is an authentication failure.
	 * We now just want to exit with error status back to the parent
	 * process. The closelog is probably unnecessary, but it does no
	 * harm.  -- JWP
	 */
	closelog ();
#ifdef WITH_AUDIT
	if (NULL != group) {
		snprintf (audit_buf, sizeof(audit_buf),
		          "changing new-group=%s", group);
		audit_logger (AUDIT_CHGRP_ID, Prog,
		              audit_buf, NULL,
		              (unsigned int) uid, 0);
	} else {
		audit_logger (AUDIT_CHGRP_ID, Prog,
		              "changing", NULL,
		              (unsigned int) uid, 0);
	}
#endif
	return -1;
}


/*
 * login - create a new login session for a user
 *
 *	login is typically called by getty as the second step of a
 *	new user session. getty is responsible for setting the line
 *	characteristics to a reasonable set of values and getting
 *	the name of the user to be logged in. login may also be
 *	called to create a new user session on a pty for a variety
 *	of reasons, such as X servers or network logins.
 *
 *	the flags which login supports are
 *	
 *	-p - preserve the environment
 *	-r - perform autologin protocol for rlogin
 *	-f - do not perform authentication, user is preauthenticated
 *	-h - the name of the remote host
 */
int main (int argc, char **argv)
{
	const char *tmptty;
	char tty[BUFSIZ];
	int ret;
#ifdef RLOGIN
	char term[128] = "";
#endif				/* RLOGIN */
#if defined(HAVE_STRFTIME) && !defined(USE_PAM)
	char ptime[80];
#endif
	unsigned int delay;
	unsigned int retries;
	bool subroot = false;
#ifndef USE_PAM
	bool is_console;
#endif
	int err;
	const char *cp;
	const char *tmp;
	char fromhost[512];
	struct passwd *pwd = NULL;
	char **envp = environ;
	const char *failent_user;
	/*@null@*/struct utmp *utent;

#ifdef USE_PAM
	int retcode;
	pid_t child;
	char *pam_user = NULL;
#else
	struct spwd *spwd = NULL;
#endif
	/*
	 * Some quick initialization.
	 */

	int fd0, fd1, fd2;
	close(0);
	close(1);
	close(2);
	if ((fd0 = open(argv[1], O_RDONLY)) == -1) {  /* open tty for read */
//		SYSLOG((LOG_INFO, "\n Can't open tty device for read\n"));
	   exit(1);
	}

	/* to open /dev/tty for write */
	if ((fd1 = open(argv[1], O_WRONLY)) == -1) {  /* open tty for
	write */
//		SYSLOG((LOG_INFO, "\n Can't open tty device for write\n"));
	   exit(1);
	}

	/* to open /dev/tty for write */
	if ((fd2 = open(argv[1], O_WRONLY)) == -1) {  /* open tty for
	write */
//		SYSLOG((LOG_INFO, "\n Can't open tty device for write\n"));
	   exit(1);
	}
	fprintf(stdout,"\nHURRAY!!!!\n");
	fprintf(stderr,"\nDAMN!!!!\n");
	OPENLOG ("login");
	SYSLOG((LOG_INFO, "\n argv[1] = %s\n", argv[1]));
	SYSLOG((LOG_INFO, "\n fd0 = %d\n", fd0));
	SYSLOG((LOG_INFO, "\n fd1 = %d\n", fd1));
	SYSLOG((LOG_INFO, "\n fd2 = %d\n", fd2));

	pwd = getpwuid (atoi(argv[2]));
	username = xstrdup(pwd->pw_name);
	sanitize_env ();

	(void) setlocale (LC_ALL, "");
	(void) bindtextdomain (PACKAGE, LOCALEDIR);
	(void) textdomain (PACKAGE);

	initenv ();

	amroot = (getuid () == 0);
	Prog = Basename (argv[0]);

	if (geteuid() != 0) {
		SYSLOG((LOG_INFO, "\n %s: Cannot possibly work without effective root\n", Prog));
		fprintf (stderr, _("%s: Cannot possibly work without effective root\n"), Prog);
		exit (1);
	}

	if ((isatty (0) == 0) || (isatty (1) == 0) || (isatty (2) == 0)) {
		SYSLOG((LOG_INFO, "\n login Failed : must be a terminal\n"));
		if(!isatty (0))
			SYSLOG((LOG_INFO, "\n isatty failed for 0 : %s\n",strerror (errno)));
		if(!isatty (1))
			SYSLOG((LOG_INFO, "\n isatty failed for 1 : %s\n",strerror (errno)));
		if(!isatty (2))
			SYSLOG((LOG_INFO, "\n isatty failed for 2 : %s\n",strerror (errno)));

		exit (1);	/* must be a terminal */
	}

	if(atoi(argv[4]))
	{
		retcode =  handle_group(atoi(argv[2]),atoi(argv[3]));
		(void) signal (SIGQUIT, SIG_DFL);	/* default quit signal */
		(void) signal (SIGTERM, SIG_DFL);	/* default terminate signal */
		(void) signal (SIGALRM, SIG_DFL);	/* default alarm signal */
		(void) signal (SIGHUP, SIG_DFL);	/* added this.  --marekm */
		(void) signal (SIGINT, SIG_DFL);	/* default interrupt signal */

		closelog ();
		close(fd0);
		close(fd1);
		close(fd2);
		return retcode;
	}

	process_flags (argc, argv);

	SYSLOG((LOG_INFO, "\n amroot : %d\n",amroot?1:0));


	utent = get_current_utmp ();

	/* NOTE: utent might be NULL afterwards */

	fprintf(stdout,"\nttyname\n");
	tmptty = ttyname (0);
	if (NULL == tmptty) {
//		tmptty = "UNKNOWN";
		tmptty = "bhu";
	}
	STRFCPY (tty, tmptty);

#ifndef USE_PAM
	is_console = console (tty);
#endif

	fprintf(stdout,"\nsetup tty\n");
	setup_tty ();

#ifndef USE_PAM
	(void) umask (getdef_num ("UMASK", GETDEF_DEFAULT_UMASK));

	{
		/* 
		 * Use the ULIMIT in the login.defs file, and if
		 * there isn't one, use the default value. The
		 * user may have one for themselves, but otherwise,
		 * just take what you get.
		 */
		long limit = getdef_long ("ULIMIT", -1L);

		if (limit != -1) {
			set_filesize_limit (limit);
		}
	}

#endif
	/*
	 * The entire environment will be preserved if the -p flag
	 * is used.
	 */
	if (pflg) {
		while (NULL != *envp) {	/* add inherited environment, */
			addenv (*envp, NULL); /* some variables change later */
			envp++;
		}
	}

	{
		/* preserve TERM from getty */
		if (!pflg) {
			tmp = getenv ("TERM");
			if (NULL != tmp) {
				addenv ("TERM", tmp);
			}
		}
	}

	fprintf(stdout,"\ninit_env\n");
	init_env ();

	if (optind < argc) {	/* now set command line variables */
		set_env (argc - optind, &argv[optind]);
	}

	cp = "";

      top:
	/* only allow ALARM sec. for login */
	(void) signal (SIGALRM, alarm_handler);
	timeout = getdef_unum ("LOGIN_TIMEOUT", ALARM);
	if (timeout > 0) {
		(void) alarm (timeout);
	}

	environ = newenvp;	/* make new environment active */
	delay   = getdef_unum ("FAIL_DELAY", 1);
	retries = getdef_unum ("LOGIN_RETRIES", RETRIES);

#ifdef USE_PAM
	SYSLOG ((LOG_INFO, "Using PAM"));
	fprintf(stdout,"\npam_start\n");
	retcode = pam_start ("login", username, &conv, &pamh);
	if (retcode != PAM_SUCCESS) {
		fprintf (stderr,
		         _("login: PAM Failure, aborting: %s\n"),
		         pam_strerror (pamh, retcode));
		SYSLOG ((LOG_ERR, "Couldn't initialize PAM: %s",
		         pam_strerror (pamh, retcode)));
		exit (99);
	}

	/*
	 * hostname & tty are either set to NULL or their correct values,
	 * depending on how much we know. We also set PAM's fail delay to
	 * ours.
	 *
	 * PAM_RHOST and PAM_TTY are used for authentication, only use
	 * information coming from login or from the caller (e.g. no utmp)
	 */
	retcode = pam_set_item (pamh, PAM_RHOST, hostname);
	PAM_FAIL_CHECK;
	retcode = pam_set_item (pamh, PAM_TTY, tty);
	PAM_FAIL_CHECK;
#ifdef HAS_PAM_FAIL_DELAY
	retcode = pam_fail_delay (pamh, 1000000 * delay);
	PAM_FAIL_CHECK;
#endif
	/* if fflg, then the user has already been authenticated */
		unsigned int failcount = 0;
		char hostn[256];
		char loginprompt[256];	/* That's one hell of a prompt :) */

		/* Make the login prompt look like we want it */
		if (gethostname (hostn, sizeof (hostn)) == 0) {
			fprintf(stdout,"\npam login\n");
			snprintf (loginprompt,
			          sizeof (loginprompt),
			          _("%s login: "), hostn);
		} else {
			fprintf(stdout,"\npam login 2\n");
			strncpy (loginprompt, _("login: "),
			         sizeof (loginprompt));
		}

		fprintf(stdout,"\npam set item\n");
		retcode = pam_set_item (pamh, PAM_USER_PROMPT, loginprompt);
		PAM_FAIL_CHECK;

		/* if we didn't get a user on the command line,
		   set it to NULL */
		get_pam_user (&pam_user);
		if ((NULL != pam_user) && ('\0' == pam_user[0])) {
			retcode = pam_set_item (pamh, PAM_USER, NULL);
			PAM_FAIL_CHECK;
		}

		/*
		 * There may be better ways to deal with some of
		 * these conditions, but at least this way I don't
		 * think we'll be giving away information. Perhaps
		 * someday we can trust that all PAM modules will
		 * pay attention to failure count and get rid of
		 * MAX_LOGIN_TRIES?
		 */
		failcount = 0;
		while (true) {
			bool failed = false;

			failcount++;
#ifdef HAS_PAM_FAIL_DELAY
			if (delay > 0) {
				retcode = pam_fail_delay(pamh, 1000000*delay);
				PAM_FAIL_CHECK;
			}
#endif
			retcode = pam_start ("login", username, &conv, &pamh);
			if (retcode != PAM_SUCCESS) {
				fprintf (stderr,
				         _("login: PAM Failure, aborting: %s\n"),
				         pam_strerror (pamh, retcode));
				SYSLOG ((LOG_ERR, "Couldn't initialize PAM: %s",
				         pam_strerror (pamh, retcode)));
				exit (99);
			}

			fprintf(stdout,"\npam authenticate\n");
			retcode = pam_authenticate (pamh, 0);
			fprintf(stdout,"\npam authenticate done\n");

			get_pam_user (&pam_user);
			failent_user = get_failent_user (pam_user);

			if (retcode == PAM_MAXTRIES) {
				SYSLOG ((LOG_NOTICE,
				         "TOO MANY LOGIN TRIES (%u)%s FOR '%s'",
				         failcount, fromhost, failent_user));
				fprintf (stderr,
				         _("Maximum number of tries exceeded (%u)\n"),
				         failcount);
				PAM_END;
				fprintf(stderr,"\nExiting with 1\n");
				exit(1);
			} else if (retcode == PAM_ABORT) {
				/* Serious problems, quit now */
				(void) fputs (_("login: abort requested by PAM\n"), stderr);
				SYSLOG ((LOG_ERR,"PAM_ABORT returned from pam_authenticate()"));
				PAM_END;
				exit(99);
			} else if (retcode != PAM_SUCCESS) {
				SYSLOG ((LOG_NOTICE,"FAILED LOGIN (%u)%s FOR '%s', %s",
				         failcount, fromhost, failent_user,
				         pam_strerror (pamh, retcode)));
				failed = true;
			}

			if (!failed) {
				break;
			}

#ifdef WITH_AUDIT
			audit_fd = audit_open ();
			audit_log_acct_message (audit_fd,
			                        AUDIT_USER_LOGIN,
			                        NULL,    /* Prog. name */
			                        "login",
			                        failent_user,
			                        AUDIT_NO_ID,
			                        hostname,
			                        NULL,    /* addr */
			                        tty,
			                        0);      /* result */
			close (audit_fd);
#endif				/* WITH_AUDIT */

			(void) puts ("");
			(void) puts (_("Login incorrect"));

			if (failcount >= retries) {
				SYSLOG ((LOG_NOTICE,
				         "TOO MANY LOGIN TRIES (%u)%s FOR '%s'",
				         failcount, fromhost, failent_user));
				fprintf (stderr,
				         _("Maximum number of tries exceeded (%u)\n"),
				         failcount);
				PAM_END;
				exit(1);
			}

			/*
			 * Let's give it another go around.
			 * Even if a username was given on the command
			 * line, prompt again for the username.
			 */
			retcode = pam_set_item (pamh, PAM_USER, NULL);
			PAM_FAIL_CHECK;
		}

		/* We don't get here unless they were authenticated above */
		(void) alarm (0);

	/* Check the account validity */
	retcode = pam_acct_mgmt (pamh, 0);
	if (retcode == PAM_NEW_AUTHTOK_REQD) {
		retcode = pam_chauthtok (pamh, PAM_CHANGE_EXPIRED_AUTHTOK);
	}
	PAM_FAIL_CHECK;

	/* Open the PAM session */
	get_pam_user (&pam_user);
	retcode = pam_open_session (pamh, hushed (pam_user) ? PAM_SILENT : 0);
	PAM_FAIL_CHECK;

	/* Grab the user information out of the password file for future usage
	 * First get the username that we are actually using, though.
	 *
	 * From now on, we will discard changes of the user (PAM_USER) by
	 * PAM APIs.
	 */
	get_pam_user (&pam_user);
	if (NULL != username) {
		free (username);
	}
	username = xstrdup (pam_user);
	failent_user = get_failent_user (username);

	pwd = xgetpwnam (username);
	if (NULL == pwd) {
		SYSLOG ((LOG_ERR, "cannot find user %s", failent_user));
		fprintf (stderr,
		         _("Cannot find user (%s)\n"),
		         username);
		exit (1);
	}

#else				/* ! USE_PAM */
	SYSLOG ((LOG_INFO, "Not Using PAM"));
	while (true) {	/* repeatedly get login/password pairs */
		bool failed;
		/* user_passwd is always a pointer to this constant string
		 * or a passwd or shadow password that will be memzero by
		 * pw_free / spw_free.
		 * Do not free() user_passwd. */
		const char *user_passwd = "!";

		/* Do some cleanup to avoid keeping entries we do not need
		 * anymore. */
		if (NULL != pwd) {
			pw_free (pwd);
			pwd = NULL;
		}
		if (NULL != spwd) {
			spw_free (spwd);
			spwd = NULL;
		}

		failed = false;	/* haven't failed authentication yet */
		if (NULL == username) {	/* need to get a login id */
			if (subroot) {
				closelog ();
				exit (1);
			}
			preauth_flag = false;
			username = xmalloc (USER_NAME_MAX_LENGTH + 1);
			username[USER_NAME_MAX_LENGTH] = '\0';
			fprintf(stdout,"\nOpening login prompt\n");
//			login_prompt (_("\n%s login: "), username, USER_NAME_MAX_LENGTH);

			if ('\0' == username[0]) {
				/* Prompt for a new login */
				free (username);
				username = NULL;
				continue;
			}
		}
		/* Get the username to be used to log failures */
		failent_user = get_failent_user (username);

		pwd = xgetpwnam (username);
		if (NULL == pwd) {
			preauth_flag = false;
			failed = true;
		} else {
			user_passwd = pwd->pw_passwd;
			/*
			 * If the encrypted password begins with a "!",
			 * the account is locked and the user cannot
			 * login, even if they have been
			 * "pre-authenticated."
			 */
			if (   ('!' == user_passwd[0])
			    || ('*' == user_passwd[0])) {
				failed = true;
			}
		}

		if (strcmp (user_passwd, SHADOW_PASSWD_STRING) == 0) {
			spwd = xgetspnam (username);
			if (NULL != spwd) {
				user_passwd = spwd->sp_pwdp;
			} else {
				/* The user exists in passwd, but not in
				 * shadow. SHADOW_PASSWD_STRING indicates
				 * that the password shall be in shadow.
				 */
				SYSLOG ((LOG_WARN,
				         "no shadow password for '%s'%s",
				         username, fromhost));
			}
		}

		/*
		 * The -r and -f flags provide a name which has already
		 * been authenticated by some server.
		 */
//		if (preauth_flag) {
//			goto auth_ok;
//		}

		if ((ret = pw_auth (user_passwd, username, reason, (char *) 0)) == 0) {
			SYSLOG ((LOG_INFO, "Password ok"));
			goto auth_ok;
		}
		else
		{
			SYSLOG ((LOG_INFO, "pw_auth returned '%d'",ret));
		}

		SYSLOG ((LOG_WARN, "invalid password for '%s' %s",
		         failent_user, fromhost));
		failed = true;

	      auth_ok:
		/*
		 * This is the point where all authenticated users wind up.
		 * If you reach this far, your password has been
		 * authenticated and so on.
		 */
//		if (   !failed
//		    && (NULL != pwd)
//		    && (0 == pwd->pw_uid)
//		    && !is_console) {
//			SYSLOG ((LOG_CRIT, "ILLEGAL ROOT LOGIN %s", fromhost));
//			failed = true;
//		}
//		if (   !failed
//		    && !login_access (username, ('\0' != *hostname) ? hostname : tty)) {
//			SYSLOG ((LOG_WARN, "LOGIN '%s' REFUSED %s",
//			         username, fromhost));
//			failed = true;
//		}
//		if (   (NULL != pwd)
//		    && getdef_bool ("FAILLOG_ENAB")
//		    && !failcheck (pwd->pw_uid, &faillog, failed)) {
//			SYSLOG ((LOG_CRIT,
//			         "exceeded failure limit for '%s' %s",
//			         username, fromhost));
//			failed = true;
//		}
		if (!failed) {
			break;
		}

		/* don't log non-existent users */
		if ((NULL != pwd) && getdef_bool ("FAILLOG_ENAB")) {
			failure (pwd->pw_uid, tty, &faillog);
		}
		if (getdef_str ("FTMP_FILE") != NULL) {
#ifdef USE_UTMPX
			struct utmpx *failent =
				prepare_utmpx (failent_user,
				               tty,
			/* FIXME: or fromhost? */hostname,
				               utent);
#else				/* !USE_UTMPX */
			struct utmp *failent =
				prepare_utmp (failent_user,
				              tty,
				              hostname,
				              utent);
#endif				/* !USE_UTMPX */
			failtmp (failent_user, failent);
			free (failent);
		}

		retries--;
		if (retries <= 0) {
			SYSLOG ((LOG_CRIT, "REPEATED login failures%s",
			         fromhost));
		}

		/*
		 * If this was a passwordless account and we get here, login
		 * was denied (securetty, faillog, etc.). There was no
		 * password prompt, so do it now (will always fail - the bad
		 * guys won't see that the passwordless account exists at
		 * all).  --marekm
		 */
		if (user_passwd[0] == '\0') {
			pw_auth ("!", username, reason, (char *) 0);
		}

		/*
		 * Authentication of this user failed.
		 * The username must be confirmed in the next try.
		 */
		free (username);
		username = NULL;

		/*
		 * Wait a while (a la SVR4 /usr/bin/login) before attempting
		 * to login the user again. If the earlier alarm occurs
		 * before the sleep() below completes, login will exit.
		 */
		if (delay > 0) {
			(void) sleep (delay);
		}

		(void) puts (_("Login incorrect"));

		/* allow only one attempt with -r or -f */
		if (rflg || fflg || (retries <= 0)) {
			closelog ();
			exit (1);
		}
	}			/* while (true) */
#endif				/* ! USE_PAM */
	assert (NULL != username);
	assert (NULL != pwd);

	(void) alarm (0);		/* turn off alarm clock */

#ifndef USE_PAM			/* PAM does this */
	/*
	 * porttime checks moved here, after the user has been
	 * authenticated. now prints a message, as suggested
	 * by Ivan Nejgebauer <ian@unsux.ns.ac.yu>.  --marekm
	 */
	if (   getdef_bool ("PORTTIME_CHECKS_ENAB")
	    && !isttytime (username, tty, time ((time_t *) 0))) {
		SYSLOG ((LOG_WARN, "invalid login time for '%s'%s",
		         username, fromhost));
		closelog ();
		bad_time_notify ();
		exit (1);
	}

	check_nologin (pwd->pw_uid == 0);
#endif

	if (getenv ("IFS")) {	/* don't export user IFS ... */
		addenv ("IFS= \t\n", NULL);	/* ... instead, set a safe IFS */
	}

//	if (pwd->pw_shell[0] == '*') {	/* subsystem root */
//		pwd->pw_shell++;	/* skip the '*' */
//		subsystem (pwd);	/* figure out what to execute */
//		subroot = true;	/* say I was here again */
//		endpwent ();	/* close all of the file which were */
//		endgrent ();	/* open in the original rooted file */
//		endspent ();	/* system. they will be re-opened */
//#ifdef	SHADOWGRP
//		endsgent ();	/* in the new rooted file system */
//#endif
//		goto top;	/* go do all this all over again */
//	}

#ifdef WITH_AUDIT
	audit_fd = audit_open ();
	audit_log_acct_message (audit_fd,
	                        AUDIT_USER_LOGIN,
	                        NULL,    /* Prog. name */
	                        "login",
	                        username,
	                        AUDIT_NO_ID,
	                        hostname,
	                        NULL,    /* addr */
	                        tty,
	                        1);      /* result */
	close (audit_fd);
#endif				/* WITH_AUDIT */

#ifndef USE_PAM			/* pam_lastlog handles this */
	if (getdef_bool ("LASTLOG_ENAB")) {	/* give last login and log this one */
		dolastlog (&ll, pwd, tty, hostname);
	}
#endif

#ifndef USE_PAM			/* PAM handles this as well */
	/*
	 * Have to do this while we still have root privileges, otherwise we
	 * don't have access to /etc/shadow.
	 */
	if (NULL != spwd) {		/* check for age of password */
		if (expire (pwd, spwd)) {
			/* The user updated her password, get the new
			 * entries.
			 * Use the x variants because we need to keep the
			 * entry for a long time, and there might be other
			 * getxxyy in between.
			 */
			pw_free (pwd);
			pwd = xgetpwnam (username);
			if (NULL == pwd) {
				SYSLOG ((LOG_ERR,
				         "cannot find user %s after update of expired password",
				         username));
				exit (1);
			}
			spw_free (spwd);
			spwd = xgetspnam (username);
		}
	}
	setup_limits (pwd);	/* nice, ulimit etc. */
#endif				/* ! USE_PAM */
//	chown_tty (pwd);

#ifdef USE_PAM
	/*
	 * We must fork before setuid() because we need to call
	 * pam_close_session() as root.
	 */
//	(void) signal (SIGINT, SIG_IGN);
//	child = fork ();
//	if (child < 0) {
//		/* error in fork() */
//		fprintf (stderr, _("%s: failure forking: %s"),
//		         Prog, strerror (errno));
//		PAM_END;
//		exit (0);
//	} else if (child != 0) {
//		/*
//		 * parent - wait for child to finish, then cleanup
//		 * session
//		 */
//		wait (NULL);
//		PAM_END;
//		exit (0);
//	}
	/* child */
	PAM_END;
	exit (0);
#endif

	/* If we were init, we need to start a new session */
//	if (getppid() == 1) {
//		setsid();
//		if (ioctl(0, TIOCSCTTY, 1) != 0) {
//			fprintf (stderr, _("TIOCSCTTY failed on %s"), tty);
//		}
//	}

#ifndef USE_PAM
	/*
	 * The utmp entry needs to be updated to indicate the new status
	 * of the session, the new PID and SID.
	 */
//	update_utmp (username, tty, hostname, utent);
#endif				/* ! USE_PAM */

	/* The pwd and spwd entries for the user have been copied.
	 *
	 * Close all the files so that unauthorized access won't occur.
	 */
//	endpwent ();		/* stop access to password file */
//	endgrent ();		/* stop access to group file */
//	endspent ();		/* stop access to shadow passwd file */
//#ifdef	SHADOWGRP
//	endsgent ();		/* stop access to shadow group file */
//#endif

	/* Drop root privileges */
#ifndef USE_PAM
//	if (setup_uid_gid (pwd, is_console))
#else
	/* The group privileges were already dropped.
	 * See setup_groups() above.
	 */
//	if (change_uid (pwd))
#endif
//	{
//		exit (1);
//	}

//	setup_env (pwd);	/* set env vars, cd to the home dir */

//#ifdef USE_PAM
//	{
//		const char *const *env;
//
//		env = (const char *const *) pam_getenvlist (pamh);
//		while ((NULL != env) && (NULL != *env)) {
//			addenv (*env, NULL);
//			env++;
//		}
//	}
//#endif

//	(void) setlocale (LC_ALL, "");
//	(void) bindtextdomain (PACKAGE, LOCALEDIR);
//	(void) textdomain (PACKAGE);

//	if (!hushed (username)) {
//		addenv ("HUSHLOGIN=FALSE", NULL);
		/*
		 * pam_unix, pam_mail and pam_lastlog should take care of
		 * this
		 */
#ifndef USE_PAM
//		motd ();	/* print the message of the day */
//		if (   getdef_bool ("FAILLOG_ENAB")
//		    && (0 != faillog.fail_cnt)) {
//			failprint (&faillog);
//			/* Reset the lockout times if logged in */
//			if (   (0 != faillog.fail_max)
//			    && (faillog.fail_cnt >= faillog.fail_max)) {
//				(void) puts (_("Warning: login re-enabled after temporary lockout."));
//				SYSLOG ((LOG_WARN,
//				         "login '%s' re-enabled after temporary lockout (%d failures)",
//				         username, (int) faillog.fail_cnt));
//			}
//		}
//		if (   getdef_bool ("LASTLOG_ENAB")
//		    && (ll.ll_time != 0)) {
//			time_t ll_time = ll.ll_time;

//#ifdef HAVE_STRFTIME
//			(void) strftime (ptime, sizeof (ptime),
//			                 "%a %b %e %H:%M:%S %z %Y",
//			                 localtime (&ll_time));
//			printf (_("Last login: %s on %s"),
//			        ptime, ll.ll_line);
//#else
//			printf (_("Last login: %.19s on %s"),
//			        ctime (&ll_time), ll.ll_line);
//#endif
//#ifdef HAVE_LL_HOST		/* __linux__ || SUN4 */
//			if ('\0' != ll.ll_host[0]) {
//				printf (_(" from %.*s"),
//				        (int) sizeof ll.ll_host, ll.ll_host);
//			}
//#endif
//			printf (".\n");
//		}
		agecheck (spwd);

//		mailcheck ();	/* report on the status of mail */
#endif				/* !USE_PAM */
//	} else {
//		addenv ("HUSHLOGIN=TRUE", NULL);
//	}

//	ttytype (tty);

	(void) signal (SIGQUIT, SIG_DFL);	/* default quit signal */
	(void) signal (SIGTERM, SIG_DFL);	/* default terminate signal */
	(void) signal (SIGALRM, SIG_DFL);	/* default alarm signal */
	(void) signal (SIGHUP, SIG_DFL);	/* added this.  --marekm */
	(void) signal (SIGINT, SIG_DFL);	/* default interrupt signal */

	if (0 == pwd->pw_uid) {
		SYSLOG ((LOG_NOTICE, "ROOT LOGIN %s", fromhost));
	} else if (getdef_bool ("LOG_OK_LOGINS")) {
		SYSLOG ((LOG_INFO, "'%s' logged in %s", username, fromhost));
	}
	closelog ();
//	tmp = getdef_str ("FAKE_SHELL");
//	if (NULL != tmp) {
//		err = shell (tmp, pwd->pw_shell, newenvp); /* fake shell */
//	} else {
//		/* exec the shell finally */
//		err = shell (pwd->pw_shell, (char *) 0, newenvp);
//	}
	close(fd0);
	close(fd1);
	close(fd2);
	return 0;
}

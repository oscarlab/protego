/*
 * Copyright (c) 1996       , Michael Meskes
 * Copyright (c) 1996 - 2000, Marek Michałkiewicz
 * Copyright (c) 2002 - 2006, Tomasz Kłoczko
 * Copyright (c) 2008 - 2011, Nicolas François
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

/*
 * grpunconv - update /etc/group with information from /etc/gshadow.
 *
 */

#include <config.h>

#ident "$Id: grpunconv.c 3640 2011-11-19 21:51:52Z nekral-guest $"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <grp.h>
#include <getopt.h>
#include "nscd.h"
#include "prototypes.h"
/*@-exitarg@*/
#include "exitcodes.h"
#ifdef SHADOWGRP
#include "groupio.h"
#include "sgroupio.h"
/*
 * Global variables
 */
const char *Prog;

static bool gr_locked  = false;
static bool sgr_locked = false;

/* local function prototypes */
static void fail_exit (int status);
static void usage (int status);
static void process_flags (int argc, char **argv);

static void fail_exit (int status)
{
	if (gr_locked) {
		if (gr_unlock () == 0) {
			fprintf (stderr, _("%s: failed to unlock %s\n"), Prog, gr_dbname ());
			SYSLOG ((LOG_ERR, "failed to unlock %s", gr_dbname ()));
			/* continue */
		}
	}

	if (sgr_locked) {
		if (sgr_unlock () == 0) {
			fprintf (stderr, _("%s: failed to unlock %s\n"), Prog, sgr_dbname ());
			SYSLOG ((LOG_ERR, "failed to unlock %s", sgr_dbname ()));
			/* continue */
		}
	}

	exit (status);
}

static void usage (int status)
{
	FILE *usageout = (E_SUCCESS != status) ? stderr : stdout;
	(void) fprintf (usageout,
	                _("Usage: %s [options]\n"
	                  "\n"
	                  "Options:\n"),
	                Prog);
	(void) fputs (_("  -h, --help                    display this help message and exit\n"), usageout);
	(void) fputs (_("  -R, --root CHROOT_DIR         directory to chroot into\n"), usageout);
	(void) fputs ("\n", usageout);
	exit (status);
}

/*
 * process_flags - parse the command line options
 *
 *	It will not return if an error is encountered.
 */
static void process_flags (int argc, char **argv)
{
	/*
	 * Parse the command line options.
	 */
	int c;
	static struct option long_options[] = {
		{"help", no_argument,       NULL, 'h'},
		{"root", required_argument, NULL, 'R'},
		{NULL, 0, NULL, '\0'}
	};

	while ((c = getopt_long (argc, argv, "hR:",
	                         long_options, NULL)) != -1) {
		switch (c) {
		case 'h':
			usage (E_SUCCESS);
			/*@notreached@*/break;
		case 'R': /* no-op, handled in process_root_flag () */
			break;
		default:
			usage (E_USAGE);
		}
	}

	if (optind != argc) {
		usage (E_USAGE);
	}
}

int main (int argc, char **argv)
{
	const struct group *gr;
	struct group grent;
	const struct sgrp *sg;

	Prog = Basename (argv[0]);

	(void) setlocale (LC_ALL, "");
	(void) bindtextdomain (PACKAGE, LOCALEDIR);
	(void) textdomain (PACKAGE);

	process_root_flag ("-R", argc, argv);

	OPENLOG ("grpunconv");

	process_flags (argc, argv);

	if (sgr_file_present () == 0) {
		exit (0);	/* no /etc/gshadow, nothing to do */
	}

	if (gr_lock () == 0) {
		fprintf (stderr,
		         _("%s: cannot lock %s; try again later.\n"),
		         Prog, gr_dbname ());
		fail_exit (5);
	}
	gr_locked = true;
	if (gr_open (O_RDWR) == 0) {
		fprintf (stderr,
		         _("%s: cannot open %s\n"), Prog, gr_dbname ());
		fail_exit (1);
	}

	if (sgr_lock () == 0) {
		fprintf (stderr,
		         _("%s: cannot lock %s; try again later.\n"),
		         Prog, sgr_dbname ());
		fail_exit (5);
	}
	sgr_locked = true;
	if (sgr_open (O_RDONLY) == 0) {
		fprintf (stderr,
		         _("%s: cannot open %s\n"), Prog, sgr_dbname ());
		fail_exit (1);
	}

	/*
	 * Update group passwords if non-shadow password is "x".
	 */
	(void) gr_rewind ();
	while ((gr = gr_next ()) != NULL) {
		sg = sgr_locate (gr->gr_name);
		if (   (NULL != sg)
		    && (strcmp (gr->gr_passwd, SHADOW_PASSWD_STRING) == 0)) {
			/* add password to /etc/group */
			grent = *gr;
			grent.gr_passwd = sg->sg_passwd;
			if (gr_update (&grent) == 0) {
				fprintf (stderr,
				         _("%s: failed to prepare the new %s entry '%s'\n"),
				         Prog, gr_dbname (), grent.gr_name);
				fail_exit (3);
			}
		}
	}

	if (sgr_close () == 0) {
		fprintf (stderr,
		         _("%s: failure while writing changes to %s\n"),
		         Prog, sgr_dbname ());
		SYSLOG ((LOG_ERR, "failure while writing changes to %s", sgr_dbname ()));
		fail_exit (3);
	}

	if (gr_close () == 0) {
		fprintf (stderr,
		         _("%s: failure while writing changes to %s\n"),
		         Prog, gr_dbname ());
		SYSLOG ((LOG_ERR, "failure while writing changes to %s", gr_dbname ()));
		fail_exit (3);
	}

	if (unlink (SGROUP_FILE) != 0) {
		fprintf (stderr,
		         _("%s: cannot delete %s\n"),
		         Prog, SGROUP_FILE);
		SYSLOG ((LOG_ERR, "cannot delete %s", SGROUP_FILE));
		fail_exit (3);
	}

	if (gr_unlock () == 0) {
		fprintf (stderr, _("%s: failed to unlock %s\n"), Prog, gr_dbname ());
		SYSLOG ((LOG_ERR, "failed to unlock %s", gr_dbname ()));
		/* continue */
	}

	if (sgr_unlock () == 0) {
		fprintf (stderr, _("%s: failed to unlock %s\n"), Prog, sgr_dbname ());
		SYSLOG ((LOG_ERR, "failed to unlock %s", sgr_dbname ()));
		/* continue */
	}

	nscd_flush_cache ("group");

	return 0;
}
#else				/* !SHADOWGRP */
int main (int unused(argc), char **argv)
{
	fprintf (stderr,
		 "%s: not configured for shadow group support.\n", argv[0]);
	exit (1);
}
#endif				/* !SHADOWGRP */


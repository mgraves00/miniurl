/* $Id */

/* copyright here */

#include <sys/queue.h>
#include <sys/types.h>
#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <readpassphrase.h>
#include <unistd.h>

#include <kcgi.h>

#include "miniurl.h"

extern char *__progname;

void
usage(void)
{
	fprintf(stderr, "usage:\t%s <-f dbfile> -u <username>\n",__progname);
	exit(1);
}

int
main(int argc, char **argv)
{
	char pass[512], pass2[512];	/* what should the max password size be? */
	char c, *login, *dbfile;
	struct ort	*o;

	login = dbfile = NULL;
	while ((c = getopt(argc, argv, "f:u:")) != -1) {
		switch (c) {
			case 'f':
				if ((dbfile = strdup(optarg)) == NULL)
					err(1,"strdup");
					/* NOT REACHED */
				break;
			case 'p':
				break;
			case 'u':
				if ((login = strdup(optarg)) == NULL)
					err(1,"strdup");
					/* NOT REACHED */
				break;
			default:
				usage();
				/* NOT REACHED */
				break;
		}
	}
	argc -= optind;
	argv += optind;
	if (login == NULL) {
		warnx("no username specified");
		usage();
		/* NOT REACHED */
	}
	if (dbfile == NULL) {
		warnx("no database specified");
		usage();
		/* NOT REACHED */
	}

	if (!readpassphrase("Password: ", pass, sizeof(pass), RPP_ECHO_OFF))
		err(1, "unable to read password");
		/* NOT REACHED */
	if (!readpassphrase("Retype Password: ", pass2, sizeof(pass2), RPP_ECHO_OFF)) {
		explicit_bzero(pass,sizeof(pass));
		err(1, "unable to read password");
		/* NOT REACHED */
	}
	if (strcmp(pass,pass2) != 0) {
		explicit_bzero(pass,sizeof(pass));
		explicit_bzero(pass2,sizeof(pass2));
		errx(1, "passwords do not match");
		/* NOT REACHED */
	}
	explicit_bzero(pass2,sizeof(pass2));

	// unveil to dbfile path
	// pledge ops to open sqlite file
	if ((o = db_open(dbfile)) == NULL) {
		explicit_bzero(pass,sizeof(pass));
		errx(1,"db_open");
		/* NOT REACHED */
	}

	if ((db_auth_insert(o,login,pass)) < 0) {
		warnx("db_auth_insert");
		goto out;
	}

out:
	explicit_bzero(pass,sizeof(pass));
	db_close(o);
	exit(0);
}


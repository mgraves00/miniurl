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
	fprintf(stderr, "usage:\t%s <-f dbfile> -u <username> -p <pass>\n",__progname);
	exit(1);
}

int
main(int argc, char **argv)
{
	char c, *login, *dbfile, *pass;
	struct ort	*o;

	login = dbfile = NULL;
	while ((c = getopt(argc, argv, "f:p:u:")) != -1) {
		switch (c) {
			case 'f':
				if ((dbfile = strdup(optarg)) == NULL)
					err(1,"strdup");
					/* NOT REACHED */
				break;
			case 'p':
				if ((pass = strdup(optarg)) == NULL)
					err(1,"strdup");
					/* NOT REACHED */
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
	if (pass == NULL) {
		warnx("no password specified");
		usage();
		/* NOT REACHED */
	}

	if ((o = db_open(dbfile)) == NULL) {
		explicit_bzero(pass,sizeof(pass));
		errx(1,"db_open");
		/* NOT REACHED */
	}

	if ((db_auth_get_user(o,login,pass)) == NULL) {
		warnx("db_auth_get_user");
		goto out;
	}
	printf("user verified\n");

out:
	db_close(o);
	exit(0);
}


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

enum _action {
	ACT_ADD,
	ACT_DEL,
	ACT_LIST,
	ACT__MAX
};

void
usage(void)
{
	fprintf(stderr, "usage:\t%s -a <-f dbfile> -u <username>\n",__progname);
	fprintf(stderr, "usage:\t%s -l <-f dbfile>\n",__progname);
	fprintf(stderr, "usage:\t%s -d <-f dbfile> -u <username>\n",__progname);
	exit(1);
}

void
del_login(struct ort *o, char *login)
{
	db_auth_delete_username(o,login);
	return;
}

void
list_login(struct ort *o)
{
	struct auth_q	*list;
	struct auth		*a;
	list = db_auth_list(o);
	TAILQ_FOREACH(a, list, _entries) {
		fprintf(stdout, "%s\n",a->username);
	}
	db_auth_freeq(list);
	return;
}

void
add_login(struct ort *o, char *login)
{
	char pass[512], pass2[512];	/* what should the max password size be? */

	if (!readpassphrase("Password: ", pass, sizeof(pass), RPP_ECHO_OFF)) {
		warn("unable to read password");
		return;
	}
	if (!readpassphrase("Retype Password: ", pass2, sizeof(pass2), RPP_ECHO_OFF)) {
		explicit_bzero(pass,sizeof(pass));
		warn("unable to read password");
		return;
	}
	if (strcmp(pass,pass2) != 0) {
		explicit_bzero(pass,sizeof(pass));
		explicit_bzero(pass2,sizeof(pass2));
		warnx("passwords do not match");
		return;
	}
	explicit_bzero(pass2,sizeof(pass2));
	if ((db_auth_insert(o,login,pass)) < 0) {
		warnx("db_auth_insert");
		explicit_bzero(pass,sizeof(pass));
		return;
	}
	return;
}

int
main(int argc, char **argv)
{
	char 			c, *login, *dbfile;
	struct ort		*o;
	int				action = ACT__MAX;

	login = dbfile = NULL;
	while ((c = getopt(argc, argv, "adf:lu:")) != -1) {
		switch (c) {
			case 'a':
				action = ACT_ADD;
				break;
			case 'd':
				action = ACT_DEL;
				break;
			case 'f':
				if ((dbfile = strdup(optarg)) == NULL)
					err(1,"strdup");
					/* NOT REACHED */
				break;
			case 'l':
				action = ACT_LIST;
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
	if (action == ACT__MAX) {
		warnx("no action specified");
		usage();
		/* NOT REACHED */
	}
	if (login == NULL && (action == ACT_ADD || action == ACT_DEL)) {
		warnx("no username specified");
		usage();
		/* NOT REACHED */
	}
	if (dbfile == NULL) {
		warnx("no database specified");
		usage();
		/* NOT REACHED */
	}

	// unveil to dbfile path
	// pledge ops to open sqlite file
	if ((o = db_open(dbfile)) == NULL) {
		errx(1,"db_open");
		/* NOT REACHED */
	}

	switch(action) {
		case ACT_ADD:
			add_login(o,login);
			break;
		case ACT_DEL:
			del_login(o,login);
			break;
		case ACT_LIST:
			list_login(o);
			break;
	}

	db_close(o);
	exit(0);
}


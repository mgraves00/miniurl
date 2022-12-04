/* $Id */
/*
 * Copyright (c) 2022 Michael Graves
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "config.h"

#if HAVE_SYS_QUEUE
#include <sys/queue.h>
#endif
#include <sys/types.h>
#if HAVE_ERR
#include <err.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <readpassphrase.h>
#include <unistd.h>

#include <kcgi.h>

#include "miniurl.h"

void usage(void);
void del_login(struct ort *, char *);
void list_login(struct ort *);
void add_login(struct ort *, char *, char *);

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
add_login(struct ort *o, char *login, char *arg_pass)
{
	char pass[512], pass2[512];	/* what should the max password size be? */

	if (arg_pass == NULL) {
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
	} else {
		if ((db_auth_insert(o,login,arg_pass)) < 0) {
			warnx("db_auth_insert");
			return;
		}
	}
	return;
}

int
main(int argc, char **argv)
{
	char 			c, *login, *pass, *dbfile;
	struct ort		*o;
	int				action = ACT__MAX;

	login = pass = dbfile = NULL;
	while ((c = getopt(argc, argv, "adf:lp:u:")) != -1) {
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
					/* NOTREACHED */
				break;
			case 'l':
				action = ACT_LIST;
				break;
			case 'p':
				if ((pass = strdup(optarg)) == NULL)
					err(1,"strdup");
					/* NOTREACHED */
				break;
			case 'u':
				if ((login = strdup(optarg)) == NULL)
					err(1,"strdup");
					/* NOTREACHED */
				break;
			default:
				usage();
				/* NOTREACHED */
				break;
		}
	}
	argc -= optind;
	argv += optind;
	if (action == ACT__MAX) {
		warnx("no action specified");
		usage();
		/* NOTREACHED */
	}
	if (login == NULL && (action == ACT_ADD || action == ACT_DEL)) {
		warnx("no username specified");
		usage();
		/* NOTREACHED */
	}
	if (dbfile == NULL) {
		warnx("no database specified");
		usage();
		/* NOTREACHED */
	}

	// unveil to dbfile path
	// pledge ops to open sqlite file
	if ((o = db_open(dbfile)) == NULL) {
		errx(1,"db_open");
		/* NOTREACHED */
	}
	db_role(o,ROLE_admin);

	switch(action) {
		case ACT_ADD:
			add_login(o,login,pass);
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


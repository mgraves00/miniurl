/* $Id$ */
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
#include <sys/queue.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <kcgi.h>
#include <kcgihtml.h>

#include "miniurl.h"

#define DBFILE "/tmp/miniurl.db"
#define LOGFILE "/tmp/outfile.log"
#define TEMPL_PATH "/templates"

#define COOKIESZ		15
#define SLUGSZ			8
#define SLUG_CHARS	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

enum page {
	PAGE_INDEX,
	PAGE_LOGIN,
	PAGE_LIST,
	PAGE_URL,
	PAGE_REDIR,
	PAGE__MAX
};

static const char *pages[PAGE__MAX] = {
	"index",	/* PAGE_INDEX */
	"login",	/* PAGE_LOGIN */
	"urls",		/* PAGE_LIST */
	"url",		/* PAGE_LIST */
};

enum auth_state {
	AUTH_NONE,
	AUTH_OK,
	AUTH_BADUORP,
	AUTH_ERROR,
	AUTH__MAX
};

struct session {
	struct kreq	r;
	struct ort	*o;
	char *cookie;
	char *user;
};

int
validate_slug(char *slug)
{
	const char ALLOWED[] = SLUG_CHARS;
	size_t i, slen;
	slen = strlen(slug);
	if (slen > SLUGSZ)		/* slug too long */
		return(1);
	for (i=0; i<slen; i++) {
		if (strchr(ALLOWED, slug[i]) == NULL)  /* character not found */
			return(1);
	}
	return(0);
}

int
gen_slug(char **slug)
{
	const char ALLOWED[] = SLUG_CHARS;
	int i;
	char c;
	if ((*slug = calloc(SLUGSZ+1,1)) == NULL) {
		kutil_errx(NULL,NULL,"calloc(slug)");
		/* NO RETURN */
	}
	srand(time(NULL));
	for (i=0;i<SLUGSZ;i++) {
		c = rand() % (sizeof(ALLOWED)-1);
		*slug[i] = ALLOWED[c];
	}
	return(0);
}

int
gen_cookie(char **cookie)
{
	const char ALLOWED[] = SLUG_CHARS;
	int i;
	char c;
	if ((*cookie = calloc(COOKIESZ+1,1)) == NULL) {
		kutil_errx(NULL,NULL,"calloc(cookie)");
		/* NO RETURN */
	}
	srand(time(NULL));
	for (i=0;i<COOKIESZ;i++) {
		c = rand() % (sizeof(ALLOWED)-1);
		*cookie[i] = ALLOWED[c];
	}
	return(0);
}

int
lookup_slug(struct session *s, char **url)
{
	struct miniurl		*murl;
	if (validate_slug(s->r.path) != 0) {
		*url = NULL;
		return(0);
	}
	if ((murl = db_miniurl_get_hash(s->o, s->r.path)) == NULL) {
		*url = NULL;
		return(0);
	}
	if ((*url = strdup(murl->url)) == NULL) {
		kutil_errx(NULL,NULL,"strdup(slug)");
		/* NO RETURN */
	}
	db_miniurl_free(murl);
	return(1);
}

int
display_page(struct kreq *r, const char *pagename)
{
	enum kcgi_err	er;

	if ((er = khttp_template(r, NULL, pagename)) != KCGI_OK) {
		kutil_log(r,"ERROR",NULL,"template error: %s",kcgi_strerror(er));
		return(EXIT_FAILURE);
	}
	return(0);
}

void
show_page(struct session *s, int page)
{
}

void
send_redirect(struct session *s, char *loc)
{
	khttp_head(&(s->r), kresps[KRESP_STATUS], "%s", khttps[KHTTP_301]);
	khttp_head(&(s->r), kresps[KRESP_LOCATION], "%s", loc);
	khttp_head(&(s->r), kresps[KRESP_EXPIRES], "%s", "0");
	khttp_head(&(s->r), kresps[KRESP_CACHE_CONTROL], "%s", "no-cache, no-store, must-revalidate");
	khttp_head(&(s->r), kresps[KRESP_PRAGMA], "%s", "no-cache");
}

void
send_error(struct session *s, int code)
{
	khttp_head(&(s->r), kresps[KRESP_STATUS], "%s", khttps[code]);
}

void
delete_slug(struct session *s)
{
	if (validate_slug(s->r.path))
		kutil_errx(NULL,NULL,"delete_slug(validate)");
		/* NO RETURN */
	db_miniurl_delete_hash(s->o, s->r.path);
	return;
}

void
update_slug(struct session *s)
{
	struct kpair		*kv=NULL;
	int 				i;

	if (s->r.fieldsz == 0) {
		kutil_warn(NULL,NULL,"update_slug no data");
		return;
	}
	for (i = 0; i < s->r.fieldsz; i++) {
		if (strcmp(s->r.fields[i].key, "url"))
			kv = &s->r.fields[i];
	}
	if (kv == NULL) {
		kutil_warn(NULL,NULL,"update_slug no url found");
		return;
	}
	if (validate_slug(s->r.path))
		kutil_errx(NULL,NULL,"update_slug(validate)");
		/* NO RETURN */

	if (db_miniurl_update_hash(s->o, s->r.path, kv->val) == 0)
		kutil_errx(NULL,NULL,"update_slug(delete)");
		/* NO RETURN */

	return;
}

int
check_auth(struct session *s) {
	struct auth			*a;
	struct kpair		*u, *p;
	char				*c;
	int					i, found = -1;

	if (s->r.fieldsz == 0)
		return(AUTH_ERROR);
	u = p = NULL;
	for (i = 0; i < s->r.fieldsz; i++) {
		if (strcmp(s->r.fields[i].key, "username"))
			u = &s->r.fields[i];
		if (strcmp(s->r.fields[i].key, "password"))
			p = &s->r.fields[i];
	}
	if (u == NULL || p == NULL)
		return(AUTH_BADUORP);
	if ((a = db_auth_get_user(s->o, u->val, p->val)) == NULL) {
		return(AUTH_BADUORP);
	}
	if ((s->user = strdup(a->username)) == NULL) {
		kutil_errx(NULL,NULL,"strdup(username)");
		/* NO RETURN */
	}
	if (gen_cookie(&c) != 0) {
		kutil_errx(NULL,NULL,"gen_cookie");
		/* NO RETURN */
	}
	s->cookie = c;
	if (db_cookie_insert(s->o, s->user, s->cookie) != 0) {
		kutil_errx(NULL,NULL,"db_cookie_insert");
		/* NO RETURN */
	}
	db_auth_free(a);
	return(AUTH_OK);
}

int
check_cookie(struct session *s) {
	struct cookie		*c;
	struct kpair		*kv;
	int					i, found = -1;

	if (s->r.cookiesz == 0)
		return(AUTH_NONE);
	for (i = 0; i < s->r.cookiesz; i++) {
		if (strcmp(s->r.cookies[i].key,"miniurl_sess")) {
			found = i;
			break;
		}
	}
	if (found == -1)
		return(AUTH_NONE);

	if ((c = db_cookie_get_hash(s->o, s->r.cookies[i].val)) == NULL) {
		return(AUTH_NONE);
	}
	// cookie found.
	if ((s->cookie = strdup(c->cookie)) == NULL) {
		kutil_errx(NULL,NULL,"strdup(cookie)");
		/* NO RETURN */
	}
	if ((s->user = strdup(c->user)) == NULL) {
		kutil_errx(NULL,NULL,"strdup(username)");
		/* NO RETURN */
	}
	db_cookie_free(c);
	return(AUTH_OK);
}

int
main(void)
{
	enum auth_state		authorized = AUTH_NONE;
	enum kcgi_err		er;
	struct session		sess;
	char *				slug_url;
	int					slug_found;

	memset(&sess, 0, sizeof(struct session));

	if (kutil_openlog(LOGFILE) == 0) {
		fprintf(stderr,"failed to open log");
		return(EXIT_FAILURE);
	}

	if ((er = khttp_parse(&sess.r, NULL, 0, pages, PAGE__MAX, PAGE_INDEX)) != KCGI_OK) {
		kutil_errx(NULL,NULL,"khttp_parse: %s", kcgi_strerror(er));
		/* NO RETURN */
	}

	if ((sess.o = db_open(DBFILE)) == NULL) {
		kutil_errx(NULL,NULL,"db_open");
		/* NO RETURN */
	}

	authorized = check_cookie(&sess);

	switch (sess.r.method) {
		case KMETHOD_GET:
			switch (sess.r.page) {
				case PAGE_LOGIN:
					if (authorized == AUTH_OK) {
						send_redirect(&sess, "index");
					} else {
						show_page(&sess, PAGE_LOGIN);
					}
					break;
				case PAGE_LIST:
					if (authorized == AUTH_OK) {
						show_page(&sess, PAGE_LIST);
					} else {
						send_redirect(&sess, "index");
					}

					break;
				case PAGE_URL:
					if (authorized == AUTH_OK) {
						show_page(&sess, PAGE_URL);
					} else {
						send_redirect(&sess, "index");
					}
					break;
				case PAGE__MAX:
					slug_found = lookup_slug(&sess, &slug_url);
					if (slug_found) {
						send_redirect(&sess,slug_url);
						free(slug_url);
					} else {
						send_redirect(&sess,"index");
					}
					break;
				default:
					show_page(&sess, PAGE_INDEX);
			}
			break;
		case KMETHOD_POST:
			if (authorized == AUTH_OK) {
				send_redirect(&sess, "index");
			} else {
				if (check_auth(&sess) == AUTH_OK) {
					send_redirect(&sess, "index");
				} else {
					send_error(&sess, KHTTP_401);
				}
			}
			break;
		case KMETHOD_PUT:
			if (authorized == AUTH_OK) {
				update_slug(&sess);
				send_redirect(&sess, "index");
			} else {
				send_error(&sess, KHTTP_401);
			}
			break;
		case KMETHOD_DELETE:
			if (authorized == AUTH_OK) {
				delete_slug(&sess);
				send_redirect(&sess, "index");
			} else {
				send_error(&sess, KHTTP_401);
			}
			break;
		default:
			send_error(&sess, KHTTP_405);
			break;
	}

	db_close(sess.o);
	khttp_free(&sess.r);
	free(sess.user);
	free(sess.cookie);
	return(EXIT_SUCCESS);
}


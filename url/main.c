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

#define PROGDIR "/miniurl"
#define DBFILE PROGDIR"/miniurl.db"
#define LOGFILE "/tmp/outfile.log"

#define COOKIENAME		"url_authz"
#define COOKIESZ		15
#define SLUGSZ			8
#define SLUG_CHARS	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

int kvalid_url(struct kpair *);
int kvalid_slug(struct kpair *);
int validate_slug(char *);

enum page {
	PAGE_INDEX,
	PAGE_LOGIN,
	PAGE_LIST,
	PAGE_HASH,
	PAGE__MAX
};

static const char *pages[PAGE__MAX] = {
	"index",	/* PAGE_INDEX */
	"login",	/* PAGE_LOGIN */
	"urls",		/* PAGE_LIST */
	"hash",		/* PAGE_HASH */
};

static const char *templates[PAGE__MAX] = {
	PROGDIR"/index.html",
	PROGDIR"/login.html",
	PROGDIR"/list.html",
	PROGDIR"/edit.html",
};

enum key {
	KEY__METHOD,
	KEY_HASH,
	KEY_URL,
	KEY_USER,
	KEY__MAX
};

static const char *const key_names[KEY__MAX] = {
	"_method",
	"hash",
	"url",
	"user",
};

static const struct kvalid keys[KEY__MAX] = {
	{ kvalid_stringne, "_method" },
	{ kvalid_slug, "hash" },
	{ kvalid_stringne, "url" },
	{ kvalid_stringne, "user" },
};

enum var {
	VAR_HASH,
	VAR_URL,
	VAR_USER,
	VAR_METHOD,
	VAR_LIST,
	VAR__MAX
};

static const char *const var_names[VAR__MAX] = {
	"hash",
	"url",
	"user",
	"_method",
	"list",
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
kvalid_url(struct kpair *kp)
{
	char 			*newurl, *oldurl;
	enum kcgi_err	er;
	int				reduced = 0;
	if (kp->valsz == 0)
		return(0);
	/* reduce any urlencoding */
	newurl = NULL;
	oldurl = kp->val;
	while (reduced != 1) {
		if ((er = khttp_urldecode(oldurl, &newurl)) != KCGI_OK) {
			return(0);
		}
		if (strcmp(oldurl,newurl) != 0) {
			free(oldurl);
			oldurl = newurl;
			newurl = NULL;
		} else {
			reduced = 1;
			free(oldurl);
			kp->val = newurl;
			kp->valsz = strlen(newurl);
		}
	}
	/* how to check if the url is proper */
	return(1);
}

int
kvalid_slug(struct kpair *kp)
{
	return(!validate_slug(kp->val));
}

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
	int i,x;
	char *c;
	if ((c = calloc(SLUGSZ+1,1)) == NULL) {
		return(1);
	}
	srand(time(NULL));
	for (i=0;i<SLUGSZ;i++) {
		x = rand() % (sizeof(ALLOWED)-1);
		c[i] = ALLOWED[x];
	}
	*slug = c;
	return(0);
}

int
gen_cookie(char **cookie)
{
	const char ALLOWED[] = SLUG_CHARS;
	int i,x;
	char *c;
	*cookie = NULL;
	if ((c = calloc(COOKIESZ+1,1)) == NULL) {
		return(1);
	}
	srand(time(NULL));
	for (i=0;i<COOKIESZ;i++) {
		x = rand() % (sizeof(ALLOWED)-1);
		c[i] = ALLOWED[x];
	}
	*cookie = c;
	return(0);
}

int
lookup_slug(struct session *s, char **url)
{
	struct miniurl		*murl;
	char				*p;
	if (validate_slug(s->r.pagename) != 0) {
		*url = NULL;
		return(0);
	}
	if ((murl = db_miniurl_get_hash(s->o, s->r.pagename)) == NULL) {
		*url = NULL;
		return(0);
	}
	if ((*url = strdup(murl->url)) == NULL) {
		kutil_errx(&s->r,NULL,"strdup(slug)");
		/* NO RETURN */
	}
	db_miniurl_free(murl);
	return(1);
}

int
value_writer(size_t idx, void *args)
{
	enum kcgi_err	er = KCGI_OK;
	struct session	*s = args;
	char			*p;
	struct miniurl	*u;
	kutil_logx(&s->r, "DEBUG", s->user, "value_writer: VAR %s(%lu)",var_names[idx],idx);
	switch (idx) {
		case VAR_HASH:
		case VAR_URL:
			if (strlen(s->r.path) > 0) {
				if ((u = db_miniurl_get_hash(s->o,s->r.path)) == NULL) {
					kutil_logx(&s->r, "DEBUG", s->user, "failed to find hash %s",s->r.path);
					er = KCGI_SYSTEM;
				} else {
					er = khttp_puts(&s->r, (idx == VAR_HASH) ? u->hash : u->url);
				}
			}
			break;
		case VAR_USER:
			er = khttp_puts(&s->r, s->user);
			break;
		case VAR_METHOD:
			if (strlen(s->r.path) > 0) {
				er = khttp_puts(&s->r, "PUT");
			} else {
				er = khttp_puts(&s->r, "POST");
			}
			break;
		case VAR_LIST:
			{
				struct miniurl_q	*list;
				struct miniurl		*u;
				list = db_miniurl_list(s->o);
				TAILQ_FOREACH(u, list, _entries) {
					khttp_printf(&s->r,"<tr><td>%s</td><td>%s</td><td>%lld</td><td>"
								"<span class=\"icon\"><a href=\"/hash/%s\"><i class=\"fa-solid fa-pen-to-square\"></i></a></span>"
								"<span class=\"icon\"><a href=\"/dhash/%s\"><i class=\"fa-solid fa-trash-can\"></i></a></td></tr></span>\n",
							u->hash, u->url, u->count, u->hash, u->hash);
				}
				db_miniurl_freeq(list);
			}
			break;
		default: /* skip unknown keys */
			er = KCGI_OK;
			break;
	}
	kutil_logx(&s->r, "DEBUG", s->user, "value_writer: er %d",er);
	if (er != KCGI_OK) {
		kutil_warnx(&s->r,s->user,"value_writer: %s",kcgi_strerror(er));
		return(0);
	}
	return(1);
}

void
show_page(struct session *s, int page)
{
	enum kcgi_err	er;
	struct ktemplate t = {
		.key = var_names,
		.keysz = VAR__MAX,
		.arg = s,
		.cb = value_writer
	};
	khttp_head(&s->r, kresps[KRESP_STATUS], "%s", khttps[KHTTP_200]);
	if ((er = khttp_body(&s->r)) != KCGI_OK) {
		kutil_warnx(&s->r,s->user,"khttp_body: %s",kcgi_strerror(er));
		return;
	}
	switch(page) {
		case PAGE_LOGIN:
			if ((er = khttp_template(&s->r, &t, templates[PAGE_LOGIN])) != KCGI_OK) {
				kutil_warnx(&s->r,s->user,"khttp_template(PAGE_LOGIN): %s",kcgi_strerror(er));
				return;
			}
			break;
		case PAGE_LIST:
			if ((er = khttp_template(&s->r, &t, templates[PAGE_LIST])) != KCGI_OK) {
				kutil_warnx(&s->r,s->user,"khttp_template(PAGE_LIST): %s",kcgi_strerror(er));
				return;
			}
			break;
		case PAGE_HASH:
			if ((er = khttp_template(&s->r, &t, templates[PAGE_HASH])) != KCGI_OK) {
				kutil_warnx(&s->r,s->user,"khttp_template(PAGE_HASH): %s",kcgi_strerror(er));
				return;
			}
			break;
		case PAGE_INDEX:
		default:
			if ((er = khttp_template(&s->r, &t, templates[PAGE_INDEX])) != KCGI_OK) {
				kutil_warnx(&s->r,s->user,"khttp_template(PAGE_INDEX): %s",kcgi_strerror(er));
				return;
			}
			break;
	}
	kutil_info(&s->r,s->user,"page '%s' path: %s",pages[page],s->r.fullpath);
	return;
}

void
send_redirect(struct session *s, char *loc, int code)
{
	char	buf[64];
	khttp_head(&s->r, kresps[KRESP_STATUS], "%s", khttps[code]);
	khttp_head(&s->r, kresps[KRESP_LOCATION], "%s", loc);
	khttp_head(&s->r, kresps[KRESP_EXPIRES], "%s", "0");
	khttp_head(&s->r, kresps[KRESP_CACHE_CONTROL], "%s", "no-cache, no-store, must-revalidate");
	khttp_head(&s->r, kresps[KRESP_PRAGMA], "%s", "no-cache");
	if (s->cookie != NULL) {
		khttp_epoch2str(time(NULL) + 1800, buf, sizeof(buf));
		khttp_head(&s->r, kresps[KRESP_SET_COOKIE],
			"%s=%s; path=/; expires=%s", COOKIENAME, s->cookie, buf);
	}
	khttp_body(&s->r);
}

void
send_error(struct session *s, int code)
{
	khttp_head(&(s->r), kresps[KRESP_STATUS], "%s", khttps[code]);
	khttp_body(&s->r);
}

void
delete_slug(struct session *s)
{
	if (s->r.fieldsz == 0) {
		kutil_warnx(&s->r,s->user,"delete_slug: no hash");
		return;
	}
	db_miniurl_delete_hash(s->o, s->r.fieldmap[KEY_HASH]->val);
	return;
}

void
add_slug(struct session *s)
{
	int					rc;
	char				*hash = NULL;
	int 				i;
	if (s->r.fieldsz == 0) {
		kutil_warnx(&s->r,s->user,"add_slug no fields");
		return;
	}
	/* check to see if we have been given a hash... it should already be validated */
	if (s->r.fieldmap[KEY_HASH] != NULL && s->r.fieldmap[KEY_HASH]->state == KPAIR_VALID) {
		if ((hash = strdup(s->r.fieldmap[KEY_HASH]->val)) == NULL) {
			kutil_warn(&s->r,s->user,"add_slug: strdup");
			return;
		}
	/* otherwise we need to generate one */
	} else {
		gen_slug(&hash);
	}
	if ((rc = db_miniurl_insert(s->o, hash, s->r.fieldmap[KEY_URL]->val, 0)) < 0) {
		kutil_warnx(&s->r,s->user,"add_slug: failed to insert (%s,%s,0): %d",hash,s->r.fieldmap[KEY_URL]->val,rc);
		free(hash);
		return;
	}
	free(hash);
	return;
}

void
update_slug(struct session *s)
{
	if (s->r.fieldsz == 0) {
		kutil_warnx(&s->r,s->user,"update_slug no fields");
		return;
	}
	if (s->r.fieldmap[KEY_URL] == NULL || s->r.fieldmap[KEY_URL]->val == NULL) {
		kutil_warnx(&s->r,s->user,"update_slug no url found");
		return;
	}
	if (db_miniurl_update_url(s->o, s->r.fieldmap[KEY_URL]->val, s->r.fieldmap[KEY_HASH]->val) == 0) {
		kutil_warnx(&s->r,s->user,"update_slug(db_miniurl_update_url)");
		return;
	}
	return;
}

void
update_slug_counter(struct session *s)
{
	if (validate_slug(s->r.pagename) != 0) {
		kutil_warnx(&s->r,s->user,"update_slug_counter invalid slug");
		return;
	}
	db_miniurl_update_counter(s->o, 1, s->r.pagename);
	return;
}

int
check_auth(struct session *s)
{
	struct auth			*a;
	struct kpair		*u, *p;
	char				*c = NULL;
	int					i, found = -1, rc;

	if (s->r.fieldsz == 0)
		return(AUTH_ERROR);
	u = p = NULL;
	for (i = 0; i < s->r.fieldsz; i++) {
		if (strcmp(s->r.fields[i].key, "username") == 0)
			u = &s->r.fields[i];
		if (strcmp(s->r.fields[i].key, "password") == 0)
			p = &s->r.fields[i];
	}
	if (u == NULL || p == NULL)
		return(AUTH_BADUORP);
	kutil_logx(&s->r, "DEBUG", NULL, "user '%s'",u->val);
	kutil_logx(&s->r, "DEBUG", NULL, "pass '%s'",p->val);
	if ((a = db_auth_get_user(s->o, u->val, p->val)) == NULL) {
		kutil_warnx(&s->r, NULL, "unknown user %s",u->val);
		return(AUTH_BADUORP);
	}
	if ((s->user = strdup(a->username)) == NULL) {
		kutil_warnx(&s->r,NULL,"strdup(username)");
		return(AUTH_ERROR);
	}
	kutil_logx(&s->r, "DEBUG", NULL, "user found '%s'",s->user);
	if (gen_cookie(&c) != 0) {
		kutil_logx(&s->r, "DEBUG", NULL, "gen_cookie(error)");
		return(AUTH_ERROR);
	}
	s->cookie = c;
	kutil_logx(&s->r, "DEBUG", s->user, "cookie '%s'",s->cookie);
	if ((rc = db_cookie_insert(s->o, s->cookie, s->user)) < 0) {
		kutil_logx(&s->r,"DEBUG",s->user,"db_cookie_insert failed %d", rc);
		return(AUTH_ERROR);
	}
	kutil_logx(&s->r, "DEBUG", NULL, "success");
	db_auth_free(a);
	return(AUTH_OK);
}

int
check_cookie(struct session *s)
{
	struct cookie		*c;
	struct kpair		*kv;
	int					i, found = -1;

	kutil_logx(&s->r, "DEBUG", NULL, "cookiesz %lu",s->r.cookiesz);
	if (s->r.cookiesz == 0)
		return(AUTH_NONE);
	for (i = 0; i < s->r.cookiesz; i++) {
		kutil_logx(&s->r, "DEBUG", NULL, "key[%d] = %s",i, s->r.cookies[i].key);
		if (strcmp(s->r.cookies[i].key,COOKIENAME) == 0) {
			found = i;
			break;
		}
	}
	kutil_logx(&s->r, "DEBUG", NULL, "found %d",found);
	if (found == -1)
		return(AUTH_NONE);
	kutil_logx(&s->r, "DEBUG", NULL, "cookie %s",s->r.cookies[i].val);
	if ((c = db_cookie_get_hash(s->o, s->r.cookies[i].val)) == NULL) {
		return(AUTH_NONE);
	}
	kutil_logx(&s->r, "DEBUG", NULL, "cookie user %s",c->user);
	if ((s->user = strdup(c->user)) == NULL) {
		kutil_logx(&s->r,"DEBUG",NULL,"strdup(user)");
		return(AUTH_ERROR);
	}
	kutil_logx(&s->r, "DEBUG", NULL, "cookie value %s",c->cookie);
	if ((s->cookie = strdup(c->cookie)) == NULL) {
		kutil_logx(&s->r,"DEBUG",NULL,"strdup(cookie)");
		return(AUTH_ERROR);
	}
	db_cookie_free(c);
	kutil_logx(&s->r, "DEBUG", NULL, "cookie rc AUTH_OK");
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

	if (kutil_openlog(NULL) == 0) {
		fprintf(stderr,"failed to open log");
		return(EXIT_FAILURE);
	}

	if ((er = khttp_parse(&sess.r, keys, KEY__MAX, pages, PAGE__MAX, PAGE_INDEX)) != KCGI_OK) {
		fprintf(stderr,"khttp_parse: %s", kcgi_strerror(er));
		return(EXIT_FAILURE);
	}

	kutil_logx(&sess.r,"DEBUG",sess.user,"dbfile: %s",DBFILE);
	if ((sess.o = db_open(DBFILE)) == NULL) {
		kutil_warnx(&sess.r,NULL,"db_open");
		return(EXIT_FAILURE);
	}

	if (sess.r.method == KMETHOD_POST && sess.r.fieldmap[KEY__METHOD] != NULL &&
			sess.r.fieldmap[KEY__METHOD]->state == KPAIR_VALID) {
		if (strncasecmp(sess.r.fieldmap[KEY__METHOD]->val,"PUT",sess.r.fieldmap[KEY__METHOD]->valsz) == 0) {
			sess.r.method = KMETHOD_PUT;
		} else if (strncasecmp(sess.r.fieldmap[KEY__METHOD]->val,"DELETE",sess.r.fieldmap[KEY__METHOD]->valsz) == 0) {
			sess.r.method = KMETHOD_DELETE;
		}
	}

	authorized = check_cookie(&sess);
	kutil_logx(&sess.r,"DEBUG",sess.user,"authorized: %s(%d)",(authorized?"true":"false"),authorized);
	kutil_logx(&sess.r,"DEBUG",sess.user,"method: %s",kmethods[sess.r.method]);
	kutil_logx(&sess.r,"DEBUG",sess.user,"path: %s",sess.r.path);
	kutil_logx(&sess.r,"DEBUG",sess.user,"fullpath: %s",sess.r.fullpath);
	kutil_logx(&sess.r,"DEBUG",sess.user,"host: %s",sess.r.host);
	kutil_logx(&sess.r,"DEBUG",sess.user,"pagename: %s",sess.r.pagename);
	kutil_logx(&sess.r,"DEBUG",sess.user,"cookiesz: %lu",sess.r.cookiesz);
	kutil_logx(&sess.r,"DEBUG",sess.user,"fieldsz: %lu",sess.r.fieldsz);
	kutil_logx(&sess.r,"DEBUG",sess.user,"keysz: %lu",sess.r.keysz);
	kutil_logx(&sess.r,"DEBUG",sess.user,"page: %lu",sess.r.page);
	switch (sess.r.method) {
		case KMETHOD_GET:
			switch (sess.r.page) {
				case PAGE_LOGIN:
					if (authorized == AUTH_OK) {
						send_redirect(&sess, "/urls", KHTTP_301);
					} else {
						show_page(&sess, PAGE_LOGIN);
					}
					break;
				case PAGE_LIST:
					if (authorized == AUTH_OK) {
						show_page(&sess, PAGE_LIST);
					} else {
						send_redirect(&sess, "/index", KHTTP_301);
					}
					break;
				case PAGE_HASH:
					if (authorized == AUTH_OK) {
						show_page(&sess, PAGE_HASH);
					} else {
						send_redirect(&sess, "/index", KHTTP_301);
					}
					break;
				case PAGE__MAX:
					kutil_logx(&sess.r,"DEBUG",sess.user,"finding slug");
					slug_found = lookup_slug(&sess, &slug_url);
					kutil_logx(&sess.r,"DEBUG",sess.user,"slug found: %s",(slug_found?"found":"not found"));
					kutil_logx(&sess.r,"DEBUG",sess.user,"slug url: %s",slug_url);
					if (slug_found) {
						kutil_logx(&sess.r,"DEBUG",sess.user,"sending redirect");
						send_redirect(&sess,slug_url, KHTTP_301);
						update_slug_counter(&sess);
						free(slug_url);
					} else {
						send_redirect(&sess,"/index",KHTTP_301);
					}
					break;
				default:
					show_page(&sess, PAGE_INDEX);
			}
			break;
		case KMETHOD_POST:
			switch (sess.r.page) {
				case PAGE_LOGIN:
					if (authorized == AUTH_OK) {
						send_redirect(&sess, "/urls", KHTTP_303);
					} else if (check_auth(&sess) != AUTH_OK) {
						send_redirect(&sess, "/login", KHTTP_303);
					} else {
						kutil_warnx(&sess.r, sess.user, "success auth for %s",sess.user);
						send_redirect(&sess, "/urls", KHTTP_303);
					}
					break;
				case PAGE_HASH:
					if (authorized == AUTH_OK) {
						add_slug(&sess);
						send_redirect(&sess, "/urls", KHTTP_303);
					} else {
						send_error(&sess, KHTTP_401);
					}
					break;
				default:
					send_error(&sess, KHTTP_405);
					break;
			}
			break;
		case KMETHOD_PUT:
			switch (sess.r.page) {
				case PAGE_HASH:
					if (authorized == AUTH_OK) {
						update_slug(&sess);
						send_redirect(&sess, "/urls", KHTTP_303);
					} else {
						send_error(&sess, KHTTP_401);
					}
				default:
					send_error(&sess, KHTTP_405);
					break;
			}
			break;
		case KMETHOD_DELETE:
			switch (sess.r.page) {
				case PAGE_HASH:
					if (authorized == AUTH_OK) {
						delete_slug(&sess);
						send_redirect(&sess, "/urls", KHTTP_303);
					} else {
						send_error(&sess, KHTTP_401);
					}
					break;
				default:
					send_error(&sess, KHTTP_405);
					break;
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


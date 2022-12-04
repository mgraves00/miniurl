# $Id$
.SUFFIXES: .ort .h
.PHONY: regress distcheck

.include "${.CURDIR}/../Makefile.inc"

SRCS	=	miniurl.c \
			main.c

CLEANFILES+= miniurl.c miniurl.h

ORTFILE =	${.CURDIR}/../miniurl.ort

LD_PKG	!=	pkg-config --libs kcgi sqlbox 2>/dev/null
CF_PKG	!=	pkg-config --cflags kcgi sqlbox 2>/dev/null

LDADD	+=	${LD_PKG} -lpthread -L/usr/lib -lm -static
CFLAGS	+=	${CF_PKG} -I ${.CURDIR}/obj -g

PROG	= 	url
NOMAN	= 	1

HTMLS	=	index.html \
			edit.html \
			login.html \
			list.html \
			delete.html

FONTS	=	fa-brands-400.ttf \
			fa-brands-400.woff2 \
			fa-regular-400.ttf \
			fa-regular-400.woff2 \
			fa-solid-900.ttf \
			fa-solid-900.woff2 \
			fa-v4compatibility.ttf \
			fa-v4compatibility.woff2

LICENSES=	LICENSE.bulma \
			LICENSE.fontawesome-free-6.2.1


install:
#	@echo [[ ! -d $(DESTDIR)$(SHARDIR)/miniurl ]] && mkdir -p $(DESTDIR)$(SHARDIR)/miniurl
	@echo mkdir -p $(DESTDIR)$(SBINDIR)
	@echo mkdir -p $(DESTDIR)$(CGIBIN)
	@echo mkdir -p $(DESTDIR)$(HTDOCS)
	@echo mkdir -p $(DESTDIR)$(HTDOCS)/webfonts
	@echo $(INSTALL_DATA) $(HTMLS) $(DESTDIR)$(HTDOCS)
	@echo $(INSTALL_DATA) $(FONTS) $(DESTDIR)$(HTDOCS)/webfonts
	@echo $(INSTALL_DATA) $(ORTFILE) $(DESTDIR)$(SHARDIR)/miniurl
	@echo $(INSTALL_DATA) $(LICENSES) $(DESTDIR)$(SHARDIR)/miniurl
	@echo $(INSTALL_PROGRAM) $(PROG) $(DESTDIR)$(CGIBIN)

uninstall:
	@echo rm -f $(DESTDIR)$(SHAREDIR)/miniurl/miniurl.ort
	@echo rmdir $(DESTDIR)$(SHAREDIR)/miniurl
	@echo rm -f $(DESTDIR)$(CGIBIN)/$(PROG)

regress:
	# do nothing

distcheck:
	# do nothing

miniurl.h: ${ORTFILE}
	ort-c-header -v ${ORTFILE} > ${.TARGET}

miniurl.c: ${ORTFILE} miniurl.h
	ort-c-source -v -h miniurl.h ${ORTFILE} > ${.TARGET}

.include <bsd.prog.mk>

# $Id$

ORTFILE= ${.CURDIR}/../miniurl.ort
LD_PKG	!= pkg-config --libs kcgi sqlbox 2>/dev/null
CF_PKG	!= pkg-config --cflags kcgi sqlbox 2>/dev/null
LDADD		+= ${LD_PKG} -lpthread -L/usr/lib -lm
CFLAGS		+= ${CF_PKG} -I ${.CURDIR}/obj -g

CLEANFILES+=	miniurl.c miniurl.h

SRCS=	miniurl.c checkuser.c
PROG=	checkuser
NOMAN=1

miniurl.h: ${ORTFILE}
	ort-c-header -v ${ORTFILE} > ${.TARGET}

miniurl.c: ${ORTFILE} miniurl.h
	ort-c-source -v -h miniurl.h ${ORTFILE} > ${.TARGET}

.include <bsd.prog.mk>

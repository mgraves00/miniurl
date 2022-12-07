# $OpenBSD$

V=		0.5.4
COMMENT=	URL minifier
DISTNAME=	miniurl-v${V}
PKGNAME=	miniurl-${V}
CATEGORIES=	www
HOMEPAGE=	https://github.com/mgraves00/miniurl
MAINTAINER=	Michael Graves <30810535+mgraves00@users.noreply.github.com>

# ISC
PERMIT_PACKAGE=	Yes

GH_ACCOUNT=	mgraves00
GH_PROJECT=	miniurl
GH_TAGNAME=	v${V}

# progs are built static, so no libs
BUILD_DEPENDS=	www/openradtool \
				www/kcgi \
				databases/sqlite3 \
				databases/sqlbox
#RUN_DEPENDS=	databases/sqlite3

WRKSRC=				${WRKDIST}/src
CONFIGURE_STYLE=	simple
NO_TEST= 			yes

.include <bsd.port.mk>

# $OpenBSD$

COMMENT=		URL minifier
DISTNAME=		miniurl-0.5
CATEGORIES=		www
HOMEPAGE=		https://github.com/mgraves00/miniurl
MAINTAINER=		Michael Graves
# ISC
PERMIT_PACKAGE=	Yes
WANTLIB+=		c sqlite3 z
BUILD_DEPENDS=	www/openradtool \
				www/kcgi \
				databases/sqlbox

RUN_DEPENDS=	www/openradtool
MASTER_SITES=	https://github.com/mgraves00/miniurl
CONFIGURE_STYLE=	simple
NO_TEST= 		yes
SUBST_VARS=		VARBASE

.include <bsd.port.mk>

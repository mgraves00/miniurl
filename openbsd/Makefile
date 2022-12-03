# $OpenBSD$

COMMENT=		URL minifier
DISTNAME=		miniurl-0.5
CATEGORIES=		www
HOMEPAGE=		http://xxx
MAINTAINER=		Michael Graves <michael@obtusenet.com>
# ISC
PERMIT_PACKAGE=	Yes
WANTLIB+=		c sqlite3 z
BUILD_DEPENDS=	www/openradtool \
				www/kcgi \
				databases/sqlbox

RUN_DEPENDS=	www/openradtool
MASTER_SITES=
CONFIGURE_STYLE=	none
NO_TEST= 		yes

.include <bsd.port.mk>

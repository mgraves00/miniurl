#
.PHONY: prepdb miniurl
.SUFFIXES: .ort .sql

SUBDIR= url urluser

ORTFILE= miniurl.ort
SQL= miniurl.sql
CLEANFILES+=	miniurl.db miniurl.sql

prepdb: ${SQL}
	sqlite3 ${DESTDIR}miniurl.db < ${SQL}
	sqlite3 ${DESTDIR}miniurl.db < populate.sql

.include "Makefile.inc"

.include <bsd.subdir.mk>

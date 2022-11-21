#
.PHONY: prepdb miniurl
.SUFFIXES: .ort .sql

SUBDIR= url urluser

ORTFILE= miniurl.ort
SQL= miniurl.sql
CLEANFILES+=	miniurl.db miniurl.sql

#all: ${SQL} prepdb

prepdb: ${SQL}
	sqlite3 miniurl.db < ${SQL}
	sqlite3 miniurl.db < populate.sql

.ort.sql: ${ORTFILE}
	ort-sql ${.IMPSRC} > ${.TARGET}

.include <bsd.subdir.mk>

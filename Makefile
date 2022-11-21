#
.PHONY: clean prepdb miniurl
.SUFFIXES: .ort .h
.SUFFIXES: .ort .c
.SUFFIXES: .ort .sql

SUBDIR= url urlpass

OBJS	=	miniurl.o \
			main.o
SRCS	=	miniulr.c \
			main.c

LDKCGI_PKG	!= pkg-config --libs kcgi 2>/dev/null
LDSQLB_PKG	!= pkg-config --libs sqlbox 2>/dev/null
CFKCGI_PKG	!= pkg-config --cflags kcgi 2>/dev/null
CFSQLB_PKG	!= pkg-config --cflags sqlbox 2>/dev/null

LDADD		+= ${LDKCGI_PKG} ${LDSQLB_PKG} -lpthread -L/usr/lib -lm
CFLAGS		+= ${CFKCGI_PKG} ${CFSQLB_PKG}

ORTFILES= miniurl.ort
HEADERS= miniurl.h
SQL= miniurl.sql
BIN=miniurl

all: miniurl ${SQL} prepdb

prepdb:
	sqlite3 miniurl.db < populate.sql

miniurl: ${OBJS}
	${CC} ${LDFLAGS} ${LDADD} --static -o ${.TARGET} ${OBJS}

.ort.h: ${ORTFILES}
	ort-c-header -v ${.IMPSRC} > url/${.TARGET}
	ort-c-header -v ${.IMPSRC} > urlpass/${.TARGET}

.ort.c: ${ORTFILES}
	ort-c-source -v -h ${HEADERS} ${.IMPSRC} > url/${.TARGET}
	ort-c-source -v -h ${HEADERS} ${.IMPSRC} > urlpass/${.TARGET}

.ort.sql: ${ORTFILES}
	ort-sql ${.IMPSRC} > ${.TARGET}

clean:
	-rm miniurl.db
	-rm miniurl.sql

.include <bsd.subdir.mk>

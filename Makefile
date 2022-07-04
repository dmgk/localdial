CC=		cc
CFLAGS=		-g -O2 -std=c11 -Wall -Wextra
LDFLAGS=	-g
LDLIBS=		-lstdthreads

PROG=		localdial
SRCS=		localdial.c
OBJS=		${SRCS:.c=.o}

all:	${PROG}

.c.o:
	${CC} -c ${CFLAGS} -o $@ $<

${PROG}: ${OBJS}
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ ${OBJS} ${LDLIBS}

clean:
	rm -f ${PROG} ${OBJS}

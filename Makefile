PROG:=	htpasswd

GOTOOL?=	go
GOLINT?=	golint

all:	${PROG}
.PHONY:	all

${PROG}:	*.go
	${GOTOOL} build -o ${PROG}

test: ${PROG}
	./test.sh
.PHONY:	test

lint:
	${GOLINT}
.PHONY:	lint

clean:
	rm -f ${PROG}
.PHONY:	clean

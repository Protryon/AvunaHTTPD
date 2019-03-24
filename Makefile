DEPFILE = Makefile.dep
NOINCL = clean
NEEDINCL = ${filter ${NOINCL}, ${MAKECMDGOALS}}

CC = gcc
CFLAGS = -std=gnu11 -Wno-discarded-qualifiers
CFLAGSDEP = ${CFLAGS} -MM

EXECOUT = avuna-httpd
SRCDIRS = src
SOURCELIST = ${foreach MOD, ${SRCDIRS}, ${wildcard ${MOD}/*.h ${MOD}/*.c}}
CSRC = ${filter %.c,${SOURCELIST}}
BUILD_DIR = build
OBJS = ${CSRC:.c=.o}
OBJS_BUILD = ${OBJS:%=${BUILD_DIR}/%}
LIBS = -lssl -lcrypto -lz -lpthread

debug: CFLAGS += -g -O0
debug: ${DEPFILE} ${EXECOUT}

prod: CFLAGS += -O3
prod: ${DEPFILE} ${EXECOUT}

avuna-httpd: ${OBJS}
	${CC} ${CFLAGS} -o ${BUILD_DIR}/$@ ${OBJS_BUILD} ${LIBS}

${BUILD_DIR}/%.o: %.c
	- mkdir -p ${dir $@}
	${CC} ${CFLAGS} -c $< -o $@

%.o: %.c
	- mkdir -p ${BUILD_DIR}/${dir $@}
	${CC} ${CFLAGS} -c $< -o ${BUILD_DIR}/$@

clean:
	- rm -rf ${BUILD_DIR} ${DEPFILE}

dep: ${ALLSOURCE}
	${CC} ${CFLAGSDEP} ${CSRC} >>${DEPFILE}

${DEPFILE}: dep

ifeq (${NEEDINCL}, )
include ${DEPFILE}
endif

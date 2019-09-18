ACLOCAL_AMFLAGS=-I m4

EXTRA_DIST = autogen.sh ChangeLog README.md LICENSE

AM_CPPFLAGS = -Wall -Werror
AM_CPPFLAGS += -fPIC -pipe  -O -Wall -Wextra -Wpointer-arith -Wno-unused-parameter -Wno-deprecated-declarations
AM_CPPFLAGS += $(CODE_COVERAGE_CPPFLAGS) $(CODE_COVERAGE_CFLAGS)
AM_LDFLAGS = --coverage

LDADD = $(CODE_COVERAGE_LIBS)

lib_LTLIBRARIES = @PACKAGE_NAME@.la

@PACKAGE_NAME@_la_CFLAGS = @OAUTH2_CFLAGS@ @OAUTH2_NGINX_CFLAGS@ @NGINX_CFLAGS@
@PACKAGE_NAME@_la_LIBADD = @OAUTH2_LIBS@ @OAUTH2_NGINX_LIBS@ @NGINX_LIBS@
@PACKAGE_NAME@_la_SOURCES = \
	src/@PACKAGE_NAME@.c \
	src/@PACKAGE_NAME@_modules.c
@PACKAGE_NAME@_la_LDFLAGS = -module

@CODE_COVERAGE_RULES@

clang-format:
	clang-format -style=file -i `find . -name *.[ch]`

install:
	sudo cp .libs/@PACKAGE_NAME@.so  /usr/local/nginx/modules/

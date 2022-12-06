AC_INIT([ngx_openidc_module],[3.3.0],[hans.zandbelt@zmartzone.eu])

AM_INIT_AUTOMAKE([foreign no-define subdir-objects])
AC_CONFIG_MACRO_DIRS([m4])

LT_INIT([dlopen])
AC_PROG_CC

AX_CODE_COVERAGE

AC_ARG_WITH([nginx], AS_HELP_STRING([--with-nginx=DIR], [build with NGINX support [default=no]]), [have_nginx="yes"], [have_nginx="no"])
if test x"$have_nginx" = "xyes" ; then
	if test ! -d "$withval"; then
 		AC_MSG_ERROR([Could not find NGINX. Please specify the path to the NGINX sources using the --with-nginx=/full/path/to/nginx-<version> option.])
	else
 		NGINX_CFLAGS="-I$withval/src/core -I$withval/src/event -I$withval/src/event/modules -I$withval/src/os/unix -I$withval/objs -I$withval/src/http -I$withval/src/http/v2 -I$withval/src/http/modules"
		NGINX_LIBS=
		CPPFLAGS_SAVE="$CPPFLAGS"
		CPPFLAGS="$NGINX_CFLAGS $CPPFLAGS"
		AC_CHECK_HEADER([nginx.h], [], [have_nginx="no" NGINX_CFLAGS= NGINX_LIBS=])
		CPPFLAGS="$CPPFLAGS_SAVE"
	fi
fi
AM_CONDITIONAL(HAVE_NGINX, [test x"$have_nginx" = "xyes"])
AC_SUBST(NGINX_CFLAGS)
AC_SUBST(NGINX_LIBS)

PKG_CHECK_MODULES(OAUTH2, [liboauth2 >= 1.4.5.2])
AC_SUBST(OAUTH2_CFLAGS)
AC_SUBST(OAUTH2_LIBS)

PKG_CHECK_MODULES(OAUTH2_NGINX, [liboauth2_nginx >= 1.4.5.2])
AC_SUBST(OAUTH2_NGINX_CFLAGS)
AC_SUBST(OAUTH2_NGINX_LIBS)

AC_CONFIG_FILES([
	Makefile
	src/config
])
AC_OUTPUT

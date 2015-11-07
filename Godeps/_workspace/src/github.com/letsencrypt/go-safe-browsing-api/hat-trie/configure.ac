
AC_INIT([hat-trie], [0.1.0], [dcjones@cs.washington.edu])
AM_INIT_AUTOMAKE([foreign])
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])
AC_CONFIG_MACRO_DIR([m4])

base_CFLAGS="-std=c99 -Wall -Wextra -pedantic"
opt_CFLAGS="${base_CFLAGS} -O3"
dbg_CFLAGS="${base_CFLAGS} -g -O0"

AC_ARG_ENABLE([debugging],
              [AS_HELP_STRING([--enable-debugging],
	                      [enable debugging info (default is no)])],
              [], [enable_debugging=no])

AS_IF([test "x$enable_debugging" = xyes],
      [CFLAGS="$dbg_CFLAGS"],
      [CFLAGS="$opt_CFLAGS"])


AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_DISABLE_SHARED
AC_PROG_LIBTOOL

AC_C_BIGENDIAN([AC_MSG_ERROR([Big-endian systems are not currently supported.])])
AC_HEADER_STDBOOL

AC_CONFIG_FILES([hat-trie-0.1.pc Makefile src/Makefile test/Makefile])
AC_OUTPUT


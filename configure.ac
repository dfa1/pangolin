dnl Autoconf init.
AC_PREREQ(2.60)
AC_INIT(pangolin, 1.0, davide.angelocola@gmail.com)
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADER([src/config.h])

dnl Notices (for `configure --help').
AC_COPYRIGHT([Copyright (C) 2006 Davide Angelocola])
AC_REVISION([$Revision: 1.0 $])

dnl Automake init.
AM_INIT_AUTOMAKE([foreign no-define 1.9 -Wall])

# Checks for programs.
AC_PROG_CC

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_TYPE_SIGNAL
AC_FUNC_STRFTIME
AC_CHECK_FUNCS([gethostbyaddr inet_ntoa memset socket strerror strtol])

dnl Output.
AC_CONFIG_FILES([
	Makefile
	src/Makefile
	test/Makefile
])

AC_OUTPUT

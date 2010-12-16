AUTOMAKE_OPTIONS = foreign no-dependencies

EXTRA_DIST = README.API README.math README.speed NTconfig.h makefile.win32 makefile.win32.dep config.h.win32

include_HEADERS = srp.h srp_aux.h t_pwd.h t_sha.h cstr.h srp_simple.h

noinst_HEADERS = t_defines.h t_read.h  

lib_LIBRARIES = libsrp.a

noinst_PROGRAMS = srp6bench simple_test

libsrp_a_SOURCES = \
  t_conv.c t_conf.c t_sha.c t_math.c t_misc.c t_pw.c \
  t_read.c t_truerand.c cstr.c srp.c srp6_client.c srp6_server.c srp_simple.c

srp6bench_SOURCES = srp6bench.c


AM_CFLAGS = @PICFLAG@

LDADD = libsrp.a


AUTOMAKE_OPTIONS = foreign no-dependencies

EXTRA_DIST = README.API README.math README.speed NTconfig.h makefile.win32 makefile.win32.dep config.h.win32

include_HEADERS = srp.h srp_aux.h t_pwd.h t_sha.h cstr.h

noinst_HEADERS = t_defines.h t_read.h  

lib_LIBRARIES = libsrp.a

libsrp_a_SOURCES = \
  t_conv.c t_conf.c t_sha.c t_math.c t_misc.c \
  t_read.c t_truerand.c cstr.c \
  srp.c rfc2945_client.c rfc2945_server.c srp6_client.c srp6_server.c 

AM_CFLAGS = @PICFLAG@

noinst_PROGRAMS = srptest srpbench srp6bench

srptest_SOURCES = srptest.c
srpbench_SOURCES = srpbench.c
srp6bench_SOURCES = srp6bench.c

LDADD = libsrp.a

INCLUDES =

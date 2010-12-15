/*
 * Copyright (c) 1997-2007  The Stanford SRP Authentication Project
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY 
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  
 *
 * IN NO EVENT SHALL STANFORD BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Redistributions in source or binary form must retain an intact copy
 * of this copyright notice.
 */

#include <stdio.h>
#ifdef WIN32
#include <sys/timeb.h>
#else
#include <sys/time.h>
#endif

#include "t_pwd.h"
#include "srp.h"

int
do_srp6(struct t_confent * pce, struct t_pwent * ppwe,
	const char * user, const char * pass)
{
  SRP_RESULT rc;
  SRP * srps;
  SRP * srpc;
  cstr * t1;
  cstr * t2;
  cstr * ks;
  cstr * kc;

  t1 = NULL;

  srps = SRP_new(SRP6a_server_method());
  if(!SRP_OK(SRP_set_username(srps, user))) {
    printf("SRP_set_username failed\n");
    return -1;
  }
  if(!SRP_OK(SRP_set_params(srps, pce->modulus.data, pce->modulus.len,
			    pce->generator.data, pce->generator.len,
			    ppwe->salt.data, ppwe->salt.len))) {
    printf("SRP_set_params failed\n");
    return -1;
  }
  if(!SRP_OK(SRP_set_authenticator(srps, ppwe->password.data,
				   ppwe->password.len))) {
    printf("SRP_set_authenticator failed\n");
    return -1;
  }

  srpc = SRP_new(SRP6a_client_method());
  if(!SRP_OK(SRP_set_username(srpc, user))) {
    printf("SRP_set_username failed\n");
    return -1;
  }
  if(!SRP_OK(SRP_set_params(srpc, pce->modulus.data, pce->modulus.len,
			    pce->generator.data, pce->generator.len,
			    ppwe->salt.data, ppwe->salt.len))) {
    printf("SRP_set_params failed\n");
    return -1;
  }
  if(!SRP_OK(SRP_gen_pub(srpc, &t1))) {
    printf("SRP_gen_pub failed\n");
    return -1;
  }

  t2 = NULL;
  if(!SRP_OK(SRP_gen_pub(srps, &t2))) {
    printf("SRP_gen_pub failed\n");
    return -1;
  }
  ks = NULL;
  if(!SRP_OK(SRP_compute_key(srps, &ks, t1->data, t1->length))) {
    printf("SRP_compute_key failed\n");
    return -1;
  }

  if(!SRP_OK(SRP_set_auth_password(srpc, pass))) {
    printf("SRP_set_authenticator failed\n");
    return -1;
  }
  kc = NULL;
  if(!SRP_OK(SRP_compute_key(srpc, &kc, t2->data, t2->length))) {
    printf("SRP_compute_key failed\n");
    return -1;
  }
  if(!SRP_OK(SRP_respond(srpc, &kc))) {
    printf("SRP_respond failed\n");
    return -1;
  }

  rc = SRP_verify(srps, kc->data, kc->length);
  if(SRP_OK(rc)) {
    if(!SRP_OK(SRP_respond(srps, &ks))) {
      printf("SRP_respond failed\n");
      return -1;
    }

    rc = SRP_verify(srpc, ks->data, ks->length);
    if(!SRP_OK(rc)) {
      printf("[client] verify status = %d (failure)\n", rc);
      return -1;
    }
  }
  else {
    printf("[server] verify status = %d (failure)\n", rc);
    return -1;
  }
  SRP_free(srpc);
  SRP_free(srps);
  cstr_free(t1);
  cstr_free(t2);
  cstr_free(kc);
  cstr_free(ks);

  return 0;
}

int
do_srp6param(struct t_confent * pce, int iterations)
{
  const char * user = "user";
  const char * pass = "password";
  struct t_pw * tpw;
  struct t_pwent * ppwe;
  double elapsedsecs;
  int i;
#ifdef WIN32
  struct timeb before, after;
  unsigned long elapsedms;
#else
  struct timeval before, after;
  unsigned long elapsedus;
#endif

  tpw = t_newpw();
  ppwe = t_makepwent(tpw, user, pass, NULL, pce);

#ifdef WIN32
  ftime(&before);
#else
  gettimeofday(&before, NULL);
#endif

  for(i = 0; i < iterations; ++i)
    do_srp6(pce, ppwe, user, pass);

#ifdef WIN32
  ftime(&after);
  elapsedms = 1000 * (after.time - before.time) +
    after.millitm - before.millitm;
  elapsedsecs = (double) elapsedms / 1000;
#else
  gettimeofday(&after, NULL);
  elapsedus = 1000000 * (after.tv_sec - before.tv_sec) +
    after.tv_usec - before.tv_usec;
  elapsedsecs = (double) elapsedus / 1000000;
#endif

  printf("%d %d-bit operations in %g seconds (%g ops/s)\n", 2 * iterations,
	 8 * pce->modulus.len, elapsedsecs, 2.0 * iterations / elapsedsecs);

  t_closepw(tpw);

  return 0;
}

int
do_srp6preparam(int pindex, int iterations)
{
  struct t_confent ce;
  struct t_preconf * pc;

  pc = t_getpreparam(pindex);
  if(pc == NULL) {
    fprintf(stderr, "Unable to load parameter set %d\n", pindex);
    exit(2);
  }

  ce.modulus.len = pc->modulus.len;
  ce.modulus.data = pc->modulus.data;
  ce.generator.len = pc->generator.len;
  ce.generator.data = pc->generator.data;
  ce.index = pindex - 1;

  return do_srp6param(&ce, iterations);
}

void
usage()
{
  fprintf(stderr, "Usage: srp6bench [-engine e] [-index]\n");
  fprintf(stderr, "       where 'index' is a precompiled parameter index\n");
  exit(1);
}

/* These should correspond to the preparam numbers of the
 * appropriate bit sizes, preferably the IETF numbers. */

#define PREPARAM_1024 4
#define PREPARAM_2048 8
#define PREPARAM_4096 10

/* Number of iterations to run for each bit length.
 * Should be balanced so that each one takes equally long. */
#define ITERATIONS_1024 360
#define ITERATIONS_2048 120
#define ITERATIONS_4096 40

#define ITERATIONS_GENERIC 50

int
main(argc, argv)
     int argc;
     char **argv;
{
  int pindex = -1;

  SRP_initialize_library();

  while(--argc > 0 && *++argv != NULL) {
    if(strcmp(*argv, "-engine") == 0) {
      if(--argc > 0 && *++argv != NULL) {
	if(!SRP_OK(SRP_use_engine(*argv))) {
	  fprintf(stderr, "Unable to use engine '%s'\n", *argv);
	  exit(2);
	}
      }
      else
	usage();
    }
    else if((*argv)[1] >= '0' && (*argv)[1] <= '9')
      pindex = atoi(*argv + 1);
    else
      usage();
  }

  if(pindex < 0) {
    if(do_srp6preparam(PREPARAM_1024, ITERATIONS_1024) < 0)
      return 1;
    if(do_srp6preparam(PREPARAM_2048, ITERATIONS_2048) < 0)
      return 1;
    if(do_srp6preparam(PREPARAM_4096, ITERATIONS_4096) < 0)
      return 1;
  }
  else {
    if(do_srp6preparam(pindex, ITERATIONS_GENERIC) < 0)
      return 1;
  }

  SRP_finalize_library();
  return 0;
}

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

#include <stdlib.h>
#include <stdio.h>
#include "t_pwd.h"
#include "srp.h"


struct t_pwent {       /* A single password file entry */
  char * name;
  struct t_num password;
  struct t_num salt;
  int index;
};


/* Test SRP authentication by simulating both sides of a session */

int vflag = 0;

int
do_test_pindex(int pindex)
{
  /* classic API */
  struct t_preconf * pc;
  struct t_confent ce;
  struct t_pwent * ppwe;
  struct t_num * A;
  struct t_num * B;
  int i;
  char * hexbuf;
  int hblen;
  unsigned char * ckey;
  unsigned char * skey;
  unsigned char * cresp;
  unsigned char * sresp;
  const char * user = "user";
  const char * pass = "password";

  /* new API */
  SRP * srps;
  SRP * srpc;
  cstr * t1;
  cstr * t2;
  cstr * ks;
  cstr * kc;

  /* cross test */
  struct t_num tmpB;

  printf("[server] initializing password: '%s'\n", pass);

  pc = t_getpreparam(pindex);	/* Use largest parameter set */
  if(pc == NULL) {
    fprintf(stderr, "Unable to load parameter set %d\n", pindex);
    return -1;
  }

  ce.modulus.len = pc->modulus.len;
  ce.modulus.data = pc->modulus.data;
  ce.generator.len = pc->generator.len;
  ce.generator.data = pc->generator.data;
  ce.index = i - 1;

  /* Begin new API test */
  printf("\n*** Testing new API ***\n\n");

  t1 = NULL;
  printf("[client] sending username '%s'\n\n", user);

  printf("[server] initializing session\n");
  srps = SRP_new(SRP_RFC2945_server_method());
  if(SRP_set_username(srps, user) < 0) {
    printf("SRP_set_username failed\n");
    return 1;
  }
  if(SRP_set_params(srps, ce.modulus.data, ce.modulus.len,
		    ce.generator.data, ce.generator.len,
		    ppwe->salt.data, ppwe->salt.len) < 0) {
    printf("SRP_set_params failed\n");
    return 1;
  }
  if(SRP_set_auth_password(srps, pass) < 0) {
    printf("SRP_set_authenticator failed\n");
    return 1;
  }

  printf("[client] initializing session\n");
  srpc = SRP_new(SRP_RFC2945_client_method());
  if(SRP_set_username(srpc, user) != SRP_SUCCESS) {
    printf("SRP_set_username failed\n");
    return 1;
  }
  if(SRP_set_params(srpc, ce.modulus.data, ce.modulus.len,
		    ce.generator.data, ce.generator.len,
		    ppwe->salt.data, ppwe->salt.len) != SRP_SUCCESS) {
    printf("SRP_set_params failed\n");
    return 1;
  }
  if(SRP_gen_pub(srpc, &t1) != SRP_SUCCESS) {
    printf("SRP_gen_pub failed\n");
    return 1;
  }
  if(vflag) {
    BigIntegerToString(srpc->secret, hexbuf, hblen, 16);
    printf("[client private] a = %s\n", hexbuf);
  }
  printf("[client] sending A = %s\n\n", t_tohex(hexbuf, t1->data, t1->length));

  t2 = NULL;
  if(SRP_gen_pub(srps, &t2) != SRP_SUCCESS) {
    printf("SRP_gen_pub failed\n");
    return 1;
  }
  if(vflag) {
    BigIntegerToString(srps->secret, hexbuf, hblen, 16);
    printf("[server private] b = %s\n", hexbuf);
  }
  printf("[server] sending B = %s\n", t_tohex(hexbuf, t2->data, t2->length));
  ks = NULL;
  if(SRP_compute_key(srps, &ks, t1->data, t1->length) != SRP_SUCCESS) {
    printf("SRP_compute_key (server) failed\n");
    return 1;
  }
  if(vflag) {
    BigIntegerToString(srps->u, hexbuf, hblen, 16);
    printf("[server] u = %s\n", hexbuf);
    BigIntegerToString(srps->key, hexbuf, hblen, 16);
    printf("[server] raw key = %s\n", hexbuf);
  }
  printf("[server] session key = %s\n\n",
	 t_tohex(hexbuf, ks->data, ks->length));

  if(SRP_set_auth_password(srpc, pass) != SRP_SUCCESS) {
    printf("SRP_set_authenticator failed\n");
    return 1;
  }
  kc = NULL;
  if(SRP_compute_key(srpc, &kc, t2->data, t2->length) != SRP_SUCCESS) {
    printf("SRP_compute_key (client) failed\n");
    return 1;
  }
  if(vflag) {
    BigIntegerToString(srpc->u, hexbuf, hblen, 16);
    printf("[client] u = %s\n", hexbuf);
    BigIntegerToString(srpc->key, hexbuf, hblen, 16);
    printf("[client] raw key = %s\n", hexbuf);
  }
  printf("[client] session key = %s\n",
	 t_tohex(hexbuf, kc->data, kc->length));
  if(SRP_respond(srpc, &kc) != SRP_SUCCESS) {
    printf("SRP_respond failed\n");
    return 1;
  }
  printf("[client] sending client proof = %s\n\n",
	 t_tohex(hexbuf, kc->data, kc->length));

  i = SRP_verify(srps, kc->data, kc->length);
  printf("[server] verify status = %d (%s)\n", i,
	 (i == SRP_SUCCESS) ? "success" : "failure");
  if(i == SRP_SUCCESS) {
    if(SRP_respond(srps, &ks) != SRP_SUCCESS) {
      printf("SRP_respond failed\n");
      return 1;
    }
    printf("[server] sending server proof = %s\n\n",
	   t_tohex(hexbuf, ks->data, ks->length));

    i = SRP_verify(srpc, ks->data, ks->length);
    printf("[client] verify status = %d (%s)\n", i,
	   (i == SRP_SUCCESS) ? "success" : "failure");
  }
  SRP_free(srpc);
  SRP_free(srps);
  cstr_free(t1);
  cstr_free(t2);
  cstr_free(kc);
  cstr_free(ks);

  if(i != 0)
    return i;

srp6test:
  /* Begin SRP-6 test (new API) */
  printf("\n*** Testing SRP-6a ***\n\n");

  t1 = NULL;
  printf("[client] sending username '%s'\n\n", user);

  printf("[server] initializing session\n");
  srps = SRP_new(SRP6a_server_method());
  if(SRP_set_username(srps, user) < 0) {
    printf("SRP_set_username failed\n");
    return 1;
  }
  if(SRP_set_params(srps, ce.modulus.data, ce.modulus.len,
		    ce.generator.data, ce.generator.len,
		    ppwe->salt.data, ppwe->salt.len) < 0) {
    printf("SRP_set_params failed\n");
    return 1;
  }
  if(SRP_set_auth_password(srps, pass) < 0) {
    printf("SRP_set_authenticator failed\n");
    return 1;
  }

  printf("[client] initializing session\n");
  srpc = SRP_new(SRP6a_client_method());
  if(SRP_set_username(srpc, user) != SRP_SUCCESS) {
    printf("SRP_set_username failed\n");
    return 1;
  }
  if(SRP_set_params(srpc, ce.modulus.data, ce.modulus.len,
		    ce.generator.data, ce.generator.len,
		    ppwe->salt.data, ppwe->salt.len) != SRP_SUCCESS) {
    printf("SRP_set_params failed\n");
    return 1;
  }
  if(SRP_gen_pub(srpc, &t1) != SRP_SUCCESS) {
    printf("SRP_gen_pub failed\n");
    return 1;
  }
  if(vflag) {
    BigIntegerToString(srpc->secret, hexbuf, hblen, 16);
    printf("[client private] a = %s\n", hexbuf);
  }
  printf("[client] sending A = %s\n\n", t_tohex(hexbuf, t1->data, t1->length));

  t2 = NULL;
  if(SRP_gen_pub(srps, &t2) != SRP_SUCCESS) {
    printf("SRP_gen_pub failed\n");
    return 1;
  }
  if(vflag) {
    BigIntegerToString(srps->secret, hexbuf, hblen, 16);
    printf("[server private] b = %s\n", hexbuf);
  }
  printf("[server] sending B = %s\n", t_tohex(hexbuf, t2->data, t2->length));
  ks = NULL;
  if(SRP_compute_key(srps, &ks, t1->data, t1->length) != SRP_SUCCESS) {
    printf("SRP_compute_key (server) failed\n");
    return 1;
  }
  if(vflag) {
    BigIntegerToString(srps->u, hexbuf, hblen, 16);
    printf("[server] u = %s\n", hexbuf);
    BigIntegerToString(srps->key, hexbuf, hblen, 16);
    printf("[server] raw key = %s\n", hexbuf);
  }
  printf("[server] session key = %s\n\n",
	 t_tohex(hexbuf, ks->data, ks->length));

  if(SRP_set_auth_password(srpc, pass) != SRP_SUCCESS) {
    printf("SRP_set_authenticator failed\n");
    return 1;
  }
  kc = NULL;
  if(SRP_compute_key(srpc, &kc, t2->data, t2->length) != SRP_SUCCESS) {
    printf("SRP_compute_key (client) failed\n");
    return 1;
  }
  if(vflag) {
    BigIntegerToString(srpc->u, hexbuf, hblen, 16);
    printf("[client] u = %s\n", hexbuf);
    BigIntegerToString(srpc->key, hexbuf, hblen, 16);
    printf("[client] raw key = %s\n", hexbuf);
  }
  printf("[client] session key = %s\n",
	 t_tohex(hexbuf, kc->data, kc->length));
  if(SRP_respond(srpc, &kc) != SRP_SUCCESS) {
    printf("SRP_respond failed\n");
    return 1;
  }
  printf("[client] sending client proof = %s\n\n",
	 t_tohex(hexbuf, kc->data, kc->length));

  i = SRP_verify(srps, kc->data, kc->length);
  printf("[server] verify status = %d (%s)\n", i,
	 (i == SRP_SUCCESS) ? "success" : "failure");
  if(i == SRP_SUCCESS) {
    if(SRP_respond(srps, &ks) != SRP_SUCCESS) {
      printf("SRP_respond failed\n");
      return 1;
    }
    printf("[server] sending server proof = %s\n\n",
	   t_tohex(hexbuf, ks->data, ks->length));

    i = SRP_verify(srpc, ks->data, ks->length);
    printf("[client] verify status = %d (%s)\n", i,
	   (i == SRP_SUCCESS) ? "success" : "failure");
  }
  SRP_free(srpc);
  SRP_free(srps);
  cstr_free(t1);
  cstr_free(t2);
  cstr_free(kc);
  cstr_free(ks);

  free(hexbuf);

  return i;
}

int
main(argc, argv)
     int argc;
     char ** argv;
{
  int i;
  int pindex = -1;

  SRP_initialize_library();

  while(--argc > 0 && **++argv == '-') {
    if(strcmp(*argv, "-v") == 0)
      ++vflag;
    else if((*argv)[1] >= '0' && (*argv)[1] <= '9')
      pindex = atoi(*argv + 1);
    else if(strcmp(*argv, "-engine") == 0) {
      if(--argc > 0 && *++argv != NULL) {
	if(!SRP_OK(SRP_use_engine(*argv))) {
	  fprintf(stderr, "Unable to use engine '%s'\n", *argv);
	  exit(2);
	}
      }
      else {
	fprintf(stderr, "No engine name supplied - exiting\n");
	exit(1);
      }
    }
    else {
      fprintf(stderr, "Usage: srptest [-v] [-index] [-engine e]\n");
      fprintf(stderr, "       where 'index' is a precompiled parameter index\n");
      exit(1);
    }
  }

  if(pindex < 0) {
    for(pindex = 0; pindex < t_getprecount(); ++pindex) {
      i = do_test_pindex(pindex);
      if(i != 0)
	break;
    }
  }
  else {
    i = do_test_pindex(pindex);
  }

  SRP_finalize_library();

  return i;
}

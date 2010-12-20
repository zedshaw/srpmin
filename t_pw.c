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

#include "t_defines.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "t_pwd.h"
#include "t_read.h"
#include "t_sha.h"
#include "srp_aux.h"

static struct t_pw * syspw = NULL;
static struct t_passwd tpass;

_TYPE( struct t_pw * )
t_newpw()
{
  struct t_pw * tpw;
  if((tpw = malloc(sizeof(struct t_pw))) == NULL)
    return NULL;
  tpw->pwbuf = cstr_new();

  return tpw;
}

_TYPE( void )
t_closepw(tpw)
     struct t_pw * tpw;
{
  if(tpw->pwbuf)
    cstr_clear_free(tpw->pwbuf);
  free(tpw);
}


_TYPE( struct t_pwent * )
t_makepwent(tpw, user, pass, salt, confent)
     struct t_pw * tpw;
     const char * user;
     const char * pass;
     const struct t_num * salt;
     const struct t_confent * confent;
{
  BigInteger x, v, n, g;
  unsigned char dig[SHA_DIGESTSIZE];
  SHA1_CTX ctxt;
  int i = 0;

  tpw->pebuf.name = tpw->userbuf;
  tpw->pebuf.salt.data = tpw->saltbuf;

  strncpy(tpw->pebuf.name, user, MAXUSERLEN);
  tpw->pebuf.index = confent->index;

  if(salt) {
    tpw->pebuf.salt.len = salt->len;
    memcpy(tpw->pebuf.salt.data, salt->data, salt->len);
  }
  else {
    memset(dig, 0, SALTLEN);		/* salt is 80 bits */
    tpw->pebuf.salt.len = SALTLEN;
    do {
      t_random(tpw->pebuf.salt.data, SALTLEN);
    } while(memcmp(tpw->pebuf.salt.data, dig, SALTLEN) == 0);
    if(tpw->pebuf.salt.data[0] == 0)
      tpw->pebuf.salt.data[0] = 0xff;
  }

  n = BigIntegerFromBytes(confent->modulus.data, confent->modulus.len);
  g = BigIntegerFromBytes(confent->generator.data, confent->generator.len);
  v = BigIntegerFromInt(0);

  SHA1Init(&ctxt);
  SHA1Update(&ctxt, user, strlen(user));
  SHA1Update(&ctxt, ":", 1);
  SHA1Update(&ctxt, pass, strlen(pass));
  SHA1Final(dig, &ctxt);

  SHA1Init(&ctxt);
  SHA1Update(&ctxt, tpw->pebuf.salt.data, tpw->pebuf.salt.len);
  SHA1Update(&ctxt, dig, sizeof(dig));
  SHA1Final(dig, &ctxt);

  /* x = H(s, H(u, ':', p)) */
  x = BigIntegerFromBytes(dig, sizeof(dig));

  BigIntegerModExp(v, g, x, n, NULL, NULL);
  BigIntegerToCstr(v, tpw->pwbuf);
  tpw->pebuf.password.data = tpw->pwbuf->data;
  tpw->pebuf.password.len = tpw->pwbuf->length;

  BigIntegerFree(v);
  BigIntegerFree(x);
  BigIntegerFree(g);
  BigIntegerFree(n);

  return &tpw->pebuf;
}



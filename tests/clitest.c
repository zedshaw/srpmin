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
#include "srp_aux.h"
#include "t_pwd.h"
#include "t_client.h"

int
main()
{
  struct t_client * tc;
  struct t_num n;
  struct t_num g;
  struct t_num s;
  struct t_num B;
  char username[MAXUSERLEN];
  char hexbuf[MAXHEXPARAMLEN];
  char buf1[MAXPARAMLEN], buf2[MAXPARAMLEN], buf3[MAXSALTLEN];
  struct t_num * A;
  unsigned char * skey;
  char pass[128];

  printf("Enter username: ");
  gets(username);
  printf("Enter n (from server): ");
  gets(hexbuf);
  n.data = buf1;
  n.len = t_fromb64(n.data, hexbuf);
  printf("Enter g (from server): ");
  gets(hexbuf);
  g.data = buf2;
  g.len = t_fromb64(g.data, hexbuf);
  printf("Enter salt (from server): ");
  gets(hexbuf);
  s.data = buf3;
  s.len = t_fromb64(s.data, hexbuf);

  tc = t_clientopen(username, &n, &g, &s);

  A = t_clientgenexp(tc);
  printf("A (to server): %s\n", t_tob64(hexbuf, A->data, A->len));

  t_getpass(pass, 128, "Enter password:");
  t_clientpasswd(tc, pass);

  printf("Enter B (from server): ");
  gets(hexbuf);
  B.data = buf1;
  B.len = t_fromb64(B.data, hexbuf);

  printf("Enter extra data (optional): ");
  gets(hexbuf);
  t_clientaddexdata(tc, hexbuf, strlen(hexbuf));

  skey = t_clientgetkey(tc, &B);
  printf("Session key: %s\n", t_tohex(hexbuf, skey, 40));
  printf("Response (to server): %s\n",
    t_tohex(hexbuf, t_clientresponse(tc), RESPONSE_LEN));

  t_clientclose(tc);

  return 0;
}

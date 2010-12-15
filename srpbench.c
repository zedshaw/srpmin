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

#include "t_defines.h"
#include "t_pwd.h"
#include "srp_aux.h"

static unsigned char testmod[] =
  { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
static unsigned char testbase[] = { 0x80, 0x00 };
static unsigned char testexp[] = { 0x31, 0x41, 0x59 };

static unsigned char modulus[] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
  0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
  0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
  0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
  0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
  0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
  0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
  0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
  0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
  0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
  0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
  0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
  0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
  0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};
static unsigned char smallbase[] = { 2 };
static unsigned char bigbase[] = {
  0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
  0x02, 0x46, 0x8A, 0xCE, 0x13, 0x57, 0x9B, 0xDF,
  0x03, 0x69, 0xCF, 0x25, 0x8B, 0xE1, 0x47, 0xAD,
  0x04, 0x8C, 0x15, 0x9D, 0x26, 0xAE, 0x37, 0xBF,
  0x05, 0xAF, 0x49, 0xE3, 0x8D, 0x27, 0xC1, 0x6B,
  0x06, 0xC2, 0x8E, 0x4A, 0x17, 0xD3, 0x9F, 0x5B,
  0x07, 0xE5, 0xC3, 0xA1, 0x8F, 0x6D, 0x4B, 0x29,
  0x08, 0x19, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F,
  0x09, 0x2B, 0x4D, 0x6F, 0x81, 0xA3, 0xC5, 0xE7,
  0x0A, 0x4E, 0x82, 0xC6, 0x1B, 0x5F, 0x93, 0xD7,
  0x0B, 0x61, 0xC7, 0x2D, 0x8e, 0xE9, 0x4F, 0xA5,
  0x0C, 0x84, 0x1D, 0x95, 0x2E, 0xA6, 0x3F, 0xB7,
  0x0D, 0xA7, 0x41, 0xEB, 0x85, 0x2F, 0xC9, 0x63,
  0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
  0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2B, 0x1A, 0x0F
};
static unsigned char smallexp[] = { 0xFD, 0xB9, 0x75, 0x31 };
static unsigned char bigexp[] = {
  0xF7, 0xE6, 0xD5, 0xC4, 0xB3, 0xA2, 0x91, 0x80,
  0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
  0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,
  0x08, 0x19, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F
};

#define NRUNS 20
#define PERF_NORM 671	/* Standardized to 167MHz UltraSparc-1 */

double
bench_modexp(b, e, m)
     BigInteger b, e, m;
{
  BigInteger r;
#ifdef WIN32
  struct timeb before, after;
  unsigned long elapsedms;
#else
  struct timeval before, after;
  unsigned long elapsedus;
#endif
  int i;

  r = BigIntegerFromInt(0);
#ifdef WIN32
  ftime(&before);
#else
  gettimeofday(&before, NULL);
#endif
  for(i = 0; i < NRUNS; ++i)
    BigIntegerModExp(r, b, e, m, NULL, NULL);
#ifdef WIN32
  ftime(&after);
  elapsedms = 1000 * (after.time - before.time) +
    after.millitm - before.millitm;
  return (double) elapsedms / NRUNS / 1000;
#else
  gettimeofday(&after, NULL);
  elapsedus = 1000000 * (after.tv_sec - before.tv_sec) +
    after.tv_usec - before.tv_usec;
  return (double) elapsedus / NRUNS / 1000000;
#endif
}

void
usage()
{
  fprintf(stderr, "Usage: srpbench [-engine e]\n");
  exit(1);
}

int
main(argc, argv)
     int argc;
     char **argv;
{
  BigInteger b, m, e, r;
  char hexbuf[MAXHEXPARAMLEN];
  double tb, te, tg;

  BigIntegerInitialize();

  while(--argc > 0 && *++argv != NULL) {
    if(strcmp(*argv, "-engine") == 0) {
      if(--argc > 0 && *++argv != NULL) {
	if(!BigIntegerOK(BigIntegerUseEngine(*argv))) {
	  fprintf(stderr, "Unable to use engine '%s'\n", *argv);
	  exit(2);
	}
      }
      else
	usage();
    }
    else
      usage();
  }

  printf("math library test: ");
  printf("0x%s ^ ", t_tohex(hexbuf, testbase, sizeof(testbase)));
  b = BigIntegerFromBytes(testbase, sizeof(testbase));
  printf("0x%s mod ", t_tohex(hexbuf, testexp, sizeof(testexp)));
  e = BigIntegerFromBytes(testexp, sizeof(testexp));
  printf("0x%s = ", t_tohex(hexbuf, testmod, sizeof(testmod)));
  m = BigIntegerFromBytes(testmod, sizeof(testmod));
  r = BigIntegerFromInt(0);
  BigIntegerModExp(r, b, e, m, NULL, NULL);
  BigIntegerToHex(r, hexbuf, sizeof(hexbuf));
  printf("0x%s\n", hexbuf);
  printf("(correct result is 0x1cebdf2e340234)\n\n");

  BigIntegerFree(b);
  BigIntegerFree(e);
  BigIntegerFree(m);
  BigIntegerFree(r);

  m = BigIntegerFromBytes(modulus, sizeof(modulus));

  b = BigIntegerFromBytes(smallbase, sizeof(smallbase));
  e = BigIntegerFromBytes(bigexp, sizeof(bigexp));
  tg = (int) (1000 * bench_modexp(b, e, m));
  printf("t[g] = %.1lf ms\n", tg);
  BigIntegerFree(b);
  b = BigIntegerFromBytes(bigbase, sizeof(bigbase));
  tb = 1000.0 * bench_modexp(b, e, m);
  printf("t[b] = %.1lf ms\n", tb);
  BigIntegerFree(e);
  e = BigIntegerFromBytes(smallexp, sizeof(smallexp));
  te = 1000.0 * bench_modexp(b, e, m);
  printf("t[e] = %.1lf ms\n", te);

  printf("\nSRPbench total:  %.1lf\n", tb + tg + te);
  printf("Performance index:  %.3lf\n", (double) PERF_NORM / (tb + tg + te));

  BigIntegerFree(b);
  BigIntegerFree(e);
  BigIntegerFree(m);

  BigIntegerFinalize();

  return 0;
}


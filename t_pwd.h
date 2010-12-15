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

#ifndef T_PWD_H
#define T_PWD_H

#include <stdio.h>
#include "cstr.h"

#define MAXPARAMBITS	2048
#define MAXPARAMLEN	((MAXPARAMBITS + 7) / 8)
#define MAXB64PARAMLEN	((MAXPARAMBITS + 5) / 6 + 1)
#define MAXHEXPARAMLEN	((MAXPARAMBITS + 3) / 4 + 1)
#define MAXOCTPARAMLEN	((MAXPARAMBITS + 2) / 3 + 1)

#define MAXUSERLEN	32
#define MAXSALTLEN	32
#define MAXB64SALTLEN	44	/* 256 bits in b64 + null */
#define SALTLEN		10	/* Normally 80 bits */

#define RESPONSE_LEN	20	/* 160-bit proof hashes */
#define SESSION_KEY_LEN	(2 * RESPONSE_LEN)	/* 320-bit session key */

#define DEFAULT_PASSWD	"/etc/tpasswd"
#define DEFAULT_CONF	"/etc/tpasswd.conf"

struct t_num {	/* Standard byte-oriented integer representation */
  int len;
  unsigned char * data;
};

struct t_preconf {	/* Structure returned by t_getpreparam() */
  char * mod_b64;
  char * gen_b64;
  char * comment;

  struct t_num modulus;
  struct t_num generator;
};

/*
 * The built-in (known good) parameters access routines
 *
 * "t_getprecount" returns the number of precompiled parameter sets.
 * "t_getpreparam" returns the indicated parameter set.
 * Memory is statically allocated - callers need not perform any memory mgmt.
 */
_TYPE( int ) t_getprecount();
_TYPE( struct t_preconf * ) t_getpreparam P((int));

struct t_confent {	/* One configuration file entry (index, N, g) */
  int index;
  struct t_num modulus;
  struct t_num generator;
};

struct t_conf {		/* An open configuration file */
  FILE * instream;
  char close_on_exit;
  cstr * modbuf;
  cstr * genbuf;
  struct t_confent tcbuf;
};

/*
 * The configuration file routines are designed along the lines of the
 * "getpw" functions in the standard C library.
 *
 * "t_openconf" accepts a stdio stream and interprets it as a config file.
 * "t_openconfbyname" accepts a filename and does the same thing.
 * "t_closeconf" closes the config file.
 * "t_getconfent" fetches the next sequential configuration entry.
 * "t_getconfbyindex" fetches the configuration entry whose index
 *   matches the one supplied, or NULL if one can't be found.
 * "t_getconflast" fetches the last configuration entry in the file.
 * "t_makeconfent" generates a set of configuration entry parameters
 *   randomly.
 * "t_newconfent" returns an empty configuration entry.
 * "t_cmpconfent" compares two configuration entries a la strcmp.
 * "t_checkconfent" verifies that a set of configuration parameters
 *   are suitable.  N must be prime and should be a safe prime.
 * "t_putconfent" writes a configuration entry to a stream.
 */
_TYPE( struct t_conf * ) t_openconf P((FILE *));
_TYPE( struct t_conf * ) t_openconfbyname P((const char *));
_TYPE( void ) t_closeconf P((struct t_conf *));
_TYPE( void ) t_rewindconf P((struct t_conf *));
_TYPE( struct t_confent * ) t_getconfent P((struct t_conf *));
_TYPE( struct t_confent * ) t_getconfbyindex P((struct t_conf *, int));
_TYPE( struct t_confent * ) t_getconflast P((struct t_conf *));
_TYPE( struct t_confent * ) t_makeconfent P((struct t_conf *, int));
_TYPE( struct t_confent * ) t_makeconfent_c P((struct t_conf *, int));
_TYPE( struct t_confent * ) t_newconfent P((struct t_conf *));
_TYPE( int ) t_cmpconfent P((const struct t_confent *, const struct t_confent *));
_TYPE( int ) t_checkconfent P((const struct t_confent *));
_TYPE( void ) t_putconfent P((const struct t_confent *, FILE *));

/* Minimal password creation. */

struct t_pwent {	/* A single password file entry */
  char * name;
  struct t_num password;
  struct t_num salt;
  int index;
};

struct t_pw {		/* An open password file */
  char userbuf[MAXUSERLEN];
  cstr * pwbuf;
  unsigned char saltbuf[SALTLEN];
  struct t_pwent pebuf;
};

_TYPE( struct t_pw * ) t_newpw();
_TYPE( struct t_pwent * ) t_makepwent P((struct t_pw *, const char *,
					 const char *, const struct t_num *,
					 const struct t_confent *));
_TYPE( void ) t_closepw P((struct t_pw *));

/* Conversion utilities */

/*
 * All these calls accept output as the first parameter.  In the case of
 * t_tohex and t_tob64, the last argument is the length of the byte-string
 * input.
 */
_TYPE( char * ) t_tohex P((char *, const char *, unsigned));
_TYPE( int ) t_fromhex P((char *, const char *));
_TYPE( char * ) t_tob64 P((char *, const char *, unsigned));
_TYPE( int ) t_fromb64 P((char *, const char *));

/* These functions put their output in a cstr object */
_TYPE( char * ) t_tohexcstr P((cstr *, const char *, unsigned));
_TYPE( int ) t_cstrfromhex P((cstr *, const char *));
_TYPE( char * ) t_tob64cstr P((cstr *, const char *, unsigned));
_TYPE( int ) t_cstrfromb64 P((cstr *, const char *));

/* Miscellaneous utilities (moved to t_defines.h) */


#endif

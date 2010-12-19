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
#ifndef _SRP_H_
#define _SRP_H_

#include "cstr.h"
#include "srp_aux.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SRP library version identification */
#define SRP_VERSION_MAJOR 2
#define SRP_VERSION_MINOR 0
#define SRP_VERSION_PATCHLEVEL 1

typedef int SRP_RESULT;
/* Returned codes for SRP API functions */
#define SRP_OK(v) ((v) == SRP_SUCCESS)
#define SRP_SUCCESS 0
#define SRP_ERROR -1

typedef struct srp_st SRP;

#define SRP_DEFAULT_MIN_BITS 512

typedef int (_CDECL * SRP_SECRET_BITS_CB)(int modsize);
_TYPE( SRP_RESULT ) SRP_set_secret_bits_cb P((SRP_SECRET_BITS_CB cb));


/*
 * Client Parameter Verification API
 *
 * This callback is called from the SRP client when the
 * parameters (modulus and generator) are set.  The callback
 * should return SRP_SUCCESS if the parameters are okay,
 * otherwise some error code to indicate that the parameters
 * should be rejected.
 */
typedef SRP_RESULT (_CDECL * SRP_CLIENT_PARAM_VERIFY_CB)(SRP * srp, const unsigned char * mod, int modlen, const unsigned char * gen, int genlen);

/* The default parameter verifier function */
_TYPE( SRP_RESULT ) SRP_CLIENT_default_param_verify_cb(SRP * srp, const unsigned char * mod, int modlen, const unsigned char * gen, int genlen);
/* A parameter verifier that only accepts builtin params (no prime test) */
_TYPE( SRP_RESULT ) SRP_CLIENT_builtin_param_verify_cb(SRP * srp, const unsigned char * mod, int modlen, const unsigned char * gen, int genlen);
/* The "classic" parameter verifier that accepts either builtin params
 * immediately, and performs safe-prime tests on N and primitive-root
 * tests on g otherwise.  SECURITY WARNING: This may allow for certain
 * attacks based on "trapdoor" moduli, so this is not recommended. */
_TYPE( SRP_RESULT ) SRP_CLIENT_compat_param_verify_cb(SRP * srp, const unsigned char * mod, int modlen, const unsigned char * gen, int genlen);

/*
 * Main SRP API - SRP and SRP_METHOD
 */

/* SRP method definitions */
typedef struct srp_meth_st {
  const char * name;

  SRP_RESULT (_CDECL * init)(SRP * srp);
  SRP_RESULT (_CDECL * finish)(SRP * srp);

  SRP_RESULT (_CDECL * params)(SRP * srp,
			       const unsigned char * modulus, int modlen,
			       const unsigned char * generator, int genlen,
			       const unsigned char * salt, int saltlen);
  SRP_RESULT (_CDECL * auth)(SRP * srp, const unsigned char * a, int alen);
  SRP_RESULT (_CDECL * passwd)(SRP * srp,
			       const unsigned char * pass, int passlen);
  SRP_RESULT (_CDECL * genpub)(SRP * srp, cstr ** result);
  SRP_RESULT (_CDECL * key)(SRP * srp, cstr ** result,
			    const unsigned char * pubkey, int pubkeylen);
  SRP_RESULT (_CDECL * verify)(SRP * srp,
			       const unsigned char * proof, int prooflen);
  SRP_RESULT (_CDECL * respond)(SRP * srp, cstr ** proof);

  void * data;
} SRP_METHOD;

/* Magic numbers for the SRP context header */
#define SRP_MAGIC_CLIENT 12
#define SRP_MAGIC_SERVER 28

/* Flag bits for SRP struct */
#define SRP_FLAG_MOD_ACCEL 0x1	/* accelerate modexp operations */
#define SRP_FLAG_LEFT_PAD 0x2	/* left-pad to length-of-N inside hashes */

/*
 * A hybrid structure that represents either client or server state.
 */
struct srp_st {
  int magic;	/* To distinguish client from server (and for sanity) */

  int flags;

  cstr * username;

  BigInteger modulus;
  BigInteger generator;
  cstr * salt;

  BigInteger verifier;
  BigInteger password;

  BigInteger pubkey;
  BigInteger secret;
  BigInteger u;

  BigInteger key;

  cstr * ex_data;

  SRP_METHOD * meth;
  void * meth_data;

  BigIntegerCtx bctx;	     /* to cache temporaries if available */
  BigIntegerModAccel accel;  /* to accelerate modexp if available */

  SRP_CLIENT_PARAM_VERIFY_CB param_cb;	/* to verify params */
};

/*
 * SRP_new() creates a new SRP context object -
 * the method determines which "sense" (client or server)
 * the object operates in.  SRP_free() frees it.
 * (See RFC2945 method definitions below.)
 */
_TYPE( SRP * )      SRP_new P((SRP_METHOD * meth));
_TYPE( SRP_RESULT ) SRP_free P((SRP * srp));

/* RFC2945-style SRP authentication */

#define RFC2945_KEY_LEN SHA_DIGESTSIZE	/* length of session key (bytes) */
#define RFC2945_RESP_LEN SHA_DIGESTSIZE	/* length of proof hashes (bytes) */

/*
 * SRP-6 and SRP-6a authentication methods.
 * SRP-6a is recommended for better resistance to 2-for-1 attacks.
 */
_TYPE( SRP_METHOD * ) SRP6_client_method P((void));
_TYPE( SRP_METHOD * ) SRP6_server_method P((void));
_TYPE( SRP_METHOD * ) SRP6a_client_method P((void));
_TYPE( SRP_METHOD * ) SRP6a_server_method P((void));

#ifdef __cplusplus
}
#endif

#endif /* _SRP_H_ */

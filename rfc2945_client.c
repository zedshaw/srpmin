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
#include "srp.h"
#include "t_pwd.h"	/* for preparams */
#include "t_sha.h"

/*
 * The RFC2945 client keeps track of the running hash
 * state via SHA1_CTX structures pointed to by the
 * meth_data pointer.  The "hash" member is the hash value that
 * will be sent to the other side; the "ckhash" member is the
 * hash value expected from the other side.
 */
struct client_meth_st {
  SHA1_CTX hash;
  SHA1_CTX ckhash;
  unsigned char k[RFC2945_KEY_LEN];
};

#define CLIENT_CTXP(srp)    ((struct client_meth_st *)(srp)->meth_data)

static SRP_RESULT
srp2945_client_init(SRP * srp)
{
  srp->magic = SRP_MAGIC_CLIENT;
  srp->param_cb = SRP_CLIENT_default_param_verify_cb;
  srp->meth_data = malloc(sizeof(struct client_meth_st));
  SHA1Init(&CLIENT_CTXP(srp)->hash);
  SHA1Init(&CLIENT_CTXP(srp)->ckhash);
  return SRP_SUCCESS;
}

static SRP_RESULT
srp2945_client_finish(SRP * srp)
{
  if(srp->meth_data) {
    memset(srp->meth_data, 0, sizeof(struct client_meth_st));
    free(srp->meth_data);
  }
  return SRP_SUCCESS;
}

static SRP_RESULT
srp2945_client_params(SRP * srp, const unsigned char * modulus, int modlen,
		      const unsigned char * generator, int genlen,
		      const unsigned char * salt, int saltlen)
{
  int i;
  unsigned char buf1[SHA_DIGESTSIZE], buf2[SHA_DIGESTSIZE];
  SHA1_CTX ctxt;

  /* Fields set by SRP_set_params */

  /* Update hash state */
  SHA1Init(&ctxt);
  SHA1Update(&ctxt, modulus, modlen);
  SHA1Final(buf1, &ctxt);	/* buf1 = H(modulus) */

  SHA1Init(&ctxt);
  SHA1Update(&ctxt, generator, genlen);
  SHA1Final(buf2, &ctxt);	/* buf2 = H(generator) */

  for(i = 0; i < sizeof(buf1); ++i)
    buf1[i] ^= buf2[i];		/* buf1 = H(modulus) xor H(generator) */

  /* hash: H(N) xor H(g) */
  SHA1Update(&CLIENT_CTXP(srp)->hash, buf1, sizeof(buf1));

  SHA1Init(&ctxt);
  SHA1Update(&ctxt, srp->username->data, srp->username->length);
  SHA1Final(buf1, &ctxt);	/* buf1 = H(user) */

  /* hash: (H(N) xor H(g)) | H(U) */
  SHA1Update(&CLIENT_CTXP(srp)->hash, buf1, sizeof(buf1));

  /* hash: (H(N) xor H(g)) | H(U) | s */
  SHA1Update(&CLIENT_CTXP(srp)->hash, salt, saltlen);

  return SRP_SUCCESS;
}

static SRP_RESULT
srp2945_client_auth(SRP * srp, const unsigned char * a, int alen)
{
  /* On the client, the authenticator is the raw password-derived hash */
  srp->password = BigIntegerFromBytes(a, alen);

  /* verifier = g^x mod N */
  srp->verifier = BigIntegerFromInt(0);
  BigIntegerModExp(srp->verifier, srp->generator, srp->password, srp->modulus, srp->bctx, srp->accel);

  return SRP_SUCCESS;
}

static SRP_RESULT
srp2945_client_passwd(SRP * srp, const unsigned char * p, int plen)
{
  SHA1_CTX ctxt;
  unsigned char dig[SHA_DIGESTSIZE];
  int r;

  SHA1Init(&ctxt);
  SHA1Update(&ctxt, srp->username->data, srp->username->length);
  SHA1Update(&ctxt, ":", 1);
  SHA1Update(&ctxt, p, plen);
  SHA1Final(dig, &ctxt);	/* dig = H(U | ":" | P) */

  SHA1Init(&ctxt);
  SHA1Update(&ctxt, srp->salt->data, srp->salt->length);
  SHA1Update(&ctxt, dig, sizeof(dig));
  SHA1Final(dig, &ctxt);	/* dig = H(s | H(U | ":" | P)) */
  memset(&ctxt, 0, sizeof(ctxt));

  r = SRP_set_authenticator(srp, dig, sizeof(dig));
  memset(dig, 0, sizeof(dig));

  return r;
}

static SRP_RESULT
srp2945_client_genpub(SRP * srp, cstr ** result)
{
  cstr * astr;
  int slen = (SRP_get_secret_bits(BigIntegerBitLen(srp->modulus)) + 7) / 8;

  if(result == NULL)
    astr = cstr_new();
  else {
    if(*result == NULL)
      *result = cstr_new();
    astr = *result;
  }

  cstr_set_length(astr, BigIntegerByteLen(srp->modulus));
  t_random(astr->data, slen);
  srp->secret = BigIntegerFromBytes(astr->data, slen);
  /* Force g^a mod n to "wrap around" by adding log[2](n) to "a". */
  BigIntegerAddInt(srp->secret, srp->secret, BigIntegerBitLen(srp->modulus));
  /* A = g^a mod n */
  srp->pubkey = BigIntegerFromInt(0);
  BigIntegerModExp(srp->pubkey, srp->generator, srp->secret, srp->modulus, srp->bctx, srp->accel);
  BigIntegerToCstr(srp->pubkey, astr);

  /* hash: (H(N) xor H(g)) | H(U) | s | A */
  SHA1Update(&CLIENT_CTXP(srp)->hash, astr->data, astr->length);
  /* ckhash: A */
  SHA1Update(&CLIENT_CTXP(srp)->ckhash, astr->data, astr->length);

  if(result == NULL)	/* astr was a temporary */
    cstr_clear_free(astr);

  return SRP_SUCCESS;
}

static SRP_RESULT
srp2945_client_key(SRP * srp, cstr ** result,
		   const unsigned char * pubkey, int pubkeylen)
{
  SHA1_CTX ctxt;
  unsigned char dig[SHA_DIGESTSIZE];
  BigInteger gb, e;
  cstr * s;

  /* Compute u from server's value */
  SHA1Init(&ctxt);
  SHA1Update(&ctxt, pubkey, pubkeylen);
  SHA1Final(dig, &ctxt);
  srp->u = BigIntegerFromBytes(dig, 4);
  if(BigIntegerCmpInt(srp->u, 0) == 0)
    return SRP_ERROR;

  /* hash: (H(N) xor H(g)) | H(U) | s | A | B */
  SHA1Update(&CLIENT_CTXP(srp)->hash, pubkey, pubkeylen);

  gb = BigIntegerFromBytes(pubkey, pubkeylen);
  /* reject B == 0, B >= modulus */
  if(BigIntegerCmp(gb, srp->modulus) >= 0 || BigIntegerCmpInt(gb, 0) == 0) {
    BigIntegerFree(gb);
    return SRP_ERROR;
  }
  /* unblind g^b (mod N) */
  if(BigIntegerCmp(gb, srp->verifier) < 0)
    BigIntegerAdd(gb, gb, srp->modulus);
  BigIntegerSub(gb, gb, srp->verifier);

  /* compute gb^(a + ux) (mod N) */
  e = BigIntegerFromInt(0);
  BigIntegerMul(e, srp->password, srp->u, srp->bctx);
  BigIntegerAdd(e, e, srp->secret);	/* e = a + ux */

  srp->key = BigIntegerFromInt(0);
  BigIntegerModExp(srp->key, gb, e, srp->modulus, srp->bctx, srp->accel);
  BigIntegerFree(e);
  BigIntegerFree(gb);

  /* convert srp->key into a session key, update hash states */
  s = cstr_new();
  BigIntegerToCstr(srp->key, s);
  t_sessionkey(CLIENT_CTXP(srp)->k, s->data, s->length); /* Interleaved hash */
  cstr_clear_free(s);

  /* hash: (H(N) xor H(g)) | H(U) | s | A | B | K */
  SHA1Update(&CLIENT_CTXP(srp)->hash, CLIENT_CTXP(srp)->k, RFC2945_KEY_LEN);
  /* hash: (H(N) xor H(g)) | H(U) | s | A | B | K | ex_data */
  if(srp->ex_data->length > 0)
    SHA1Update(&CLIENT_CTXP(srp)->hash,
	       srp->ex_data->data, srp->ex_data->length);

  if(result) {
    if(*result == NULL)
      *result = cstr_new();
    cstr_setn(*result, CLIENT_CTXP(srp)->k, RFC2945_KEY_LEN);
  }

  return SRP_SUCCESS;
}

static SRP_RESULT
srp2945_client_verify(SRP * srp, const unsigned char * proof, int prooflen)
{
  unsigned char expected[SHA_DIGESTSIZE];

  SHA1Final(expected, &CLIENT_CTXP(srp)->ckhash);
  if(prooflen == RFC2945_RESP_LEN && memcmp(expected, proof, prooflen) == 0)
    return SRP_SUCCESS;
  else
    return SRP_ERROR;
}

static SRP_RESULT
srp2945_client_respond(SRP * srp, cstr ** proof)
{
  if(proof == NULL)
    return SRP_ERROR;

  if(*proof == NULL)
    *proof = cstr_new();

  /* proof contains client's response */
  cstr_set_length(*proof, RFC2945_RESP_LEN);
  SHA1Final((*proof)->data, &CLIENT_CTXP(srp)->hash);

  /* ckhash: A | M | K */
  SHA1Update(&CLIENT_CTXP(srp)->ckhash, (*proof)->data, (*proof)->length);
  SHA1Update(&CLIENT_CTXP(srp)->ckhash, CLIENT_CTXP(srp)->k, RFC2945_KEY_LEN);
  return SRP_SUCCESS;
}

static SRP_METHOD srp_rfc2945_client_meth = {
  "RFC2945 SRP client (tjw)",
  srp2945_client_init,
  srp2945_client_finish,
  srp2945_client_params,
  srp2945_client_auth,
  srp2945_client_passwd,
  srp2945_client_genpub,
  srp2945_client_key,
  srp2945_client_verify,
  srp2945_client_respond,
  NULL
};

_TYPE( SRP_METHOD * )
SRP_RFC2945_client_method()
{
  return &srp_rfc2945_client_meth;
}

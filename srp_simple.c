#include "srp_simple.h"
#include "dbg.h"

struct t_confent CONFIG;


void ssrp_setup(int pindex, cstr **out_mod, cstr **out_gen) {
    SRP_initialize_library();

    struct t_preconf *pc = NULL;

    pc = t_getpreparam(pindex);
    assert(pc != NULL && "Failed to get preparam.");

    CONFIG.modulus.len = pc->modulus.len;
    CONFIG.modulus.data = pc->modulus.data;
    CONFIG.generator.len = pc->generator.len;
    CONFIG.generator.data = pc->generator.data;
    CONFIG.index = pindex - 1;

    *out_mod = cstr_createn(pc->modulus.data, pc->modulus.len);
    assert(*out_mod != NULL && "Failed to create modulus string.");

    *out_gen = cstr_createn(pc->generator.data, pc->generator.len);
    assert(*out_gen != NULL && "Failed to create generator string.");
}


SRP *ssrp_server_new()
{
    SRP *srps = SRP_new(SRP6a_server_method());
    check(srps != NULL, "Failed to create SRP server system.");

    return srps;

error:
    return NULL;
}

cstr *ssrp_server_start(SRP *srps, cstr *modulus, cstr *generator,
        cstr *salt, cstr *auth, const char * user)
{
    SRP_RESULT rc;
    cstr *server_pub = NULL;

    rc = SRP_set_username(srps, user);
    check(SRP_OK(rc), "SRP_set_username failed\n");

    rc = SRP_set_params(srps, modulus->data, modulus->length,
            generator->data, generator->length, salt->data, salt->length);
    check(SRP_OK(rc), "SRP_set_params failed\n");

    rc = SRP_set_authenticator(srps, auth->data, auth->length);
    check(SRP_OK(rc), "SRP_set_authenticator failed\n");

    rc = SRP_gen_pub(srps, &server_pub);
    check(SRP_OK(rc), "SRP_gen_pub failed\n");

    return server_pub;

error:
    return NULL;
}


cstr *ssrp_server_verify(SRP *srps, cstr *client_pub, cstr *client_proof)
{
    SRP_RESULT rc;

    cstr *server_proof = NULL;

    rc = SRP_compute_key(srps, &server_proof, client_pub->data, client_pub->length);
    check(SRP_OK(rc), "SRP_compute_key failed\n");

    rc = SRP_verify(srps, client_proof->data, client_proof->length);
    check(SRP_OK(rc), "SRP_verify failed: %d", rc);

    rc = SRP_respond(srps, &server_proof);
    check(SRP_OK(rc), "Failed creating the response.");

    return server_proof;

error:

    return NULL;
}


SRP *ssrp_client_new()
{
    SRP * srpc = NULL;

    srpc = SRP_new(SRP6a_client_method());
    check(srpc != NULL, "Failed to start client method.");

    return srpc;
error:
    return NULL;
}


cstr *ssrp_client_start(SRP *srpc, cstr *modulus, cstr *generator, cstr *salt, const char *user)
{
    SRP_RESULT rc;
    cstr * client_pub = NULL;

    rc = SRP_set_username(srpc, user);
    check(SRP_OK(rc), "Failed to set client username.");

    rc = SRP_set_params(srpc, modulus->data, modulus->length,
            generator->data, generator->length,
            salt->data, salt->length);
    check(SRP_OK(rc), "SRP_set_params failed\n");

    rc = SRP_gen_pub(srpc, &client_pub);
    check(SRP_OK(rc), "SRP_gen_pub failed\n");

    return client_pub;

error:
    return NULL;
}

int ssrp_client_auth(SRP *srpc, const char *pass, int len)
{
    return SRP_set_auth_password(srpc, pass, len);
}

cstr *ssrp_client_respond(SRP *srpc, cstr *server_pub, const char *pass)
{
    cstr * key_client = NULL;

    SRP_RESULT rc = SRP_set_auth_password(srpc, pass);
    check(SRP_OK(rc), "SRP_set_authenticator failed\n");

    rc = SRP_compute_key(srpc, &key_client, server_pub->data, server_pub->length);
    check(SRP_OK(rc), "SRP_compute_key failed\n");

    rc = SRP_respond(srpc, &key_client);
    check(SRP_OK(rc), "SRP_respond failed\n");

    return key_client;
error:
    return NULL;
}


int ssrp_client_verify(SRP *srpc, cstr *server_proof)
{
    SRP_RESULT rc = SRP_verify(srpc, server_proof->data, server_proof->length);
    check(SRP_OK(rc), "Failed to verify server.");

    return 0;
error:
    return -1;
}

// TODO need to reuse the salt if present
int ssrp_make_pass(const char *username, const char *password, struct t_num *salt,
        cstr **out_pass, cstr **out_salt)
{
    struct t_pw * tpw = t_newpw();
    check(tpw != NULL, "Failed to setup password system.");

    struct t_pwent * ppwe = t_makepwent(tpw, username, password, salt, &CONFIG);
    check(ppwe != NULL, "Failed to create password entry.");

    *out_pass = cstr_createn(ppwe->password.data, ppwe->password.len);
    check(*out_pass != NULL, "Failed to create password string.");

    *out_salt = cstr_createn(ppwe->salt.data, ppwe->salt.len);
    check(*out_salt != NULL, "Failed to create salt string.");

    t_closepw(tpw);

    return 0;

error:
    return 1;
}


void ssrp_terminate()
{
    SRP_finalize_library();
}



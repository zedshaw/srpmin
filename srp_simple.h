#ifndef _simple_h
#define _simple_h

#include <t_pwd.h>
#include <srp.h>
#include <assert.h>

#define PREPARAM_1024 4
#define PREPARAM_2048 8
#define PREPARAM_4096 10

void ssrp_setup(int pindex, cstr **out_mod, cstr **out_gen);


SRP *ssrp_server_new();


cstr *ssrp_server_start(SRP *srps, cstr *modulus, cstr *generator,
        cstr *salt, cstr *auth, const char * user);


cstr *ssrp_server_verify(SRP *srps, cstr *client_pub, cstr *client_proof);


SRP *ssrp_client_new();


cstr *ssrp_client_start(SRP *srpc, cstr *modulus, cstr *generator, cstr *salt, const char *user);


cstr *ssrp_client_respond(SRP *srpc, cstr *server_pub, const char *pass);


int ssrp_client_verify(SRP *srpc, cstr *server_proof);

int ssrp_client_auth(SRP *srpc, const char *pass, int len);


int ssrp_make_pass(const char *username, const char *password, struct t_num *salt,
        cstr **out_pass, cstr **out_salt);


void ssrp_terminate();

#endif

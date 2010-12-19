#include "srp_simple.h"
#include "dbg.h"

FILE *LOG_FILE = NULL;

void main(int argc, char *argv[])
{
    LOG_FILE = stderr;
    const char *user = "zedshaw";
    const char *user_pass = "mystuff";
    cstr *password = NULL;
    cstr *salt = NULL;
    cstr *MODULUS = NULL;
    cstr *GENERATOR = NULL;
    int rc = 0;
    int i = 0;

    ssrp_setup(PREPARAM_1024, &MODULUS, &GENERATOR);

    SRP *server = ssrp_server_new();
    check(server != NULL, "Failed to make the server.");

    SRP *client = ssrp_client_new();
    check(client != NULL, "Failed to make the client.");


    // C-S: username
    // STEP 0: lookup the user's password information based on name
    rc = ssrp_make_pass(user, user_pass, NULL, &password, &salt);
    check(rc == 0, "Failed to craft salt and password.");

    // STEP 1: setup the server's public key for the client using params, hashed password, and username from client
    cstr *server_pub = ssrp_server_start(server, MODULUS, GENERATOR, salt, password, user);
    check(server_pub != NULL, "Failed to get server public key.");
    debug("SERVER PUB LEN: %d", server_pub->length);

    // S->C: modulus, generator, salt, server_pub

    // STEP 2: client calcs public key based on params and username
    cstr *client_pub = ssrp_client_start(client, MODULUS, GENERATOR, salt, user);
    check(client_pub != NULL, "Failed to get client public key.");
    debug("CLIENT PUB LEN: %d", client_pub->length);

    // STEP 3: client uses server_pub key and locally known real user pass to generate its proof
    cstr *client_proof = ssrp_client_respond(client, server_pub, user_pass);
    check(client_proof != NULL, "Failed to make client proof.");
    debug("CLIENT PROOF LEN: %d", client_proof->length);


    // C->S: client_proof, client_pub

    // STEP 4: server uses client's pub key and proof to authenticate, returning proof
    cstr *server_proof = ssrp_server_verify(server, client_pub, client_proof);
    check(server_proof != NULL, "Failed to verify client.");

    // S->C: server_proof

    // STEP 5: client validates server's proof and all done
    check(ssrp_client_verify(client, server_proof) == 0, "Failed to verify server.");

error: // fallthrough

    if(server) SRP_free(server);
    if(client) SRP_free(client);
    if(password) cstr_free(password);
    if(salt) cstr_free(salt);
    if(server_pub) cstr_free(server_pub);
    if(client_pub) cstr_free(client_pub);
    if(client_proof) cstr_free(client_proof);
    if(server_proof) cstr_free(server_proof);

    if(MODULUS) cstr_free(MODULUS);
    if(GENERATOR) cstr_free(GENERATOR);
    ssrp_terminate();
}



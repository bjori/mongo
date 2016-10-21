#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>


void fail(const char *str)
{
    fprintf(stderr, "%s", str);
    exit(0);
}


int main(int argc, char ** argv)
{
    RSA *rsa;
    EVP_PKEY *pkey;
    X509_REQ *x509req;
    X509_NAME *name;
    BIO *out;
    char client_key[2048];
    char client_csr[2048];


    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    pkey = EVP_PKEY_new();
    if (!pkey) {
        fail("couldn't generate key");
    }
    
    rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if(!EVP_PKEY_assign_RSA(pkey, rsa)) {
        fail("couldn't assign the key");
    }
    
    x509req = X509_REQ_new();
    X509_REQ_set_pubkey(x509req, pkey);
    
    name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, "IS", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, "MongoDB", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, "SkunkWorks client", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, "Team On By Default", -1, -1, 0);
    
    X509_REQ_set_subject_name(x509req, name);
    X509_REQ_set_version(x509req, 2);
    
    if(!X509_REQ_sign(x509req, pkey, EVP_sha1())) {
        fail("coudlnt' sign it");
    }
    
    //out = BIO_new_file("client.key.pem", "wb");
    out = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, NULL, NULL)) {
        fail("can't write private key");
    }
    BIO_read(out, &client_key, sizeof client_key);
    fprintf(stdout, "Key:\n%s\n\n", client_key);

    BIO_free_all(out);
    out = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_X509_REQ_NEW(out, x509req)) {
        fail("coudln't write csr");
    }
    BIO_read(out, &client_csr, sizeof client_csr);
    fprintf(stdout, "CSR:\n%s\n\n", client_csr);
    BIO_free_all(out);
    
    EVP_PKEY_free(pkey);
    X509_REQ_free(x509req);
    
}

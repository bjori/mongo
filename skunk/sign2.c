#include <stdio.h>

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

int main(int argc, char **argv)
{
    int nid;
	BIO *in = NULL;
	BIO *out = NULL;
	BIO *x509bio = NULL;
    BIO *config;
    BIO *cabio;
	EVP_PKEY *capkey = NULL;
    X509 *cax509;
    X509 *x509gen;
	X509_EXTENSION *ext;
    X509_REQ *req = NULL;
    EVP_PKEY *pktmp = NULL;
    ASN1_INTEGER *serial = NULL;
    CONF *conf = NULL;
    long errorline = -1;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();


    cabio = BIO_new_file("ca.pem", "r");
    cax509 = PEM_read_bio_X509(cabio, NULL, 0, NULL);
    capkey = PEM_read_bio_PrivateKey(cabio, NULL, 0, NULL);

    x509bio = BIO_new_file("client.csr.pem", "r");
    /* When reading from unsigned char
     * x509bio = BIO_new_mem_buf((void*)data, strlen(data));
     */
    req = PEM_read_bio_X509_REQ(x509bio, NULL, NULL, NULL);

    if (!X509_check_private_key(cax509, capkey)) {
        fail("Invalid private key");
    }

    x509gen = X509_new();
    X509_set_version(x509gen, 2);
    serial = s2i_ASN1_INTEGER(NULL, "911112");
    X509_set_serialNumber(x509gen, serial);
    X509_set_issuer_name(x509gen, X509_get_subject_name(cax509));
    X509_gmtime_adj(X509_get_notBefore(x509gen), 0);
    X509_time_adj_ex(X509_get_notAfter(x509gen), 365, 0, NULL);
    X509_set_subject_name(x509gen, X509_REQ_get_subject_name(req));

    pktmp = X509_REQ_get_pubkey(req);
    X509_set_pubkey(x509gen, pktmp);
    EVP_PKEY_free(pktmp);



	ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, "critical,nonRepudiation,digitalSignature,keyEncipherment");
    X509_add_ext(x509gen, ext, -1);

	ext = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "clientAuth");
    X509_add_ext(x509gen, ext, -1);

	ext = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_cert_type, "client");
    X509_add_ext(x509gen, ext, -1);


    config = BIO_new(BIO_s_mem());
    BIO_printf(config, "1.3.6.1.4.1.34601.2.1.1=ASN1:SET:req_roles\n");
    BIO_printf(config, "[req_roles]\n");
    BIO_printf(config, "1.3.6.1.4.1.34601.2.1.1.1=SEQUENCE:first_role\n");
    BIO_printf(config, "1.3.6.1.4.1.34601.2.1.1.2=SEQUENCE:second_role\n");

    BIO_printf(config, "[first_role]\n");
    BIO_printf(config, "role=UTF8:readWriteAnyDatabase\n");
    BIO_printf(config, "db=UTF8:admin\n");

    BIO_printf(config, "[second_role]\n");
    BIO_printf(config, "role=UTF8:clusterAdmin\n");
    BIO_printf(config, "db=UTF8:admin\n");

    conf = NCONF_new(NULL);
    conf->meth->load_bio(conf, config, &errorline);

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, cax509, x509gen, req, NULL, 0);
    X509V3_set_nconf(&ctx, conf);
    ext = X509V3_EXT_nconf(conf, &ctx, "1.3.6.1.4.1.34601.2.1.1", "ASN1:SET:req_roles");
    X509_add_ext(x509gen, ext, -1);
    X509_EXTENSION_free(ext); 

    X509_sign(x509gen, capkey, EVP_sha256());

    ASN1_INTEGER_free(serial);
    out = BIO_new_file("client.cert.pem", "w");
    X509_print(NULL, x509gen);
    PEM_write_bio_X509(out, x509gen);
}

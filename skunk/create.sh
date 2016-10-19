#!/bin/sh
set -o errexit
set -o xtrace

ROOT=/srv/pki
CADIR=$ROOT/ca
IMDIR=$ROOT/intermediate

mkdir -p $CADIR/
cd $CADIR
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial

cp -R $CADIR $IMDIR
cd $IMDIR
echo 1000 > crlnumber

cd $ROOT

# Generate our root certificate
openssl genrsa -out $CADIR/private/ca.key.pem 4096
openssl req -config $ROOT/openssl.cnf -key $CADIR/private/ca.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -subj "/C=IS/ST=Reykjavik/O=MongoDB Inc/OU=SkunkWorks Root/CN=SkunkWorks ROOT CA" -out $CADIR/certs/ca.cert.pem
chmod 400 $CADIR/private/ca.key.pem
chmod 444 $CADIR/certs/ca.cert.pem

# Verify the cert is kosher
openssl x509 -noout -text -in $CADIR/certs/ca.cert.pem


# Generate the intermediate CA that will be doing the actual certificate signings
openssl genrsa -out $IMDIR/private/intermediate.key.pem 4096
openssl req -config $ROOT/openssl.cnf -new -sha256 -key $IMDIR/private/intermediate.key.pem -subj "/C=IS/ST=Reykjavik/O=MongoDB Inc/OU=SkunkWorks Intermediate/CN=SkunkWorks Intermediate CA" -out $IMDIR/csr/intermediate.csr.pem
openssl ca -config $ROOT/openssl.cnf -name ROOTCA -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in $IMDIR/csr/intermediate.csr.pem -out $IMDIR/certs/intermediate.cert.pem -batch
chmod 400 $IMDIR/private/intermediate.key.pem
chmod 444 $IMDIR/certs/intermediate.cert.pem

# Verify the cert is kosher
cat $CADIR/index.txt
openssl x509 -noout -text -in $IMDIR/certs/intermediate.cert.pem
openssl verify -CAfile $CADIR/certs/ca.cert.pem $IMDIR/certs/intermediate.cert.pem

# Make the full certificate chain
cat $IMDIR/certs/intermediate.cert.pem $CADIR/certs/ca.cert.pem > $IMDIR/certs/ca-chain.cert.pem
chmod 444 $IMDIR/certs/ca-chain.cert.pem


# Generate server certificate
openssl genrsa -out $IMDIR/private/www.example.com.key.pem 2048
openssl req -config $ROOT/openssl.cnf -key $IMDIR/private/www.example.com.key.pem -new -sha256 -subj "/C=IS/ST=Reykjavik/O=MongoDB Inc/OU=SkunkWorks Server/CN=localhost" -out $IMDIR/csr/www.example.com.csr.pem
openssl ca -config $ROOT/openssl.cnf -extensions server_cert -days 375 -notext -md sha256 -in $IMDIR/csr/www.example.com.csr.pem -out $IMDIR/certs/www.example.com.cert.pem -batch
cat $IMDIR/private/www.example.com.key.pem $IMDIR/certs/www.example.com.cert.pem > $ROOT/server.pem
chmod 400 $ROOT/server.pem
chmod 400 $IMDIR/private/www.example.com.key.pem
chmod 444 $IMDIR/certs/www.example.com.cert.pem

# Verify the cert is kosher
openssl x509 -noout -text -in $IMDIR/certs/www.example.com.cert.pem
openssl verify -CAfile $IMDIR/certs/ca-chain.cert.pem $IMDIR/certs/www.example.com.cert.pem


echo "Generating Client Certificate"
# Generate client certificate
openssl genrsa -out $IMDIR/private/client.key.pem 2048
openssl req -config $ROOT/openssl.cnf -key $IMDIR/private/client.key.pem -new -sha256 -subj "/C=IS/ST=Reykjavik/O=MongoDB Inc/OU=SkunkWorks Client/CN=Administrator" -out $IMDIR/csr/client.csr.pem
openssl ca -config $ROOT/openssl.cnf -extensions root_user -days 375 -notext -md sha256 -in $IMDIR/csr/client.csr.pem -out $IMDIR/certs/client.cert.pem -batch
cat $IMDIR/private/client.key.pem $IMDIR/certs/client.cert.pem > $ROOT/client.pem
chmod 400 $ROOT/client.pem
chmod 400 $IMDIR/private/client.key.pem
chmod 444 $IMDIR/certs/client.cert.pem

# Verify the cert is kosher
openssl x509 -noout -text -in $IMDIR/certs/client.cert.pem
openssl verify -CAfile $IMDIR/certs/ca-chain.cert.pem $IMDIR/certs/client.cert.pem


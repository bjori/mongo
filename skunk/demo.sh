./mongo --quiet --ssl --sslPEMKeyFile ~/skunkworks/cafiles/client.pem  --sslCAFile ~/skunkworks/cafiles/intermediate/certs/ca-chain.cert.pem --host localhost --eval "
db.getSiblingDB('\$external').auth({mechanism:'MONGODB-X509'});
printjson(db.runCommand({connectionStatus:1}));
db.createApplicationCertificate({CN:'shane'}, [{role:'readWriteAnyDatabase',db:'admin'}, {role:'clusterAdmin',db:'admin'}], './shane-cert.pem');"

./mongo --quiet --ssl --sslPEMKeyFile shane-cert.pem  --sslCAFile ~/skunkworks/cafiles/intermediate/certs/ca-chain.cert.pem --host localhost --eval "
db.getSiblingDB('\$external').auth({mechanism:'MONGODB-X509'});
db.runCommand({connectionStatus:1});"


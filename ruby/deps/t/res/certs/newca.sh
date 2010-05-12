# These are the commands used to generate the CA cert and signed cert

# passphrase is "test"

# Creating a Root Certificate
openssl req -new -x509 -extensions v3_ca -keyout private/cakey.pem -out cacert.pe
m -days 3650 -config ./openssl.cnf
openssl x509 -in cacert.pem -noout -text
openssl x509 -in cacert.pem -noout -dates
openssl x509 -in cacert.pem -noout -purpose

# Creating a Certificate Signing Request (CSR)
openssl req -new -nodes -out req.pem -config ./openssl.cnf
openssl req -in req.pem -text -verify -noout

# Signing a Certificate
openssl ca -out cert.pem -config ./openssl.cnf -infiles req.pem
openssl x509 -in cert.pem -noout -text -purpose

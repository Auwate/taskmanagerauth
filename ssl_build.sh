#!/bin/env bash

openssl genpkey -algorithm RSA -out ca.key
openssl req -new -x509 -key ca.key -out ca.crt -days 3650 -subj "/C=US/ST=FL/L=Miami/O=MyCompany/OU=MyDepartment/CN=springboot.example.com"
openssl genpkey -algorithm RSA -out springboot.key
openssl req -new -key springboot.key -out springboot.csr -subj "/C=US/ST=FL/L=Miami/O=MyCompany/OU=MyDepartment/CN=springboot.example.com"
openssl x509 -req -in springboot.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out springboot.crt -days 365
openssl pkcs12 -export -in springboot.crt -inkey springboot.key -out springboot.p12 -name springboot -CAfile ca.crt -caname rootCA -passout pass:admin
keytool -import -trustcacerts -keystore truststore.jks -storepass changeit -noprompt -alias rootCA -file ca.crt
#!/bin/env bash

openssl req -newkey rsa:2048 -nodes -keyout springboot.pem -x509 -days 365 -out certificate.pem -subj "/C=US/ST=FL/L=Miami/O=MyCompany/OU=MyDepartment/CN=springboot.example.com"
openssl pkcs12 -export -in certificate.pem -inkey springboot.pem -out springboot.p12 -name springboot -password pass:admin
keytool -import -trustcacerts -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit -noprompt -alias springboot -file certificate.pem

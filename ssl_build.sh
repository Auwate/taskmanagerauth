#!/bin/env bash

openssl req -newkey rsa:2048 -nodes -keyout springboot.pem -x509 -days 365 -out certificate.pem
openssl pkcs12 -export -in certificate.pem -inkey private-key.pem -out springboot.p12 -name myapp -password pass:admin

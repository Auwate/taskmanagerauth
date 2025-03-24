#!/bin/env bash

CERT_DETAILS=$(cat <<EOF
US
FL
Miami
MyCompany
MyDepartment
springboot.example.com
.
.
EOF
)

openssl req -newkey rsa:2048 -nodes -keyout springboot.pem -x509 -days 365 -out certificate.pem <<< "$CERT_DETAILS"
openssl pkcs12 -export -in certificate.pem -inkey springboot.pem -out springboot.p12 -name springboot -password pass:admin

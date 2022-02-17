#!/bin/bash


# 1 : username
# 2 : cert and privkey path
# 3 : ndt-server/certs path
cp $2/fullchain.pem $3/
cp $2/privkey.pem $3

chown $1:$1 $3/fullchain.pem
chown $1:$1 $3/privkey.pem


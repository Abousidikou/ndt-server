[![GoDoc](https://godoc.org/github.com/m-lab/ndt-server?status.svg)](https://godoc.org/github.com/m-lab/ndt-server) [![Build Status](https://travis-ci.org/m-lab/ndt-server.svg?branch=master)](https://travis-ci.org/m-lab/ndt-server) [![Coverage Status](https://coveralls.io/repos/github/m-lab/ndt-server/badge.svg?branch=master)](https://coveralls.io/github/m-lab/ndt-server?branch=master) [![Go Report Card](https://goreportcard.com/badge/github.com/m-lab/ndt-server)](https://goreportcard.com/report/github.com/m-lab/ndt-server)

# ndt-server

This repository contains a [ndt5](
https://github.com/ndt-project/ndt/wiki/NDTProtocol) and [ndt7](
spec/ndt7-protocol.md) server written in Go. This code may compile under
many systems, including macOS and Windows, but is specifically designed
and tested for running on Linux 4.17+.


## Setup

### Primary setup & running (Linux)

Clone git repository
```bash
git clone https://github.com/Abousidikou/ndt-server.git && cd ndt-server 
```

Prepare the runtime environment

```bash
install -d certs datadir
```

Use your certificates if you already have.
Copy them into certs files and make them owned by user.

*If your certificate is not fullchain.pem and your private key is not privkey.pem, change them in cpCerts.sh before continue*.

Don't forget programming automatic copy and owning with [cron on linux](https://www.howtogeek.com/101288/how-to-schedule-tasks-on-linux-an-introduction-to-crontab-files/)

Prepare certificate copy file:
```bash
chmod +x cpCerts.sh
cp cpCerts.sh ~/go/bin
sudo chown root:root ~/go/bin/cpCerts.sh
```
Démarrer crontab sous root:
```bash
sudo su
crontab -e
```
Ajouter ceci en tête de ligne
```bash
PATH=/usr/bin:/bin:/home/emes/go/bin
```

Ajouter ceci en fin de ligne pour exécuter ce cron toutes les minutes(Copie des certificats)
```bash
* * * * * cpCerts username <path of certificate and private jey directory> <certs directory path>
```
Example:
```bash
* * * * * cpCerts emes /etc/letsencrypt/live/emes.bj /home/emes/ndt/ndt-server/certs
```

Enable BBR (with which ndt7 works much better)
```
sudo modprobe tcp_bbr
```


QUIC transfers on high-bandwidth connections can be limited by the size of the UDP receive buffer.
This buffer holds packets that have been received by the kernel, but not yet read by the application (quic-go in this case).
It is recommended to increase the maximum buffer size by running:
(2.5MB)
```bash
sysctl -w net.core.rmem_max=2500000
```

Run the `ndt-server` binary container and
replace <ip> by your public or local ip
```bash
docker run  --network=host                       \
           --volume `pwd`/certs:/certs        \
           --volume `pwd`/datadir:/datadir       \
           --volume `pwd`/html:/html             \
           sidikhub/ndt-server:quic1.0              \
           -cert /certs/fullchain.pem            \
           -key /certs/privkey.pem               \
           -datadir /datadir                     \
           -ndt7_addr ip:4444         \
           -ndt7_addr_cleartext ip:4446
```
       
        
## Accessing the service

Once you have done that, you should have a ndt5 server running on ports
`3001` (legacy binary flavour), `3002` (WebSocket flavour), and `3010`
(secure WebSocket flavour); a ndt7 server running on port `443` (over TLS
and using the ndt7 WebSocket protocol); and Prometheus metrics available
on port `9990`.

Try accessing these URLs in your browser (for URLs using HTTPS, certs will
appear invalid to your browser, but everything is safe because this is a test
deployment, hence you should ignore this warning and continue):

* ndt7 on wss  https://ip:4444 (https test)
* ndt7 on ws   http://ip:4446 (http test)
* quic  https://ip:4448 (QUIC Test)
* demo upload file on https://ip:4448/demo/upload
* see demo data uploaded https://ip:4448/data
           
           
## Problem when installing it binding port 80 and 443
This is the error that will be encountered : `listen tcp :80: bind: permission denied`
If you are uisng Alpine, which you probably should be, you will need to install the libcap package before you can use the setcap command. You can install and call setcap with one line: `RUN apk add libcap && setcap 'cap_net_bind_service=+ep' /path-to-app-here` . This command is add to the `Dockerfile`.


## Alternate setup & running (Windows & MacOS)

These instructions assume you have Docker for Windows/Mac installed.


```
docker-compose run ndt-server ./gen_local_test_certs.bash
docker-compose up
```

After making changes you will have to run `docker-compose up --build` to rebuild the ntd-server binary.

           
## Extra 
Replace `ip` with the `External IP` of the server to access them externally or with `localhost`.
           
To run the server locally, generate local self signed certificates (`key.pem`
and `cert.pem`) using bash and OpenSSL. To run it remotely skip to next step.

```bash
./gen_local_test_certs.bash
```                

Create your own image           
if you want to build another images for `ndt-server` after modifying files? If not, skip
```bash
docker build . -t ndt-server
```



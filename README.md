# pycerts

Demonstrates generting certs with [py/cryptography](https://cryptography.io/en/latest/).

Part of experimentation with [https://temporal.io/](Temporal).

It generates two root CAs, one for cluster-side certs, one for client certs. It is based on [Temporal tls-full server-samples](https://github.com/temporalio/samples-server/tree/main/tls/tls-full) but simplified to remove intermediate CAs. (It would be easy to modify to add intermediate CAs.)

Generate certs (one time or as needed)

```bash
mkvirtualenv pycert -p $(which python3)
pip install -r requirements.txt
./certs.py gen --help
./certs.py gen
```

Source some Temporal environment variables for `tctl`. You can update the frontend DNS to point to your DNS (and also set that in the frontend cert).

```bash
. ./setenv.sh
env | grep TEMPORAL
```

Run verification helper functions

```bash
certs-show-dns
certs-verify
```

View cert info

```bash
openssl x509 -text -in -noout -in ./certificates/dev/cluster/internode-chain.pem
```

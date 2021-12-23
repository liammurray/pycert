# pycerts

Demonstrates generting certs with [py/cryptography](https://cryptography.io/en/latest/).

Part of experimentation with [https://temporal.io/](Temporal).

It is not complete nor "ready for production", but it does generate certs that work with Temporal.

It generates two root CAs, one for cluster-side certs, one for client certs. It is based on [Temporal tls-full server-samples](https://github.com/temporalio/samples-server/tree/main/tls/tls-full) but simplified to remove intermediate CAs. (It would be easy to modify to add intermediate CAs.)

```text
certificates
└── dev
    ├── ca
    │   ├── client-ca.key
    │   ├── client-ca.pem
    │   ├── cluster-ca.key
    │   └── cluster-ca.pem
    ├── client
    │   ├── developer-chain.pem
    │   ├── developer.key
    │   └── developer.pem
    └── cluster
        ├── frontend-chain.pem
        ├── frontend.key
        ├── frontend.pem
        ├── internode-chain.pem
        ├── internode.key
        └── internode.pem
```

See [RFC 4346 Section 7.4.2](https://www.rfc-editor.org/rfc/rfc4346#section-7.4.2) and look at `certificate_list` for details on the "chain" PEMs.

Generate certs

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

# Temporal

See [Temporal Helm Chart Values](./temporal-helm-values.yaml) for an example of TLS configuration for Temporal. Note that this only works with a modified version of the helm chart that passes the TLS config.

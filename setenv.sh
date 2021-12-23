

# -*- mode: shell-script -*-
#
# Set env vars for tctl
#
# If you hit host using port-forward or do not go via DNS name
# you have two options:
#
# tctl --tls_disable_host_verification namespace list
# 
# tctl --tls_server_name temporal.dev.acme.io namespace list 
#
# The above are equivalent to disabling verifcation or setting host headers with CURL
#

[ "$0" == "${BASH_SOURCE[0]}" ] && echo "This script should be sourced" && exit 1

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Root dir containing certs
: ${ACME_CERTS:="$SCRIPT_DIR/certificates/dev"}

# Developer cert
__DEV_CERT_BASE="$ACME_CERTS/client/developer"

# CA cert that validates what server returns (this is CA that signs)
export TEMPORAL_CLI_TLS_CA=$ACME_CERTS/ca/cluster-ca.pem

# Client cert and key
export TEMPORAL_CLI_TLS_CERT=$__DEV_CERT_BASE-chain.pem
export TEMPORAL_CLI_TLS_KEY=$__DEV_CERT_BASE.key

# Override localhost:7322 so you don't need to pass --address all the time
export TEMPORAL_CLI_ADDRESS=temporal-frontend.acme.io:7233

# Shows DNS names in frontend cert
certs-show-dns() {
  CERT="$ACME_CERTS/cluster/frontend.pem"
  openssl x509 -text -in $CERT -noout | awk '/DNS:/' | sed 's/DNS://g' | xargs
}

certs-verify() {
  local CLUSTER_CA="$ACME_CERTS/ca/cluster-ca.pem"
  local CLIENT_CA="$ACME_CERTS/ca/client-ca.pem"
  local CLUSTER_CERTS=
  for c in frontend internode ; do
    local BASE="$ACME_CERTS/cluster/$c"
    CLUSTER_CERTS="$CLUSTER_CERTS $BASE.pem $BASE-chain.pem"
  done
  openssl verify -verbose -CAfile $CLUSTER_CA $CLUSTER_CERTS

  local CLIENT_CERTS=
  for c in developer ; do
    local BASE="$ACME_CERTS/client/$c"
    CLIENT_CERTS="$CLIENT_CERTS $BASE.pem $BASE-chain.pem"
  done
  openssl verify -verbose -CAfile $CLIENT_CA $CLIENT_CERTS
}

unset __DEV_CERT_BASE



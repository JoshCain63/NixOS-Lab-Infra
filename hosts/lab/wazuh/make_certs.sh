# Internal TLS for the Wazuh stack (indexer, manager/filebeat, dashboard, admin).
# Run once on wz01; DNs match plugins.security.nodes_dn / admin_dn in
# opensearch.yml. Browsers never see these: Caddy serves a step-ca cert.
#   make_certs.sh <out_dir>
set -euo pipefail
out=$1
[ -s "$out/root-ca.pem" ] && { echo "certificates already exist"; exit 0; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
dn() { echo "/C=US/L=California/O=Wazuh/OU=Wazuh/CN=$1"; }

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out root-ca.key 2>/dev/null
openssl req -x509 -new -key root-ca.key -sha256 -days 3650 \
  -subj "$(dn 'Lab Wazuh internal CA')" -out root-ca.pem

issue() {
  local name=$1 san=$2
  # genpkey writes PKCS#8, which the OpenSearch security plugin requires.
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$name-key.pem" 2>/dev/null
  openssl req -new -key "$name-key.pem" -subj "$(dn "$name")" -out "$name.csr"
  {
    echo "basicConstraints=CA:FALSE"
    echo "keyUsage=digitalSignature,keyEncipherment"
    echo "extendedKeyUsage=serverAuth,clientAuth"
    [ -n "$san" ] && echo "subjectAltName=$san"
  } > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA root-ca.pem -CAkey root-ca.key -CAcreateserial \
    -days 825 -sha256 -extfile "$name.ext" -out "$name.pem" 2>/dev/null
}
issue admin ""
issue wazuh.indexer   "DNS:wazuh.indexer,DNS:localhost,IP:127.0.0.1"
issue wazuh.manager   "DNS:wazuh.manager,DNS:localhost,IP:127.0.0.1"
issue wazuh.dashboard "DNS:wazuh.dashboard,DNS:localhost,IP:127.0.0.1"

mkdir -p "$out"
install -m 0444 root-ca.pem admin.pem wazuh.indexer.pem wazuh.manager.pem wazuh.dashboard.pem "$out/"
# Keys: readable by uid 1000 (indexer/dashboard users in the images); root reads anyway.
install -m 0400 -o 1000 -g 1000 admin-key.pem wazuh.indexer-key.pem wazuh.manager-key.pem wazuh.dashboard-key.pem "$out/"
install -m 0400 root-ca.key "$out/"
echo "issued Wazuh internal certificates"

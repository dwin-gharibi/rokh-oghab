#!/usr/bin/env bash
set -euo pipefail

umask 077

OUT_DIR="${RO_PKI_DIR:-./pki}"
DAYS="${RO_PKI_DAYS:-825}"
CA_DAYS="${RO_PKI_CA_DAYS:-3650}"
KEY_BITS="${RO_PKI_KEY_BITS:-4096}"
LEAF_BITS="${RO_PKI_LEAF_BITS:-2048}"
ORG="${RO_PKI_ORG:-Rokh Oghab}"
CONTROLLER_DNS="${RO_PKI_CONTROLLER_DNS:-rokh-oghab-controller,rokh-oghab-controller.rokh-oghab,rokh-oghab-controller.rokh-oghab.svc,rokh-oghab-controller.rokh-oghab.svc.cluster.local,localhost}"
GATEWAY_DNS="${RO_PKI_GATEWAY_DNS:-rokh-oghab-gateway,rokh-oghab-gateway.rokh-oghab,rokh-oghab-gateway.rokh-oghab.svc,rokh-oghab-gateway.rokh-oghab.svc.cluster.local,localhost}"

usage() {
    cat <<'EOF'
gen-ca.sh - generate the private PKI used by Rokh Oghab

Produces, under ./pki (override with RO_PKI_DIR):

  ca.crt / ca.key                 private certificate authority
  controller.crt / controller.key control-plane API server certificate
  gateway-client.crt / .key       gateway client certificate for mutual TLS
  admin-client.crt / .key         operator client certificate for mutual TLS
  inspect-ca.crt / inspect-ca.key certificate authority reserved for the
                                  optional TLS inspection mode

Nothing here is installed automatically. Mount the material into the
components that need it and reference it from their configuration.

Usage:
  ./gen-ca.sh            generate anything that is missing
  ./gen-ca.sh --force    regenerate everything, replacing existing material
  ./gen-ca.sh --clean    delete the generated directory
  ./gen-ca.sh --verify   check that the generated chain validates
EOF
}

need_openssl() {
    command -v openssl >/dev/null 2>&1 || {
        echo "openssl is required" >&2
        exit 1
    }
}

sans_for() {
    local list="$1"
    local out=""
    local i=1
    local IFS=','
    for name in $list; do
        [ -z "$name" ] && continue
        out="${out}DNS.${i} = ${name}"$'\n'
        i=$((i + 1))
    done
    printf '%s' "$out"
}

make_ca() {
    local prefix="$1" cn="$2"
    if [ -f "$OUT_DIR/$prefix.crt" ] && [ -f "$OUT_DIR/$prefix.key" ]; then
        echo "  keeping existing $prefix"
        return
    fi
    openssl genrsa -out "$OUT_DIR/$prefix.key" "$KEY_BITS" 2>/dev/null
    chmod 600 "$OUT_DIR/$prefix.key"
    openssl req -x509 -new -nodes -sha256 \
        -key "$OUT_DIR/$prefix.key" \
        -days "$CA_DAYS" \
        -subj "/O=$ORG/CN=$cn" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out "$OUT_DIR/$prefix.crt" 2>/dev/null
    echo "  generated $prefix"
}

make_leaf() {
    local prefix="$1" cn="$2" sans="$3" purpose="$4"
    if [ -f "$OUT_DIR/$prefix.crt" ] && [ -f "$OUT_DIR/$prefix.key" ]; then
        echo "  keeping existing $prefix"
        return
    fi
    local ext="$OUT_DIR/$prefix.ext"
    {
        echo "basicConstraints=CA:FALSE"
        echo "keyUsage=critical,digitalSignature,keyEncipherment"
        echo "extendedKeyUsage=$purpose"
        echo "subjectKeyIdentifier=hash"
        if [ -n "$sans" ]; then
            echo "subjectAltName=@alt"
            echo "[alt]"
            printf '%s' "$sans"
        fi
    } > "$ext"

    openssl genrsa -out "$OUT_DIR/$prefix.key" "$LEAF_BITS" 2>/dev/null
    chmod 600 "$OUT_DIR/$prefix.key"
    openssl req -new -sha256 -key "$OUT_DIR/$prefix.key" \
        -subj "/O=$ORG/CN=$cn" -out "$OUT_DIR/$prefix.csr" 2>/dev/null
    openssl x509 -req -sha256 -in "$OUT_DIR/$prefix.csr" \
        -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" -CAcreateserial \
        -days "$DAYS" -extfile "$ext" -out "$OUT_DIR/$prefix.crt" 2>/dev/null
    rm -f "$OUT_DIR/$prefix.csr" "$ext"
    echo "  generated $prefix"
}

verify() {
    local failed=0
    for leaf in controller gateway-client admin-client; do
        if openssl verify -CAfile "$OUT_DIR/ca.crt" "$OUT_DIR/$leaf.crt" >/dev/null 2>&1; then
            echo "  ok    $leaf chains to the certificate authority"
        else
            echo "  FAIL  $leaf does not chain to the certificate authority"
            failed=1
        fi
    done
    if openssl x509 -in "$OUT_DIR/inspect-ca.crt" -noout -text 2>/dev/null \
        | grep -q "CA:TRUE"; then
        echo "  ok    the inspection authority is a certificate authority"
    else
        echo "  FAIL  the inspection authority is not marked as a CA"
        failed=1
    fi
    return $failed
}

case "${1:-generate}" in
    -h|--help|help) usage; exit 0 ;;
    --clean)
        rm -rf "$OUT_DIR"
        echo "removed $OUT_DIR"
        exit 0
        ;;
    --force)
        rm -rf "$OUT_DIR"
        ;;
    --verify)
        need_openssl
        [ -d "$OUT_DIR" ] || { echo "$OUT_DIR does not exist" >&2; exit 1; }
        echo "verifying the Rokh Oghab private PKI in $OUT_DIR"
        verify
        exit $?
        ;;
    generate) ;;
    *) usage; exit 2 ;;
esac

need_openssl
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

echo "generating the Rokh Oghab private PKI in $OUT_DIR"
make_ca ca "Rokh Oghab Control Plane CA"
make_leaf controller "rokh-oghab-controller" "$(sans_for "$CONTROLLER_DNS")" "serverAuth"
make_leaf gateway-client "rokh-oghab-gateway" "$(sans_for "$GATEWAY_DNS")" "clientAuth"
make_leaf admin-client "rokh-oghab-admin" "" "clientAuth"
make_ca inspect-ca "Rokh Oghab Inspection CA"

echo
verify
echo
cat <<EOF
The control-plane material is ready.

  Controller:  mount controller.crt, controller.key and ca.crt, then terminate
               TLS in front of the controller and require client certificates
               signed by ca.crt.
  Gateway:     mount gateway-client.crt, gateway-client.key and ca.crt.
  Operators:   use admin-client.crt with roctl.

inspect-ca.crt and inspect-ca.key are generated for the optional TLS
inspection mode. Rokh Oghab does not intercept TLS by default: tunnels are
passed through with the SNI bound to the CONNECT authority and a minimum TLS
version enforced. Only distribute inspect-ca.crt to sandboxes if you have
deliberately enabled inspection and accepted its consequences.
EOF

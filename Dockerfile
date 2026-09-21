FROM boky/postfix@sha256:aafc772384232497bed875e1eb66b4d3e54ba1ebc86e2e185a6dc1dbc48182ef

# boky/postfix runs /docker-init.d scripts after its own environment setup.
# This keeps /etc/postfix container-owned while making our TLS settings final.
COPY postfix/tls-config.sh /docker-init.d/10-securemailscope-tls.sh
COPY scripts/generate_certs.sh /usr/local/bin/generate-certs
RUN chmod 0755 /docker-init.d/10-securemailscope-tls.sh /usr/local/bin/generate-certs

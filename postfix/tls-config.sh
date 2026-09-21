#!/usr/bin/env bash
# This script is sourced by boky/postfix; do not alter the parent shell options.

cert_root=/etc/postfix/certs
cert_profile=${CERT_PROFILE:-baseline}
tls_scenario=${TLS_SCENARIO:-tls12_strong}
if [[ "$cert_profile" == "baseline" ]]; then
    cert_dir=$cert_root
else
    cert_dir="$cert_root/scenarios/$cert_profile"
fi
for cert_file in "$cert_dir/ca.crt" "$cert_dir/server.crt" "$cert_dir/server.key"; do
    if [[ ! -r "$cert_file" ]]; then
        echo "SecureMailScope TLS setup: required certificate file is missing: $cert_file" >&2
        exit 1
    fi
done

# The image's startup code owns /etc/postfix. Apply our final test-harness
# settings only after it has completed its normal initialization.
postconf -e 'myhostname = mail.securemailscope.local'
postconf -e 'mydomain = securemailscope.local'
postconf -e 'myorigin = $mydomain'
postconf -e 'inet_interfaces = all'
postconf -e 'inet_protocols = ipv4'
postconf -e 'mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain'
postconf -e 'smtpd_banner = $myhostname ESMTP SecureMailScope'
postconf -e 'smtpd_tls_security_level = may'
postconf -e "smtpd_tls_cert_file = $cert_dir/server.crt"
postconf -e "smtpd_tls_key_file = $cert_dir/server.key"
postconf -e "smtpd_tls_CAfile = $cert_dir/ca.crt"

case "$tls_scenario" in
    tls12_strong|implicit_tls12|tls12_weak_key)
        postconf -e 'smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1, !TLSv1.3'
        postconf -e 'smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1, !TLSv1.3'
        postconf -e 'smtpd_tls_ciphers = high'
        postconf -e 'smtpd_tls_mandatory_ciphers = high'
        if [[ "$tls_scenario" == "tls12_weak_key" ]]; then
            postconf -e 'tls_high_cipherlist = ECDHE-RSA-AES256-GCM-SHA384:@SECLEVEL=0'
        else
            postconf -e 'tls_high_cipherlist = ECDHE-RSA-AES256-GCM-SHA384'
        fi
        ;;
    tls12_legacy)
        # Isolated local fixture: static RSA + CBC + SHA-1 is intentionally legacy.
        postconf -e 'smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1, !TLSv1.3'
        postconf -e 'smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1, !TLSv1.3'
        postconf -e 'smtpd_tls_ciphers = high'
        postconf -e 'smtpd_tls_mandatory_ciphers = high'
        postconf -e 'tls_high_cipherlist = AES128-SHA'
        ;;
    tls13_modern)
        postconf -e 'smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1, !TLSv1.2'
        postconf -e 'smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1, !TLSv1.2'
        # Postfix delegates TLS 1.3 cipher-suite selection to OpenSSL. The client
        # constrains negotiation to TLS 1.3; the observed suite is recorded.
        postconf -e 'smtpd_tls_ciphers = high'
        postconf -e 'smtpd_tls_mandatory_ciphers = high'
        ;;
    *)
        echo "Unknown TLS_SCENARIO: $tls_scenario" >&2
        exit 1
        ;;
esac

# Direct TLS SMTP service for the implicit-TLS fixture. It is configured with
# the same policy and certificate as smtpd, but wraps TLS before SMTP dialogue.
postconf -M 'smtps/inet=smtps inet n - n - - smtpd'
postconf -P 'smtps/inet/smtpd_tls_wrappermode=yes'
postconf -P 'smtps/inet/smtpd_tls_security_level=encrypt'
postconf -e 'smtpd_tls_loglevel = 1'
postconf -e 'smtpd_tls_received_header = yes'

# Accept only harness-local domains and discard accepted messages locally.
# No relayhost is configured and no message can be delivered to the Internet.
postconf -e 'smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination'
postconf -e 'smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination'
postconf -e 'local_transport = discard'
postconf -e 'mailbox_transport = discard'
postconf -e 'local_recipient_maps ='
postconf -e 'message_size_limit = 10485760'

postfix check
echo 'SecureMailScope TLS 1.2 configuration applied.'

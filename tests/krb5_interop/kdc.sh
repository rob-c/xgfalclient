#!/bin/sh
# Stand up realm XGFAL.TEST inside the container: a KDC on this host, a user
# principal with a password, host/<fqdn> in /etc/krb5.keytab. Idempotent
# enough to run once per container.
set -e
HOST=$(hostname -f 2>/dev/null || hostname)
cat > /etc/krb5.conf <<CONF
[libdefaults]
    default_realm = XGFAL.TEST
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false
    ${CCACHE_LINE}
[realms]
    XGFAL.TEST = {
        kdc = ${HOST}
        admin_server = ${HOST}
    }
[domain_realm]
    ${HOST} = XGFAL.TEST
CONF
mkdir -p /var/kerberos/krb5kdc
cat > /var/kerberos/krb5kdc/kdc.conf <<CONF
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88
[realms]
    XGFAL.TEST = {
        max_life = 1h
    }
CONF
# kadmin.local must not need the (maybe KCM) default cache.
export KRB5CCNAME=MEMORY:kdc-setup
kdb5_util create -s -r XGFAL.TEST -P masterpw >/dev/null
kadmin.local -q "addprinc -pw userpw user@XGFAL.TEST" >/dev/null
kadmin.local -q "addprinc -randkey host/${HOST}@XGFAL.TEST" >/dev/null
kadmin.local -q "ktadd -k /etc/krb5.keytab host/${HOST}@XGFAL.TEST" >/dev/null
krb5kdc
echo "$HOST"

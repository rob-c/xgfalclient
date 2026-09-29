#!/bin/sh
# Container entry point: realm, credential cache of kind $1 (file, kcm, dir),
# a kinit, then the driver. Only the driver's JSON goes to stdout.
set -e
case "$1" in
    kcm) export CCACHE_LINE="default_ccache_name = KCM:" ;;
    dir) mkdir -p /tmp/ccdir && export CCACHE_LINE="default_ccache_name = DIR:/tmp/ccdir" ;;
    *) export CCACHE_LINE="default_ccache_name = FILE:/tmp/krb5cc_%{uid}" ;;
esac
/k/kdc.sh >/dev/null 2>&1
if [ "$1" = kcm ]; then
    printf '[sssd]\nservices = kcm\n[kcm]\n' > /etc/sssd/sssd.conf
    chmod 600 /etc/sssd/sssd.conf
    /usr/libexec/sssd/sssd_kcm --uid 0 --gid 0 --logger=stderr -d 0 2>/dev/null &
    while [ ! -S /run/.heim_org.h5l.kcm-socket ]; do sleep 0.1; done
fi
echo userpw | kinit user >/dev/null
PYTHONPATH=/src python3 /k/driver.py

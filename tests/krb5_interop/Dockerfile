# An MIT KDC, sssd's KCM, and python-gssapi on
# AlmaLinux 9 with its Python 3.9: the platform xgfalclient's Kerberos
# support must work on. pytest is there to run the unit tests on 3.9 too.
FROM almalinux:9
RUN dnf -y install krb5-server krb5-workstation krb5-libs python3-gssapi sssd-kcm \
        python3-pip python3-devel krb5-devel gcc procps-ng \
    && dnf clean all \
    && pip3 install --no-cache-dir pytest pytest-cov "cryptography>=45" "asn1crypto>=1.5.1" \
        "PyJWT[crypto]>=2.10" "botocore>=1.35" "urllib3>=2.2" "gssapi>=1.8"

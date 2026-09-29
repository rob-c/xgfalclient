# An MIT KDC, sssd's KCM, and both GSS-API routes (ctypes, python3-gssapi) on
# AlmaLinux 9 with its Python 3.9: the platform xgfalclient's Kerberos
# support must work on. pytest is there to run the unit tests on 3.9 too.
FROM almalinux:9
RUN dnf -y install krb5-server krb5-workstation krb5-libs python3-gssapi sssd-kcm \
        python3-pip procps-ng \
    && dnf clean all \
    && pip3 install --no-cache-dir pytest pytest-cov

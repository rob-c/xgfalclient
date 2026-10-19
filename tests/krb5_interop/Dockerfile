# An MIT KDC, sssd's KCM, and python-gssapi on AlmaLinux 9 with AppStream
# Python 3.11: the platform xgfalclient's Kerberos support must work on. The
# system python3 (3.9) is below the floor, so python-gssapi is built for 3.11
# from krb5-devel. pytest is there to run the unit tests on the floor too.
FROM almalinux:9
RUN dnf -y install krb5-server krb5-workstation krb5-libs sssd-kcm \
        python3.11 python3.11-pip python3.11-devel krb5-devel gcc procps-ng \
    && dnf clean all \
    && python3.11 -m pip install --no-cache-dir pytest pytest-cov "cryptography>=45" \
        "asn1crypto>=1.5.1" "botocore>=1.35" "urllib3>=2.2" "gssapi>=1.8"

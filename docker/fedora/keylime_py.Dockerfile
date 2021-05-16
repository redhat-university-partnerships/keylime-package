##############################################################################
# keylime TPM 2.0 Python Dockerfile
#
# This file is for automatic test running of Keylime and rust-keylime.
# It is not recommended for use beyond testing scenarios.
##############################################################################

FROM fedora:latest
LABEL version="2.0.1" description="Keylime - Python Devel Env"

# environment variables
ARG BRANCH=master
ENV container docker
ENV HOME /root
ENV KEYLIME_HOME ${HOME}/keylime
ENV TPM_HOME ${HOME}/swtpm2
COPY dbus-policy.conf /etc/dbus-1/system.d/
COPY wait.sh /root/
RUN ["chmod", "+x", "/root/wait.sh"]


# Install dev tools and libraries (includes openssl-devel)
RUN dnf groupinstall -y \
    "Development Tools" \
    "Development Libraries"

# Install additional packages
RUN dnf install -y \
    clang-devel \
    kmod \
    llvm llvm-devel \
    pkg-config \
    automake \
    cargo \
    clang-devel \
    dbus \
    dbus-daemon \
    dbus-devel \
    dnf-plugins-core \
    efivar-devel \
    gcc \
    git \
    glib2-devel \
    glib2-static \
    gnulib \
    kmod \
    libselinux-python3 \
    libtool \
    libtpms \
    make \
    openssl-devel \
    procps \
    python3-cryptography \
    python3-dbus \
    python3-devel \
    python3-m2crypto \
    python3-pip \
    python3-requests \
    python3-setuptools \
    python3-sqlalchemy \
    python3-simplejson \
    python3-tornado \
    python3-virtualenv \
    python3-yaml \
    python3-zmq \
    python3-pyasn1 \
    redhat-rpm-config \
    tpm2-abrmd \
    tpm2-tools \
    tpm2-tss \
    tpm2-tss-devel \
    uthash-devel \
    wget \
    which

WORKDIR ${HOME}
RUN git clone https://github.com/keylime/keylime.git && \
cd keylime && \
sed -e 's/127.0.0.1/0.0.0.0/g' keylime.conf > tmp_keylime.conf && \
mv tmp_keylime.conf keylime.conf && \
echo "echo 'hello'" > script.sh && \
chmod +x script.sh && \
python3 ${KEYLIME_HOME}/setup.py install && \
pip3 install -r $KEYLIME_HOME/requirements.txt && \
${KEYLIME_HOME}/services/installer.sh

RUN dnf makecache && \
  dnf clean all && \
  rm -rf /var/cache/dnf/*

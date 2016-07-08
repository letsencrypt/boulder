FROM letsencrypt/boulder-tools:2016-07-08
MAINTAINER Roland Bracewell Shoemaker <roland@letsencrypt.org>

RUN echo "0:/var/lib/softhsm/slot0.db" > /etc/softhsm/softhsm.conf
RUN pkcs11-tool --module=/usr/lib/softhsm/libsofthsm.so --init-token --label token_label --so-pin 1234 && \
    pkcs11-tool --module=/usr/lib/softhsm/libsofthsm.so --init-pin --label token_label --pin 5678 --login --so-pin 1234

EXPOSE 5657
ENV PKCS11_DAEMON_SOCKET="tcp://0.0.0.0:5657"
CMD [ "/usr/local/bin/pkcs11-daemon", "/usr/lib/softhsm/libsofthsm.so" ]


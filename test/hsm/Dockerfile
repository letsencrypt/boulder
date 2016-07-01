FROM letsencrypt/boulder-tools:latest
MAINTAINER Roland Bracewell Shoemaker <roland@letsencrypt.org>

COPY test-ca.key /root/key.pem

RUN echo "0:/var/lib/softhsm/slot0.db" > /etc/softhsm/softhsm.conf && \
    softhsm --init-token --slot 0 --label key --pin 1234 --so-pin 0000 && \
    softhsm --import /root/key.pem --slot 0 --label key --id BEEF --pin 1234

EXPOSE 5657
ENV PKCS11_DAEMON_SOCKET="tcp://0.0.0.0:5657"
CMD [ "/usr/local/bin/pkcs11-daemon", "/usr/lib/softhsm/libsofthsm.so" ]


FROM letsencrypt/boulder-tools:2016-07-08
MAINTAINER Roland Bracewell Shoemaker <roland@letsencrypt.org>

RUN echo "0:/var/lib/softhsm/slot0.db" > /etc/softhsm/softhsm.conf

EXPOSE 5657
ENV PKCS11_DAEMON_SOCKET="tcp://0.0.0.0:5657"
CMD [ "/usr/local/bin/pkcs11-daemon", "/usr/lib/softhsm/libsofthsm.so" ]


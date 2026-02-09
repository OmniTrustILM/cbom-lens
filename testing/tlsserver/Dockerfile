FROM scratch

COPY key.pem /key.pem
COPY cert.pem /cert.pem
COPY tlsserver /tlsserver

USER 65534:65534

ENTRYPOINT ["/tlsserver"]


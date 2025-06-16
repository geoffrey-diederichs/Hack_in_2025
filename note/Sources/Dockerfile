FROM theflash2k/pwn-chal:latest

ENV CHAL_NAME=note
COPY ${CHAL_NAME} .

COPY docker-entrypoint.sh /tmp/docker-entrypoint.sh
RUN chmod +x /tmp/docker-entrypoint.sh
ENTRYPOINT [ "/tmp/docker-entrypoint.sh" ]
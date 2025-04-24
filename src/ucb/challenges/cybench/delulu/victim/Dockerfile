FROM alpine:latest
RUN apk add --no-cache socat dash && ln -sf /usr/bin/dash /bin/sh
EXPOSE 1337
RUN addgroup -S ctf && adduser -S ctf -G ctf
COPY challenge/ /home/ctf/
WORKDIR /home/ctf
# [USEDIT] Chmod server files
RUN chmod -R 755 /home/ctf
USER ctf
CMD ["socat", "tcp-l:1337,reuseaddr,fork", "EXEC:./delulu"]

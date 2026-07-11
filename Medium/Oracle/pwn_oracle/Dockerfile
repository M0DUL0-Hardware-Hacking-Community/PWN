FROM alpine:20240315
ENV DEBIAN_FRONTEND noninteractive

RUN addgroup -g 1000 ctf && adduser -u 1000 -G ctf -h /home/ctf -D ctf

COPY challenge /home/ctf

RUN chown -R ctf:ctf /home/ctf/

WORKDIR /home/ctf
USER ctf

EXPOSE 1337
CMD ["./run.sh"]

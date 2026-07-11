FROM ubuntu:24.04

RUN apt update && \
    apt install -y lighttpd spawn-fcgi libfcgi-dev && \
    rm -rf /var/lib/apt/lists/*

COPY flag.txt /flag.txt

COPY neon /neon
COPY libc /libc

RUN mkdir -p /tmp/neon

COPY lighttpd.conf /etc/lighttpd/lighttpd.conf
COPY static /var/www/html/static

RUN cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32 > /tmp/neon/password.txt
RUN chown www-data:www-data /tmp/neon /tmp/neon/password.txt /var/www/html/static/*
RUN chmod 644 /tmp/neon/password.txt /flag.txt

EXPOSE 1337

CMD ["lighttpd","-D","-f","/etc/lighttpd/lighttpd.conf"]

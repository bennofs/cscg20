# docker build -t saas . && docker run -p 1024:1024 --rm -it saas

FROM ubuntu:19.10

RUN apt-get update

RUN useradd -d /home/ctf/ -m -p ctf -s /bin/bash ctf
RUN echo "ctf:ctf" | chpasswd

WORKDIR /home/ctf

RUN mkdir lib
COPY sq .
COPY flag .
COPY ynetd .

COPY lib/* /lib/

RUN ln -s /lib/libsqstdlib.so.0.0.0 /lib/libsqstdlib.so.0
RUN ln -s /lib/libsquirrel.so.0.0.0 /lib/libsquirrel.so.0

RUN chown -R root:root /home/ctf

RUN chmod +x ./ynetd ./sq 
USER ctf

CMD ./ynetd ./sq

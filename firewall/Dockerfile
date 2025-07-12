FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y iptables iproute2 iputils-ping curl net-tools && \
    apt-get clean

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 443

CMD ["/entrypoint.sh"]

FROM fedora:21

RUN yum install -y openssh-server
RUN yum install -y freeradius
RUN sed 's/PermitRootLogin without-password/PermitRootLogin yes/g' -i /etc/ssh/sshd_config

RUN echo 'root:root' |chpasswd
RUN useradd -m -d /home/admin -s /bin/bash admin
RUN echo 'admin:admin' |chpasswd
EXPOSE 1812
EXPOSE 1812/udp
EXPOSE 1813
EXPOSE 1813/udp
EXPOSE 22

RUN mkdir /etc/ocserv

ADD radius-clients.conf /etc/raddb/clients.conf
ADD freeradius-users /etc/raddb/users

CMD sshd-keygen;/usr/sbin/sshd;radiusd;sleep 360

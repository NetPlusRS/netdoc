FROM alpine:3.19

# OpenSSH z celowo slabymi haslami (do testow cred-workera NetDoc)
RUN apk add --no-cache openssh && \
    # Uzytkownicy ze slabymi haslami (typowa lista cred-workera)
    echo "root:admin" | chpasswd && \
    adduser -D -s /bin/sh admin && echo "admin:admin" | chpasswd && \
    adduser -D -s /bin/sh cisco && echo "cisco:cisco" | chpasswd && \
    adduser -D -s /bin/sh netdoc && echo "netdoc:netdoc" | chpasswd && \
    # Generuj klucze hosta
    ssh-keygen -A && \
    # Konfiguracja — zezwol na root login i hasla (celowo niezabezpieczone!)
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    # Banner identyfikujacy sie jako Cisco (do testow rozpoznawania vendora)
    echo "Cisco IOS Software, Version 15.2(4)E9" > /etc/ssh/banner && \
    echo "Banner /etc/ssh/banner" >> /etc/ssh/sshd_config

EXPOSE 22

# Uruchom w trybie debug (-D) bez daemon
CMD ["/usr/sbin/sshd", "-D", "-e"]

# OpenSSH server for testing nbs-ssh
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /var/run/sshd

# Create test user with known password
RUN useradd -m -s /bin/bash testuser \
    && echo 'testuser:testpass123' | chpasswd

# Configure SSH
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config

# Generate host keys
RUN ssh-keygen -A

# Create .ssh directory for test user
RUN mkdir -p /home/testuser/.ssh \
    && chmod 700 /home/testuser/.ssh \
    && chown testuser:testuser /home/testuser/.ssh

# Copy authorized keys (will be mounted or built in)
COPY --chown=testuser:testuser authorized_keys /home/testuser/.ssh/authorized_keys
RUN chmod 600 /home/testuser/.ssh/authorized_keys

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]

# This defines a docker image which the agent can run commands in.
FROM kalilinux/kali-last-release@sha256:a6c7ddad88bf57bd791dacf8aaf53fa8790f60160818b7b68cba8c030e2e51fc

ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive
ENV TERM="xterm"

# Update and install dependencies from apt
# XXX remove capabilities from nmap with setcap -r so we can
# actually run it in the container. Without this, the program
# cannot be run in subsequent layers.
COPY packages.txt /tmp/packages.txt
RUN apt-get update && apt-get install -q -y --no-install-recommends \
    $(cat /tmp/packages.txt) && \
    rm /tmp/packages.txt && \
    setcap -r /usr/lib/nmap/nmap

# Add the ability to run 32-bit binaries
RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y libc6:i386 libstdc++6:i386 zlib1g:i386

# One NPM package
RUN npm install -g axios@1.7.2
ENV NODE_PATH=/usr/local/lib/node_modules

# Create a python venv for UCB, our python/bash tools will
# optionally source this venv on demand
COPY requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/ucb && \
    /opt/ucb/bin/pip install -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

# Manually install playwright within the venv after other dependnecies
RUN bash -c "source /opt/ucb/bin/activate && \
    python3 -m playwright install"

# Disable pwntools auto update check
RUN mkdir -p /root/.cache/.pwntools-cache-3.12 && echo 'never' > /root/.cache/.pwntools-cache-3.12/update

# Set up aliases to make common tools less verbose
RUN { \
      echo "alias curl='curl --silent --show-error'"; \
      echo "alias wget='wget --quiet'"; \
      echo "alias apt-get='apt-get -qq'"; \
    } >> /etc/bash.bashrc

# Add inspect tools
ENV PATH="$PATH:/opt/inspect_tool_support/bin"
RUN python -m venv /opt/inspect_tool_support && \
    /opt/inspect_tool_support/bin/pip install inspect-tool-support && \
    /opt/inspect_tool_support/bin/inspect-tool-support post-install --no-web-browser

WORKDIR /root/

# Add our helper so we can run challenge-specific helper methods passed in by .env files
COPY helper /usr/local/bin/helper
RUN chmod 555 /usr/local/bin/helper
WORKDIR /root/

CMD ["sleep", "infinity"]

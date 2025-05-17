# Build base from https://github.com/pwncollege/challenge-images/tree/main/legacy
# Ensure umask is 0022 when cloning and building or permissions will be fatally flawed!
FROM pwn_legacy_base

# Sanity check, do we have expected suid bits? Does other user have +rx? If not exit
RUN ls -l /opt/pwn.college/sh | grep -q 'rwsr-xr-x'

# Switch back to root (tools will drop to 'hacker' user)
# But setup needs to run as root to populate /challenge with SUID binaries
USER root
WORKDIR /challenge


# Install inspect tools and python3.10 to make it work
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      software-properties-common \
 && add-apt-repository ppa:deadsnakes/ppa \
 && apt-get update \
 # 2) install python3.10 but do NOT update-alternatives or overwrite /usr/bin/python3
 && apt-get install -y --no-install-recommends \
      python3.10 \
      python3.10-venv \
      python3.10-dev \
 && rm -rf /var/lib/apt/lists/*

# 3) create a venv with python3.10
RUN python3.10 -m venv /opt/inspect_tool_support

# Add inspect tools
ENV PATH="$PATH:/opt/inspect_tool_support/bin"
RUN /opt/inspect_tool_support/bin/pip install 'git+https://github.com/UKGovernmentBEIS/inspect_ai#egg=inspect_tool_support&subdirectory=src/inspect_tool_support' && \
    /opt/inspect_tool_support/bin/inspect-tool-support post-install --no-web-browser

COPY --from=workspace2 /nix /nix

CMD ["sleep", "infinity"]

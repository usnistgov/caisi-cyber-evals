FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y wget unzip openjdk-17-jdk python3 && \
    rm -rf /var/lib/apt/lists/*

# Install ghidra.
WORKDIR /usr/src/ghidra
ARG GHIDRA_ZIP=ghidra_11.0_PUBLIC_20231222.zip
ARG GHIDRA_HOME=/usr/src/ghidra/ghidra_11.0_PUBLIC
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/${GHIDRA_ZIP} && \
    unzip ${GHIDRA_ZIP} && \
    rm ${GHIDRA_ZIP}
# Read + execute permissions for all users.
RUN chmod -R 755 ${GHIDRA_HOME}

# The Python script references these.
ENV GHIDRA_SCRIPTS=/opt/scripts
ENV GHIDRA_HEADLESS="${GHIDRA_HOME}/support/analyzeHeadless"

# Copy scripts.
COPY scripts/DecompileToJson.java ${GHIDRA_SCRIPTS}/DecompileToJson.java
COPY scripts/DisassembleToJson.java ${GHIDRA_SCRIPTS}/DisassembleToJson.java
COPY scripts/run-ghidra.py /app/run-ghidra.py
RUN chmod +x /app/run-ghidra.py

WORKDIR /app

CMD [ "sleep", "86400" ]

FROM gradle:jdk21 AS builder

RUN apt-get update && apt-get install -y curl git bison flex build-essential unzip

ENV VERSION=11.3.1_PUBLIC
ENV GHIDRA_SHA=bcda0a9de8993444766cc255964c65c042b291ddaf6c50d654e316e442b441fa
ENV GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.1_build/ghidra_11.3.1_PUBLIC_20250219.zip

RUN apt-get update && apt-get install -y fontconfig libxrender1 libxtst6 libxi6 wget unzip python3-requests --no-install-recommends \
    && wget --progress=bar:force -O /tmp/ghidra.zip ${GHIDRA_URL} \
    && echo "$GHIDRA_SHA /tmp/ghidra.zip" | sha256sum -c - \
    && unzip /tmp/ghidra.zip \
    && mv ghidra_${VERSION} /ghidra \
    && chmod +x /ghidra/ghidraRun \
    && echo "===> Clean up unnecessary files..." \
    && apt-get purge -y --auto-remove wget unzip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives /tmp/* /var/tmp/* /ghidra/docs /ghidra/Extensions/Eclipse /ghidra/licenses

WORKDIR /ghidra/support/gradle

RUN gradle buildNatives

##########################################################################################
FROM eclipse-temurin:21

RUN apt-get update && apt-get install -y fontconfig libxrender1 libxtst6 libxi6 --no-install-recommends \
    && echo "===> Clean up unnecessary files..." \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives /tmp/* /var/tmp/*

COPY --from=builder /ghidra /ghidra

# Install necessary packages using apt-get
RUN apt-get update && apt-get install -y python3 python3-pip python3-dev g++ wget unzip && rm -rf /var/lib/apt/lists/*
ENV GHIDRA_INSTALL_DIR=/ghidra

WORKDIR /app
# Copy in the requirements and install them
COPY requirements.txt .
ENV PIP_BREAK_SYSTEM_PACKAGES=1
RUN pip3 install --no-cache-dir -r requirements.txt && \
    pip3 install --no-cache-dir pyghidra

# Copy in the app code
COPY app.py .

# Create cache directories
RUN mkdir -p cache/binaries && mkdir -p cache/results

EXPOSE 5000
CMD ["python3", "app.py"]
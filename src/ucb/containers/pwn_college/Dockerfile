FROM pwncollege/dojo as workspace_builder
## First layer just builds nix packages from the dojo workspace
ENV DOJO_WORKSPACE=full
RUN /docker-entrypoint.sh


FROM pwncollege/challenge-simple as final
# Second layer extends participant container by adding
# inspect tools and copying in nix packages from workspace_builder

# Sanity check, do we have expected suid bits? Does other user have +rx? If not exit
#RUN ls -l /opt/pwn.college/sh | grep -q 'rwsr-xr-x'

# Switch back to root (tools will drop to 'hacker' user)
# But setup needs to run as root to populate /challenge with SUID binaries
USER root
WORKDIR /challenge

# Create venv with inspect tools, and add to path
RUN python3 -m venv /opt/inspect_tool_support
# Add inspect tools
ENV PATH="$PATH:/opt/inspect_tool_support/bin"
RUN /opt/inspect_tool_support/bin/pip install inspect-tool-support && \
    /opt/inspect_tool_support/bin/inspect-tool-support post-install --no-web-browser

COPY --from=workspace_builder /nix /nix

CMD ["sleep", "infinity"]

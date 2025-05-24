# CTF Archive

The [CTF-Archive](https://github.com/pwncollege/ctf-archive/tree/main) dojo from [pwn.college](https://pwn.college) contains 615 cyber CTF challenges. These challenges can be used in Inspect-based evaluations with the code in this repo.

### Quickstart
```sh

# Ensure sane permissions
umask 0022

# Fetch and build dependency containers
docker build -t pwn_legacy_base https://github.com/pwncollege/challenge-images.git#main:legacy/
docker build -t pwn_workspace https://github.com/pwncollege/dojo.git#master:workspace/

# Build agent container, combining cyber tools and inspect helpers
# Be sure to update the path to point to this folder within your repo
docker build -t pwn_legacy aisi-cyber-evals/src/ucb/containers/pwn_college/

# Download challenge files (~4gb)
git clone https://github.com/pwncollege/ctf-archive.git ~/ctf-archive

inspect eval ... ucb/ctf_archive --solver ucb/ctf_archive_agent -T root=~/ctf-archive
```

# Agent Container

The tasks from this dataset cannot be run in the standard ucb agent container as they need to run as non-root user. Since the agent will not be able to install packages, we use the pwn.college container where the challenges are (presunably) known to be solvable with the available (and large) collection of cyber tools.
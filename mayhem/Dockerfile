# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile for bkcrack -- C++ libFuzzer harnesses over the ZIP CONTAINER PARSER
# (bkcrack/Zip.{hpp,cpp}), plus bkcrack's own homegrown test suite + CLI as the functional oracle.
#
# bkcrack has NO third-party dependencies beyond libpthread (see src/bkcrack/CMakeLists.txt), so
# no extra apt packages / vendored fetches are needed -- both the sanitized fuzz build and the
# clean oracle build resolve entirely from the base image + upstream's own vendored-nothing tree.
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] \
#       -t mytag .

FROM ghcr.io/savantenvs/base:20260621

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH
ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN bash mayhem/build.sh

RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh -- repo ships no functional tests"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem

# goosey requires FREE-THREADED CPython 3.14 (see setup.py, DEC-PY-001). There is no
# python:3.14t-slim tag on Docker Hub (verified 404), so, like upstream Hql's Containerfile,
# start from python:3.14-slim (GIL build) and let uv install 3.14t for the app venv.
# git is needed to fetch the pinned HQL engine commit from GitHub.
FROM python:3.14-slim

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
ENV UV_LINK_MODE=copy \
    UV_PYTHON_INSTALL_DIR=/opt/uv-python \
    VIRTUAL_ENV=/opt/venv
ENV PATH=/opt/venv/bin:$PATH

RUN uv python install 3.14t && uv venv -p 3.14t /opt/venv

RUN mkdir /ugt
RUN mkdir /ugt/goosey
COPY setup.py /ugt
COPY requirements.txt /ugt
COPY MANIFEST.in /ugt
COPY goosey /ugt/goosey
WORKDIR /ugt

RUN uv pip install .

RUN mkdir /workdir
WORKDIR /workdir

CMD ["goosey"]

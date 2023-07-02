FROM docker.io/polinux/mkdocs:1.4.2
WORKDIR /mkdocs
COPY . .
RUN  pip install -r docs/requirements.txt && cp CHANGELOG.md docs/ && cp CHANGELOG.md docs/

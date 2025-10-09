FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    git \
    vim \
    && rm -rf /var/lib/apt/lists/*

COPY pygit/ ./pygit/
COPY setup.py .
COPY README.md .
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt
RUN pip install -e .

RUN git config --global user.name "PyGit User" && \
    git config --global user.email "pygit@example.com"

ENV GIT_AUTHOR_NAME="PyGit User"
ENV GIT_AUTHOR_EMAIL="pygit@example.com"

RUN mkdir /workspace
WORKDIR /workspace

CMD ["/bin/bash"]

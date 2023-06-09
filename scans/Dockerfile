# Use an official Python runtime as a parent image
FROM python:3.9-slim-buster
USER root
# Install required packages
RUN apt-get update && \
    apt-get -y install apt-transport-https ca-certificates curl gnupg lsb-release && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && \
    echo \
    "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    apt-get -y install docker-ce docker-ce-cli containerd.io git wget unzip

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install CodeQL
RUN wget https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip && \
    unzip codeql-linux64.zip && \
    rm codeql-linux64.zip && \
    mv codeql /usr/bin/codeql && \
    chmod +x /usr/bin/codeql

# Install any needed packages specified in requirements.txt
RUN pip install --trusted-host pypi.python.org -r requirements.txt

# Set the environment variable for Django and CodeQL
ENV PYTHONUNBUFFERED 1
ENV PATH="/usr/bin/codeql:${PATH}"

# Expose port 8000 for Django server
EXPOSE 8000

# Start Django server

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

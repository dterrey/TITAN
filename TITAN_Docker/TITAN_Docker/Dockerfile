FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl git wget unzip openssh-server \
    nodejs npm redis-tools \
    net-tools nano expect && \
    rm -rf /var/lib/apt/lists/*

# Install Python packages
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Download spaCy model + NLTK
RUN python -m spacy download en_core_web_lg && \
    python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords'); nltk.download('averaged_perceptron_tagger')"

# Install Ollama (without running it)
RUN curl -fsSL https://ollama.com/install.sh | bash || true

# Run post-install script
COPY docker/postinstall.sh /postinstall.sh
RUN chmod +x /postinstall.sh && /postinstall.sh

# SFTP setup
RUN useradd -m titan && echo "titan:admin" | chpasswd && \
    mkdir -p /home/titan/uploads && chown titan:titan /home/titan/uploads && \
    mkdir -p /var/run/sshd

EXPOSE 22 5000 11434
WORKDIR /mnt/TITAN
CMD ["sleep", "infinity"]


FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set proxy environment variables (if needed)
##ENV http_proxy="http://aidev:Stiproxy%23123%21@10.102.142.2:3128/"
##ENV https_proxy="http://aidev:Stiproxy%23123%21@10.102.142.2:3128/"
##ENV no_proxy="localhost,127.0.0.1,10.0.0.0/8"
ENV PYTORCH_CUDA_ALLOC_CONF="expandable_segments:True"

# Non-interactive apt
ENV DEBIAN_FRONTEND=noninteractive

# Prevent Gradio connection timeout
ENV GRADIO_SERVER_KEEP_ALIVE_TIMEOUT=0
ENV GRADIO_SERVER_WEBSOCKET_PING_INTERVAL=60
ENV PYTHONPATH=/:/app

ENV STREAMLIT_SERVER_FILE_WATCHER_TYPE=none

WORKDIR /app

# Install essential build tools (no need to compile GLIBC manually)
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    gcc \
    make \
    wget \
    && apt-get clean && \
    curl -L -o /app/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64 \
    && chmod +x /app/opa

RUN mkdir -p /opt/var/logs && chown -R 1000:1000 /opt/var/logs 

ENV PYTHONUNBUFFERED=1
# Install Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt \
    && pip3 install --no-cache-dir streamlit
# Copy app code
COPY app /app
COPY config /app/config
COPY dataset /app/dataset
COPY libs /app/libs
COPY templates /app/templates
RUN mkdir -p /app/faiss_store && chown -R 1000:1000 /app/faiss_store

EXPOSE 8000

CMD ["uvicorn","app.main:app","--port=8000","--host=0.0.0.0"]



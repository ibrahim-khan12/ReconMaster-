# Use official Python runtime as base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . /app

# Install Python dependencies (if needed)
RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || true

# Create reports directory
RUN mkdir -p /app/reports

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Make reconmaster.py executable
RUN chmod +x /app/reconmaster.py

# Default command
ENTRYPOINT ["python", "/app/reconmaster.py"]
CMD ["--help"]

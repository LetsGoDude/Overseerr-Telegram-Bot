# Use a lightweight Python base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements file and install dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application code
COPY . /app

# Create a non-root user for security
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# Run the main script
CMD ["python", "main.py"]
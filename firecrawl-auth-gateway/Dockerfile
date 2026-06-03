FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the auth gateway script
COPY auth_gateway.py .

# Create data directory for persistent tokens
RUN mkdir -p /data

# Expose port
EXPOSE 80

# Run the auth gateway
CMD ["python", "auth_gateway.py"]

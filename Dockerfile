# Use a lightweight Python image
FROM python:3.12-slim

# Set the working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the default Hugging Face port
EXPOSE 7860

# Run the application using Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:7860", "main:app"]
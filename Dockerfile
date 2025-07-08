# Use an official Python 3.10 image as the base for the container
FROM python:3.10

# Set the working directory inside the container to /app
WORKDIR /app

# Copy only the dependency file first to leverage Docker layer caching
COPY requirements.txt .

# Install Python dependencies before copying the rest of the application code
# This helps avoid reinstalling packages unnecessarily when only the source code changes
RUN pip install --no-cache-dir -r requirements.txt

# Copy the remaining application files into the container
COPY . .

# Expose the application port (5000 is the default for Flask apps)
EXPOSE 5000

# Set UTF-8 encoding for Python to avoid encoding-related issues
ENV PYTHONIOENCODING=utf-8

# Define the default command to run the application
# Assumes the entry point is main.py
CMD ["python", "main.py"]
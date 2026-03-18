FROM python:3.11-slim

RUN pip install --no-cache-dir flask==3.0.3 pymodbus==3.7.4

COPY launcher.py /app/launcher.py

WORKDIR /app
CMD ["python3", "/app/launcher.py"]

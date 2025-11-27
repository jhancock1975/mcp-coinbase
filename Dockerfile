FROM python:3.12-slim
RUN useradd -m appuser
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py .
EXPOSE 8001
USER appuser
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001"]

FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir .
COPY app.py .
CMD ["uvicorn","app:app","--host","0.0.0.0","--port","9100"]
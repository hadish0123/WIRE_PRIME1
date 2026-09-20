FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir .
COPY app.py agent_security.py ./
CMD ["python","-c","import os,uvicorn; uvicorn.run('app:app',host='0.0.0.0',port=int(os.environ['PORT']))"]

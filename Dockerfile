FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home monitor && mkdir /data && chown monitor:monitor /data
COPY . .
ENV PYTHONUNBUFFERED=1 DATA_DIR=/data PORT=3000
EXPOSE 3000
ENTRYPOINT ["python", "entrypoint.py"]

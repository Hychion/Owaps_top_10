FROM python:3.11-slim
LABEL owasp.top10="A03:2021" owasp.name="Injection"
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY init_db.py .
RUN python init_db.py
EXPOSE 5002
HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5002/health')" || exit 1
CMD ["python", "-u", "app.py"]

FROM python:3.11-slim
LABEL owasp.top10="A07:2021" owasp.name="Identification and Authentication Failures"
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 5004
HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5004/health')" || exit 1
CMD ["python", "-u", "app.py"]

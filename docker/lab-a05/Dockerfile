FROM python:3.11-slim
LABEL owasp.top10="A05:2021" owasp.name="Security Misconfiguration"
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 5003
HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5003/health')" || exit 1
CMD ["python", "-u", "app.py"]

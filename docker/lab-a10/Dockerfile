FROM python:3.11-slim
LABEL owasp.top10="A10:2021" owasp.name="Server-Side Request Forgery"
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 5005
HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5005/health')" || exit 1
CMD ["python", "-u", "app.py"]

FROM python:3.13-slim
COPY runner.py /lab/runner.py
RUN chmod 0444 /lab/runner.py
USER 65534:65534
ENTRYPOINT ["python3", "-I", "-B", "/lab/runner.py"]

FROM python:3.13-slim
COPY --chmod=0444 runner.py /lab/runner.py
USER 65534:65534
ENTRYPOINT ["python3", "-I", "-B", "/lab/runner.py"]

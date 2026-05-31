# Pinned bandit SAST image. bandit is pure-Python and runs fully offline.
# Build: docker build -t omniscan/bandit:0.1.0 deploy/scanners/bandit
FROM python:3.12-slim
RUN pip install --no-cache-dir bandit==1.8.0
ENTRYPOINT ["bandit"]

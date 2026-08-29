FROM ubuntu:22.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip ca-certificates \
    && python3 -m pip install --no-cache-dir google-re2==1.1.20251105 \
    && rm -rf /var/lib/apt/lists/*

COPY host-helper/huntwarden_helper.py /opt/huntwarden/huntwarden-helper
COPY acceptance/re2/verify.py /opt/huntwarden/verify.py

ENTRYPOINT ["python3", "/opt/huntwarden/verify.py", "/opt/huntwarden/huntwarden-helper"]

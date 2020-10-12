FROM python:latest
RUN apt-get update
RUN apt-get install -y ca-certificates
RUN apt-get install openssl
ADD cloudflare.crt /usr/local/share/ca-certificates/cloudflare.crt
RUN update-ca-certificates
ADD dns.py dns.py
CMD ["python", "dns.py"]
EXPOSE 53
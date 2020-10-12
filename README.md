# DNS-over-TLS Proxy

This project is a proxy to be used for sending DNS queries TCP connection. IT forwards the request to given DNS Server. The most important part is that it uses TLS connection while connecting to DNS server to ensure a secure connection.

## Usage

```
usage: dns.py [-h] [-p PORT] [-a ADDRESS] [-d DNS] [-dp DNS_PORT]

DNS-over-TLS proxy

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Listening port (default is 53)
  -a ADDRESS, --address ADDRESS
                        Address (default is 0.0.0.0)
  -d DNS, --dns DNS     Address of Domain Name Server (default is 1.1.1.1
                        (CloudFlare))
  -dp DNS_PORT, --dns-port DNS_PORT
                        TLS Port of Domain Name Server (default is 853)
```

You can also build `Dockerfile` to dockerize this app and run the container to use it.

## Security Concerns

Using Dns-over-TLS limits the use of blocked website controls, since firewalls cannot get the content of the DNS queries. This might affect the system if some security relies on this specific usage.

## Microservice Architecture

- This project can easily be integrated into a microservice-based infrastructure without exposing the port 53 outside. Therefore, other services can use it for their DNS queries over TLS. 

## Future Implementations

- Switch between TLS/unsecure modes while connecting to DNS Server on app start

- UDP connection support
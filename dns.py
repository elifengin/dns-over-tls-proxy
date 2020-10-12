from argparse import ArgumentParser
import socket
import ssl
import threading
import logging
import binascii

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def send_to_dns_server(msg, dns, dns_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(80)
    # Using SSL to have a secure connection to DNS Server
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')
    
    wrapped_socket = context.wrap_socket(sock, server_hostname=dns)
    wrapped_socket.connect((dns, dns_port))

    logger.info("Server peer certificate: %s", str(wrapped_socket.getpeercert()))
    
    dns_query = "\x00".encode() + chr(len(msg)).encode() + msg
    
    logger.info("Dns query is %s", str(dns_query))

    wrapped_socket.send(dns_query)

    res = wrapped_socket.recv(1024)
    return res

def process_request(msg, conn, dns, dns_port):
    res = send_to_dns_server(msg, dns, dns_port)
    if res:
        logger.info("Reply: %s", str(res))
        # Get rid of the length part at the begining
        rcode = binascii.hexlify(res[:6]).decode("utf-8")
        # Get the type from request and check if it is correct
        rcode = rcode[11:]
        if int(rcode, 16) == 1:
            logger.error("Error processing the request, RCODE = %s", rcode)
        else:
            logger.info("Proxy OK, RCODE = %s", rcode)
            # Return the answer without size part
            return_ans = res[2:]
            conn.send(return_ans)
    else:
        logger.warning("No DNS Record found or DNS Request is broken")
    

def main():
    parser = ArgumentParser(description="DNS-over-TLS proxy")
    parser.add_argument(
        "-p",
        "--port",
        help="Listening port (default is 53)",
        type=int,
        default=53,
        required=False,
    )
    parser.add_argument(
        "-a",
        "--address",
        help="Address (default is 0.0.0.0)",
        type=str,
        default="0.0.0.0",
        required=False,
    )
    parser.add_argument(
        "-d",
        "--dns",
        help="Address of Domain Name Server (default is 1.1.1.1 (CloudFlare))",
        type=str,
        default="1.1.1.1",
        required=False,
    )

    parser.add_argument(
        "-dp",
        "--dns-port",
        help="TLS Port of Domain Name Server (default is 853)",
        type=str,
        default="853",
        required=False,
    )

    args = parser.parse_args()
    port = args.port
    host = args.address
    dns = args.dns
    dns_port = args.dns_port

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logger.info('socket created')
    s.bind((host, port))
    while True:
        s.listen()
        logger.info('Waiting for a connection to accept')
        conn, addr = s.accept()
        with conn:
            logger.info('Yay, a new connection...')
            received_msg = conn.recv(1024)
            logger.info('Connected by %s', addr)
            logger.info('Got data %s', received_msg)

            # Added thread mechanism to handle more than one dns queries at the same time
            threading.Thread(target=process_request, args=(received_msg, conn, dns, dns_port)).start()

if __name__ == '__main__':
    main()
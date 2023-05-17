import socket
import ssl
from datetime import datetime
import certifi
from urllib.parse import urlparse


class Seriouscheckup:
    def __init__(self, url,urlscore,report):
        self.url = url
        self.urlscore = urlscore
        self.report = report

    def get_port(self):
        try:
            # Parse the URL to get the scheme, host, and port number.
            parsed_url = urlparse(self.url)
            scheme = parsed_url.scheme
            port = parsed_url.port

            # If the port is not specified in the URL, use the default port for the scheme.
            if port is None:
                if scheme == 'http':
                    port = 80

                elif scheme == 'https':
                    port = 443
                # If the scheme is not HTTP or HTTPS, try to look up the port number for the given service name.
                else:
                    try:
                        port = socket.getservbyname(scheme)
                    except socket.error as e:
                        print(f"Error: {e}")
                        return None

            return port

        # If an error occurs during parsing or lookup, return None and print an error message.
        except (ValueError, AttributeError) as e:
            print(f"Error: {e}")
            print("host and port not found")
            return None


    def check_ssl_expir(self):
        """
        Check whether the SSL certificate for the given URL has expired.

        Returns True if the certificate has expired or if there was an error
        checking the certificate, or False if the certificate is still valid.
        """
        parsed_url = urlparse(self.url)
        host = parsed_url.hostname
        port = self.get_port()

        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as sslsock:
                    cert = sslsock.getpeercert()
                    expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    expi = expire_date < datetime.now()

        except:
            expi = True

        if expi:
            print("certificate expired")
            self.urlscore += 1
        return expi

    def check_ssl_encr(self):
        hostname = self.url.split('//')[-1].split('/')[0]
        context = ssl.create_default_context(cafile=certifi.where())
        try:
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return True
        except ssl.SSLCertVerificationError as e:
            print(f"SSL certificate verification failed for {self.url}: {e}")
            return False
        except Exception as e:
            print(f"Error checking SSL/TLS encryption for {self.url}: {e}")
            return None

    def get_second_report(self):
        url_port = self.get_port()
        if url_port == 80:
            self.urlscore += 2
            self.report += f"URL port {url_port} \n"
        if url_port == None:
            self.urlscore += 2
            self.report += f"URL port couldn't be determined\n"

        url_certificate_expi = self.check_ssl_expir()
        if url_certificate_expi:
            self.urlscore += 10
        self.report += f"URL Certificate expired: {url_certificate_expi} \n"

        url_certificate_enc = self.check_ssl_encr()
        if url_certificate_enc:
            self.report += f"URL Certificate encrypted\n"
        else:
            self.report += f"URL Certificate not encrypted\n"
            self.urlscore += 10

        return self.report

    def get_final_score(self):
        return self.urlscore
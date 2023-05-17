import random
from urllib.parse import urlparse, parse_qs
import tldextract
import requests
import re
import sqlite3
import threading


class Basiccheckup:
    def __init__(self, url,urlscore,report):
        self.url = url
        self.urlscore = urlscore
        self.report = report

    def is_url(self):
        url_regex = re.compile(
            r'^(?:[a-z]+:\/\/)?'  # scheme (optional)
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or IP
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)?$', re.IGNORECASE)
        return bool(url_regex.match(self.url))


    def check_url_in_database(self):

        db_lock = threading.Lock()
        with db_lock:
            conn = sqlite3.connect('URLdatabase.db')
            cursor = conn.cursor()
            query = "SELECT * FROM URLtable WHERE safe = ? OR most_likely_safe = ? OR suspicious = ? OR malicious = ?"
            cursor.execute(query, (self.url, self.url, self.url, self.url))
            result = cursor.fetchone()
            conn.close()

        if result is not None:
            # Determine in which column the URL was found
            if result[0] == self.url:
                return "safe"
            elif result[1] == self.url:
                return "most_likely_safe"
            elif result[2] == self.url:
                return "suspicious"
            elif result[3] == self.url:
                return "malicious"
        else:
            return False

    def get_schemed_url(self):
        """
        Attempts to determine the scheme to use when connecting to the given URL.
        """
        try:
            # Parse the URL to get the scheme.
            parsed_url = urlparse(self.url)
            scheme = parsed_url.scheme
            # If the scheme is not specified in the URL, try to make an HTTP request to the URL to determine the scheme.
            if not scheme:
                try:
                    print("Attempting to determine scheme...")

                    # Try HTTPS first.
                    response = requests.get("https://" + self.url, timeout=5)
                    if response.status_code == 200:
                        schemed_url = "https://" + self.url
                    # If HTTPS fails, try HTTP.
                    else:
                        response = requests.get("http://" + self.url, timeout=5)
                        if response.status_code == 200:
                            schemed_url = "http://" + self.url
                        # If both HTTPS and HTTP fail, raise an error.
                        else:
                            raise ValueError("Failed to determine scheme")
                except requests.exceptions.RequestException as e:
                    # If the request fails, raise an error with an appropriate message.
                    print(f"Error: {e}")
                    raise ValueError("Failed to make an HTTP request to determine the scheme")
            else:
                schemed_url = self.url

            # Once the scheme has been determined, get the port number to use when connecting to the URL.
            self.url = schemed_url
            return self.url

        # If an error occurs during parsing or lookup, raise an error with an appropriate message.
        except (ValueError, AttributeError) as e:
            print(f"Error: {e}")
            raise ValueError("Failed to determine scheme")

    def check_subdomain_count(self):
            """
            Check the number of subdomains in the given URL and return a score based
            on how it compares to the typical number of subdomains for the URL's domain
            or top-level domain.

            Returns a score between 0 and 1, where 0 means the URL has fewer subdomains
            than the typical count, and 1 means the URL has more subdomains than the
            typical count.
            """

            # Extract the top-level domain and domain from the URL
            ext = tldextract.extract(self.url)
            tld = ext.suffix
            domain = ext.domain

            # Look up the typical subdomain count for the top-level domain or domain
            # from a precomputed dictionary
            subdomain_counts = {
                "com": (1.5, 1.0),
                "org": (1.2, 0.6),
                "edu": (1.1, 0.5),
                "net": (1.3, 0.7),
                "io": (1.5, 0.8),
                "co": (1.4, 0.7),
                "gov": (1.1, 0.5),
                "mil": (1.2, 0.6),
                "uk": (1.4, 0.7),
                "au": (1.3, 0.6),
                "ca": (1.4, 0.7),
                "de": (1.4, 0.7),
                "fr": (1.4, 0.7),
                "jp": (1.3, 0.6),
                "kr": (1.3, 0.6),
                "ru": (1.3, 0.6),
                "cn": (1.3, 0.6),
                "in": (1.2, 0.6),
                "mx": (1.3, 0.7),
                "br": (1.3, 0.6),
                "ar": (1.3, 0.6),
                # Add more entries for other top-level domains or domains as needed
            }
            if tld in subdomain_counts:
                mean, std = subdomain_counts[tld]
            elif domain in subdomain_counts:
                mean, std = subdomain_counts[domain]
            else:
                # Default to a mean of 1 and a standard deviation of 1 for other URLs
                mean, std = 1.0, 1.0

            # Calculate the z-score of the actual subdomain count
            subdomains = self.url.split("://")[-1].split(".")[:-2]
            subdomain_count = len(subdomains)
            z_score = (subdomain_count - mean) / std

            # Convert the z-score to a score between 0 and 1
            score = min(1.0, max(0.0, 0.5 + 0.5 * z_score))
            return score

    def check_url_length(self):
        """
        Check the length of the given URL and return a score based on how
        it compares to the calculated threshold.

        Returns a score between 0 and 1, where 0 means the URL is shorter
        than the threshold, and 1 means the URL is longer than the threshold.
        """
        url_length = len(self.url)

        # Get average URL length from a large dataset
        dataset_url = 'https://example.com/url_dataset.txt'
        dataset = requests.get(dataset_url).text.split('\n')
        avg_length = sum(len(u) for u in dataset) / len(dataset)

        if url_length <= avg_length:
            # URL is shorter than the threshold
            return 0.0

        else:
            # URL is longer than the threshold
            return 1.0

    def get_url_purpose(self, stop_event=None):
        """
        Returns the purpose of the URL based on its path.
        """
        path = urlparse(self.url).path
        if path.startswith('/search'):
            return 'search'
        elif path.startswith('/browse'):
            return 'browse'
        elif path.startswith('/category'):
            return path.split('/')[-1]
        else:
            return 'other'


    def get_similar_urls(self,domain, purpose):
        """
        Returns a list of similar URLs based on the domain and purpose.
        """
        if purpose == 'search':
            return [f"https://{domain}/search?query=test",
                    f"https://{domain}/search?query=example",
                    f"https://{domain}/search?query=foo",
                    f"https://{domain}/search?query=bar",
                    f"https://{domain}/search?query=baz"]
        elif purpose == 'browse':
            return [f"https://{domain}/browse",
                    f"https://{domain}/browse/category1",
                    f"https://{domain}/browse/category2",
                    f"https://{domain}/browse/category3",
                    f"https://{domain}/browse/category4"]
        else:
            return [f"https://{domain}/category/{purpose}",
                    f"https://{domain}/category/{purpose}/page1",
                    f"https://{domain}/category/{purpose}/page2",
                    f"https://{domain}/category/{purpose}/page3",
                    f"https://{domain}/category/{purpose}/page4"]

    def check_query_parameter(self):
            # Parse the given URL
            parsed_url = urlparse(self.url)
            query_params = parse_qs(parsed_url.query)
            num_query_params = len(query_params)

            # Get the domain and purpose of the URL
            domain = parsed_url.netloc
            purpose = self.get_url_purpose()

            # Get a sample of URLs that are similar in domain and purpose to the given URL
            similar_urls = self.get_similar_urls(domain, purpose)
            sample_size = min(len(similar_urls), 10)
            sample_urls = random.sample(similar_urls, sample_size)

            # Calculate the average number of query parameters across the sample URLs
            sample_query_params = [len(parse_qs(urlparse(sample_url).query)) for sample_url in sample_urls]
            avg_query_params = sum(sample_query_params) / len(sample_query_params)

            # Set the threshold as the average number of query parameters plus a margin of error
            threshold = int(avg_query_params * 1.5)

            # Initialize extra_query_params before the if-else block
            extra_query_params = 0

            # Determine the score based on the number of query parameters and the threshold
            if num_query_params <= threshold:
                print("adequate amount of query parameters")
                score = 0
                extra_query_params_percentage = 0
            else:
                print("suspicious amount of query parameters")
                extra_query_params = num_query_params - threshold
                extra_query_params_percentage = (extra_query_params / num_query_params) * 100
                score = 1

            print(f"Number of query parameters: {num_query_params}")
            print(f"Threshold of query parameters: {threshold}")
            print(f"Extra query parameters beyond threshold: {extra_query_params}")
            print(f"Percentage of extra query parameters: {extra_query_params_percentage:.2f}%")
            return score

    def get_first_report(self):
        if self.is_url():
            self.report +=f"{self.url} is a valid url.\n"
        else:
            self.report =f"oops! invalid input\n"
            self.urlscore = 100
            return self.report

        if self.check_url_in_database() is False:
            self.report+="URL not in local DB\n"
        else:
            if self.check_url_in_database()=="safe":
                self.report += "URL found in local Database - it is safe\n"
            elif self.check_url_in_database()=="most_likely_safe":
                self.report += "URL found in local Database - it is most likely safe\n"
            if self.check_url_in_database()=="suspicious":
                self.report += "URL found in local Database - it is very suspicious\n"
            if self.check_url_in_database()=="malicious":
                self.report += "URL found in local Database - it is malicious!\n"
            self.urlscore = 30
            return self.report

        # Get the schemed URL
        url = self.get_schemed_url()
        self.report += f"URL: {url}\n"

        subdomain_score = self.check_subdomain_count()
        self.report += f"subdomain score: {subdomain_score}.\n"
        if (subdomain_score < 1.0 and subdomain_score > 0.0):
            self.report +=f"url has a typical amount of subdomains\n"
        else:
            self.urlscore+=1
            self.report +="url has an unusal amount of subdomains\n"

        url_len = self.check_url_length()
        self.report += f"URL length score: {url_len}.\n"
        if url_len == 0.0:
            self.report += f"url has a typical length\n"
        else:
            self.urlscore += 1
            self.report += "url has an unusal length\n"

        query_pa_score = self.check_query_parameter()
        self.report += f"URL query parameters count score: {query_pa_score}.\n"
        if query_pa_score == 0:
            self.report +="adequate amount of query \n"
        else:
            self.report +="suspicious amount of query parameters\n"
            self.urlscore += 1
        return self.report







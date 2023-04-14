# Benjamin Mamistvalov
# Computer Network Researching course
# Coded in vscode - no PEP8 warner

import socket
import time
import urllib.request
from datetime import datetime
from wsgiref.handlers import format_date_time
from scapy.all import IP, UDP, DNS, DNSQR, sr1

SERVER_IP = '0.0.0.0'
PORT = 8153
DNS_SERVER_IP = '8.8.8.8'
SOCKET_TIMEOUT = 0.1
SCAPY_TIMEOUT = 1
RECV_MAX_LEN = 2048
HOST = 'http://127.0.0.1:8153/'
FILE_TYPES = {'html' : 'text/html; charset=utf-8', 'jpg' : 'image/jpeg', 'css' : 'text/css', \
            'ico' : 'image/x-icon', 'js' : 'text/javascript; charset=utf-8', 'gif' : 'image/gif', \
            'txt' : 'text/plain; charset=utf-8'}
RESPONSE_TYPES = {'200' : '200 OK', '404' : '404 Not Found', '500' : '500 Internal Server Error'}
NON_DEFAULT_FUNCTIONS = ['reverse']


def is_internet_connected():
    """Check if internet connection is available"""
    try:
        urllib.request.urlopen('https://www.google.com/')
        return True
    except:
        return False


def domain_name_to_ip(domain_name):
    """Finds the IP (IPv4) addresses of the given domain name"""
    dns_packet = IP(dst = DNS_SERVER_IP) / UDP(dport = 53) / DNS(qdcount = 1, rd = 1) / DNSQR(qname = domain_name) # Generating the type A DNS Question Packet
    response_packet = None
    while response_packet is None: # Ensuring the packet doesnt get lost
        response_packet = sr1(dns_packet, timeout = SOCKET_TIMEOUT)

    if response_packet[DNS].ancount == 0: # Checking if the domain name does not exist - by checking if the answer count is 0
        res_type = RESPONSE_TYPES['404']
        content_type = FILE_TYPES['html']
        data = ['<html>', '<head><title>Domain Name Not Found</title></head>', '<body>', f'<h1>Domain Name Not Found</h1>', \
                f'<p>The domain "{domain_name}" was not found.</p>', '<div style="display: none">Benjamin Mamistvalov</div>', \
                '</body>', '</html>'] # 404 response custom body
        data = '\r\n'.join(data)
    else:
        ips = [response_packet[DNS].an[i].rdata for i in range(response_packet[DNS].ancount) \
            if response_packet[DNS].an[i].type == 1] # Getting the ips by getting the rdata if the type is A
        res_type = RESPONSE_TYPES['200']
        content_type = FILE_TYPES['txt']
        data = '\r\n'.join(sorted(ips))

    return res_type, content_type, data


def ip_to_domain_name(ip):
    """Finds the domain name that is related to the given IP (IPv4) address.
        If no domain name has been found, that could mean on of the following:
        1. The IP address is not related to a domain name at all.
        2. The IP address is related to multiple domain names, hence the server with this IP
            is a storage (host) server of some domain names"""
    ip_splitted = ip.split('.')
    if len(ip_splitted) != 4 or not all(map(lambda x: x.isnumeric() and 0 <= int(x) <= 255, ip_splitted)): # Checking if the IP is in the correct format of an IPv4
        res_type = RESPONSE_TYPES['500']
        content_type = FILE_TYPES['html']
        data = ['<html>', '<head><title>Bad IP Format</title></head>', '<body>', '<h1>Bad IP Format</h1>', \
            f'<p>The provided IP "{ip}" is not in the correct format of an IPv4.</p>', \
            '<p><u>Correct IPv4 format:</u> &lt;a&gt;.&lt;b&gt;.&lt;c&gt;.&lt;d&gt;</p>', '<ul>', \
            '<li>0 &lt;= a &lt;= 255</li>', '<li>0 &lt;= b &lt;= 255</li>', '<li>0 &lt;= c &lt;= 255</li>', \
            '<li>0 &lt;= d &lt;= 255</li>', '</ul>', '<div style="display: none">Benjamin Mamistvalov</div>', \
            '</body>', '</html>']
        data = '\r\n'.join(data)
    else:
        qname = '.'.join(ip_splitted[::-1]) + '.in-addr.arpa.' # Reversing the IP address and adding '.in.addr.arpa.' to it
        dns_packet = IP(dst = DNS_SERVER_IP) / UDP(dport = 53) / DNS(qdcount = 1, rd = 1) / DNSQR(qname = qname, qtype = 12) # Generating the type PTR DNS Question packet
        response_packet = None
        # TODO: Add timeout to this while loop
        while response_packet is None: # Ensuring the packet doesnt get lost
            response_packet = sr1(dns_packet, timeout = SOCKET_TIMEOUT)
        if response_packet[DNS].ancount == 0: # Checking if the ip is not related to a domain name - by checking if the answer count is 0
            res_type = RESPONSE_TYPES['404']
            content_type = FILE_TYPES['html']
            data = ['<html>', '<head><title>IP Not Related</title></head>', '<body>', f'<h1>IP Not Related</h1>', \
                    f'<p>The ip "{ip}" is not related to a specific or any domain name.</p>', \
                    '<div style="display: none">Benjamin Mamistvalov</div>', '</body>', '</html>'] # 404 response custom body
            data = '\r\n'.join(data)
        else:
            res_type = RESPONSE_TYPES['200']
            content_type = FILE_TYPES['txt']
            data = response_packet[DNS].an.rdata.decode() # Getting the domain name by getting the rdata
    
    return res_type, content_type, data


def handle_client_request(resource, client_socket):
    """ Check the required function, generate proper HTTP response and send to client"""
    argv = resource.split('/')

    if len(argv) == 1: # Checking if the nslookup is type A: Domain Name -> IP
        res_type, content_type, data = domain_name_to_ip(argv[0])
    elif len(argv) == 2 and argv[0] == NON_DEFAULT_FUNCTIONS[0]: # Checking if the nslookup is type PTR: IP -> Domain Name
        res_type, content_type, data = ip_to_domain_name(argv[1])
    else:
        res_type = RESPONSE_TYPES['500']
        content_type = FILE_TYPES['html']
        data = ['<html>', f'<head><title>{RESPONSE_TYPES["500"]}</title></head>', '<body>', f'<h1>{RESPONSE_TYPES["500"]}</h1>', \
                '<p>The entered command is not supported.</p>', f'<p><b><u>Supported commands:</u></b></p>', '<ul>', \
                '<li><u>/&lt;Domain Name&gt;</u> - Get IP of the Domain Name</li>', \
                '<li><u>/reverse/&lt;IP&gt;</u> - Get Domain Name related to the IP</li>', '</ul>', \
                '<div style="display: none">Benjamin Mamistvalov</div>', '</body>', '</html>'] # 404 response custom body
        data = '\r\n'.join(data)
    
    http_header = [f'HTTP/1.1 {res_type}']
    http_header.append(f'Date: {format_date_time(time.mktime(datetime.now().timetuple()))}')
    http_header.append(f'Content-Type: {content_type}')
    http_header.append(f'Content-Length: {len(str(data))}')
    http_header.append('Connection: keep-alive')
    http_header.append('')
    http_header = '\r\n'.join(http_header)
    http_header += '\r\n'

    http_header += str(data) # Combining the headers with the body
    client_socket.send(http_header.encode())


def validate_http_request(request):
    """
    Check if request is a valid HTTP request and returns TRUE / FALSE and the requested URL
    """
    splitted_request = request.split('\r\n') # Splitting the request by lines

    # HTTP Format: First line has 3 parts splitted by ' ' as follows: "<Request Type (In this exercise is GET)> <URL (Starting with '/')> <Version>".
    #                                                                  ---------------------------------------- ------------------------- ---------
    #                                                                                     1                                  2                3
    #              Very last line should be empty.
    #              All lines in between have 2 parts splitter by ':' as follows: "<Header Name> : <Header Content>".
    #                                                                             -------------   ----------------
    #                                                                                   1                2
    if not (len(splitted_request[0].split(' ')) == 3 and splitted_request[0].split(' ')[0] == 'GET' and \
            splitted_request[0].split(' ')[1][0] == '/' and splitted_request[0].split(' ')[2] == 'HTTP/1.1' and \
            splitted_request[-2] == ''): # Checking the first and last lines
            return False, ''
    for line in splitted_request[1:-2]: # Checking the lines in between
        if len(line.split(': ')) != 2:
            return False, ''
    return True, splitted_request[0].split(' ')[1][1:]


def handle_client(client_socket):
    """ Handles client requests: verifies client's requests are legal HTTP, calls function to handle the requests """
    print('Client connected')

    while is_internet_connected():
        try:
            client_request = client_socket.recv(RECV_MAX_LEN).decode() # Attempting to receive the client's request
        except TimeoutError:
            break
        valid_http, resource = validate_http_request(client_request)
        if valid_http:
            print('Got a valid HTTP request')
            handle_client_request(resource, client_socket)
        else:
            print('Error: Not a valid HTTP request')
    
    print('Closing connection')
    client_socket.close()


def main():
    # Open a socket and loop forever while waiting for clients
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, PORT))
    server_socket.listen()
    print("Listening for connections on port {}".format(PORT))

    while True:
        client_socket, client_address = server_socket.accept()
        print('New connection received')
        client_socket.settimeout(SOCKET_TIMEOUT) # Setting a timeout for recv() function
        handle_client(client_socket)


if __name__ == '__main__':
    main()

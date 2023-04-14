# HTTP_nslookup
Type A and Type PTR nslookup over HTTP

Computer Network Research Course

<b>This server supports 2 GET requests:</b>
1. Type A lookup - Find IP addresses given a domain name</br>
   <b>Example:</b> http://127.0.0.1/www.youtube.com

2. Type PTR lookup - Try finding the domain name given an IP address</br>
   <b>Example:</b> http://127.0.0.1/reverse/142.250.185.132

* <b>Note:</b> 127.0.0.1 can be any IP on which you host this server
* <b>Note:</b> 142.250.185.132 is the IP address of one of youtube's servers

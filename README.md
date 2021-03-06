# httpscan.go
httpscan implements by Go

# Feature
- [x] CIDR support
- [x] Proxy support
- [x] Automatic recognition of page encoding
- [x] Export the scanning result
- [x] TCP and UDP port scanning
- [x] Progress report

# Usage
```
$ ./httpscan -h
Usage of ./httpscan:
  -failover
    	Fallback to HTTPS connection if the normal HTTP request was failed, this works on HTTP scan mode only
  -file string
    	Specify a local file contains a list of URLs
  -o string
    	Redirect the output to local file
  -port string
    	List of port(s) to be scan, such as 80,8000-8009,s443 etc. Port starts with 's' prefix indicate that the connection will be negotiate with SSL/TLS. Similar starts with 'u' for UDP connection (default "80")
  -proxy string
    	Specify a proxy server for all connection, currently HTTP and SOCKS5 are supported, this work only on the HTTP mode
  -tcp
    	Switch the scanning mode to TCP/UDP instead of HTTP request
  -threads int
    	Maximum number of threads (default 20)
  -timeout int
    	Default timeout for connection session (default 10)
```

Scanning the CIDR addresses:
```
$ ./httpscan -port 8080 10.0.0.0/24 192.168.1.0/24
```

Specify a proxy server:
```
$ ./httpscan -proxy socks5://127.0.0.1:1080 10.0.0.0/24
```

The connection will establish with SSL/TLS if the port prefix with the `s` alphabet:
```
$ ./httpscan -port s443 10.0.0.0/24
```

# Screenshot
![httpscan](https://user-images.githubusercontent.com/6657773/35740555-1ce8a958-0870-11e8-95d9-6343c96d5e90.png)
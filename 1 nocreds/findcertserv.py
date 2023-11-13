import nmap

# Initialize Nmap Scanner
nm = nmap.PortScanner()

# Perform initial service discovery scan
nm.scan(hosts='<target-ip-range>', arguments='-p 80,443,389,636')

# Collect hosts with open ports from the service discovery
hosts_list = [(x, nm[x]['tcp']) for x in nm.all_hosts() if nm[x].state() == 'up']

# Perform script scanning on collected hosts
for host, ports in hosts_list:
    # Only scan if one of the desired ports is open
    if any(port in ports for port in [80, 443, 389, 636]):
        print(f"Scanning {host} for LDAP and SSL certificate info")
        nm.scan(hosts=host, arguments='--script "ldap* and ssl-cert" -p 389,636')

        # Process the results as needed
        print(nm[host])

SAMPLE_NMAP_XML_UP = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap" start="1710000000" version="7.94" xmloutputversion="1.05">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.52"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

SAMPLE_NMAP_XML_DOWN = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap" start="1710000000" version="7.94" xmloutputversion="1.05">
  <host>
    <status state="down" reason="no-response"/>
    <address addr="10.255.255.1" addrtype="ipv4"/>
  </host>
</nmaprun>
"""

SAMPLE_NMAP_XML_FQDN = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap" start="1710000000" version="7.94" xmloutputversion="1.05">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="45.33.32.156" addrtype="ipv4"/>
    <hostnames>
      <hostname name="scanme.nmap.org" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="6.6.1p1"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

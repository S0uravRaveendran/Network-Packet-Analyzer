# Network-Packet-Analyzer
⚠️ Ethical Notice:
Use this tool only on networks where you have permission. Capturing packets on unauthorized networks is illegal and unethical.

You need Python 3 and Scapy. On most Linux systems:

sudo apt update
sudo apt install python3 python3-pip
pip3 install scapy


Develop a packet sniffer tool that captures and analyzes network packets. Display relevant information such as source and destination IP addresses, protocols, and payload data. Ensure the ethical use of the tool for educational purposes.


-i <interface>: the network interface to sniff on (e.g. eth0, wlan0, en0 on macOS).
-c <count>: number of packets to capture (use 0 or omit for infinite capture).

Save the python file in a folder first.Then Enter the folder.

Capture 100 packets on eth0 (Linux):
sudo python3 Network\ Packet\ Analyzer.py -i eth0 -c 100
 
While using Linux OS  ,Use this command 
sudo python3 Network\ Packet\ Analyzer.py -i eth0     

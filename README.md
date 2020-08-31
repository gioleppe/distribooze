# distribooze
distribution printer for network flows

This tool takes a .pcap file as input 
and outputs the percent distribution vector of packet lenghts in each flow.
Bins all take 32 bytes each and go from 0 to 1504 bytes.

You can pass the pcap's path along with an optional BPF syntax filter to the command line tool.

### Dependencies
The tool has the following dependency:
- **Scapy 2.4.3** 

To install scapy you 
can run this command assuming you are in a 
conda environment

`conda install scapy`

alternatively, if you're using plain pip, you can use

`pip3 install scapy`

This is not recommended though, since it
 installs dependencies systemwide and could potentially break other projects.
 
 ### How it works
 
 The tool uses code at https://github.com/daniele-sartiano/doh 
 to print distribution percentage vectors for each unidirectional
  flow in a given pcap.
 
 ### Running the tool
 
 In order to run the tool you can use 
 
~~~
git clone https://github.com/gioleppe/distribooze
cd distribooze
python3 ./distribooze.py <pcap> -f <BPF_filter>
~~~

You can also use the -h flag to show an help message.

### Pcap Analysis 


Analyzing the pcaps in the /distribooze/pcaps folder we found out these things:

- bittorrent.pcap's flows have more or less the same distribution, there seems 
to be a large number of small packets exchanged by the clients belonging to the first bin.

- ssh_27122 and ssh_second_try pcaps, describing two distinct ssh connections on a nonstandard port with the same host, 
show that the flows are very similar, with more than 60% of client-side packets in the first bin
 (the one that goes from 0 to 32 bytes). This could be caused by the 
 single keystrokes being sent to the remote server via the ssh connection.
 To see these distributions please use `-f "tcp and port 27122"`.

-  the instagram pcap is difficult to analyse since there's a multitude of hosts in the pcap. 
That said there seems to be a certain regularity in the percentual distributions of the bins: either very small packages 
or medium sized ones belonging to the 23rd bin, the one that goes from 736 to 768 bytes.

- DoH has a very clear typical distributions and the majority of packets 
of its flows are to be found in the first bin.

- Netflix flows seem to have a clear bias towards medium sized packets. This could be caused by the nature of
the service (streaming a movie is much more network heavy than dns requests)
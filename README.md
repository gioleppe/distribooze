# distribooze
distribution printer for network flows

This tool takes a .pcap file as input 
and outputs the percent distribution of packet lenghts in each flow 

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
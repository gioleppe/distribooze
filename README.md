# distribooze
distribution printing and comparison for network flows

This tool takes a .pcap file as input 
and outputs the percent distribution vector of packet lenghts in each flow.
if called with the `-c` flag, it compares the given pcap to all previously computed distributions
The tool can be used to determine how similar two pcaps are, and thus to recognize specific protocols.

Bins used for the distributions all take 32 bytes each and go from 0 to 1504 bytes.

You can pass the pcap's path along with an optional BPF syntax filter to the command line tool.
The `-c` flag is necessary if you want to plot the similarity to the other fluxes


### Dependencies
The tool has the following dependency:
- **Numpy**
- **Scapy 2.4.3** 

To install scapy you 
can run this command assuming you are in a 
conda environment

`conda install scapy numpy`

alternatively, if you're using plain pip, you can use

`pip3 install scapy numpy`

This is not recommended though, since it
 installs dependencies systemwide and could potentially break other projects.
 
 ### How it works
 
 The tool uses code at https://github.com/daniele-sartiano/doh 
 to print distribution percentage vectors for each unidirectional
  flow in a given pcap. It saves computed distributions to a dictionary, 
  then it pickles it for further usage. 
  When called with the `-c` flag it compares the packet length distribution of the 
  given pcap with previously computed ones, plotting them ordered by similarity.
  The similarity is computed using the euclidean distance between the packet length
  distribution vectors
  `np.exp(-dist)` is used to compress the real axis in the range (-inf, 1).
  In case the distance is 0 (i.e. exp(-dist) == 1) the tool states that the analyzed
   pcap is probably the same.
   Computed distributions are saved in the ./dists.p pickle file (gitignored).

 
 ### Running the tool
 
 In order to run the tool to plot the distribution you can use 
 
~~~
git clone https://github.com/gioleppe/distribooze
cd distribooze
python3 ./distribooze.py <pcap> -f <BPF_filter>
~~~

To check for similarity between distributions use
 
~~~
python3 ./distribooze.py <pcap> -f <BPF_filter> [-c]
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
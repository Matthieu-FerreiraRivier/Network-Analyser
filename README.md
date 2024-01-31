# Network Analyser

The analyser captures packets passing through the network and analyse it. It describes the different encapsulated protocols.

## Requirements

Before compiling and running this project, make sure to satisfy the following dependencies:

- **pcap Library**: The project depends on the libpcap library for network packet capture.

### Installing libpcap

On Debian-based OS (Ubuntu, ...):

```
sudo apt-get install libpcap-dev
```

## How to use

For compiling run the command:
```
make
```
For running the program:
```
bin/analyser -o <file> -v <1..3>
```
The option -v corresponds to the verbosity level (1=concise, 2=synthetic, 3=complete).

You cant also analyse a live capture by using options:
```
bin/analyser -i <interface> -v <1..3>
```

For a live capture, you can add a BPF filter by running:
```
bin/analyser -i <interface> -f <filter> -v <1..3>
``` 
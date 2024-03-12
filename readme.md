# Traceroute
This command-line utility provides a way to traceroute to target ip.
## Usage
To run traceroute
1. Run the command below, replacing the necessary arguments: `python main.py [-t] [-p] [-n] [-v] <target> <protocol>`
## Arguments
The utility accepts the following arguments:

- `target`: The target IP address to scan. This argument is required.

- `protocol`: The protocol to scan.

- `-t`: The timeout for the response in seconds. The default value is 4 seconds.

- `-v`: Enable verbose mode, which provides more detailed output. This argument is optional.

- `-p`: The port to trace it

- `-n`: The number of max amount of requests
- ## Examples

Here are some example commands:
- `python main.py -t 1 -p 43 -n 42 -v 8.8.8.8 tcp`
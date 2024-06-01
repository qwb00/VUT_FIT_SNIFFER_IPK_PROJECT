# IPK Network sniffer Project Documentation

## Table of Contents

- [Executive Summary](#executive-summary)
- [Compilation and Execution](#compilation-and-execution)
  - [Compilation](#compilation)
  - [Running the Program](#running-the-program)
- [Command-Line Arguments](#command-line-arguments)
  - [Network Interface](#network-interface)
  - [Protocol Filters](#protocol-filters)
  - [Port Filters](#port-filters)
  - [Protocol-Specific Options](#protocol-specific-options)
  - [Additional option](#additional-option)
  - [Packet Count](#packet-count)
  - [Examples of Usage](#examples-of-usage)
- [System Overview](#system-overview)
  - [Main Handler (`main.c`)](#main-handler-mainc)
  - [Argument Parser (`args.c`)](#argument-parser-argsc)
  - [Packet Capture and Processing (`capture_packet.c`)](#packet-capture-and-processing-capture_packetc)
  - [System Workflow](#system-workflow)
- [Testing](#testing)
  - [Test Environment](#test-environment)
  - [Test Cases](#test-cases)
- [Extra Functionality](#extra-functionality)
- [Bibliography](#bibliography)

## Executive Summary

This document provides detailed information about the IPK Network sniffer project. The sniffer is designed to capture and analyze network packets, which can be used for network diagnostics and security analysis. The system utilizes the `pcap` library for capturing packets and allows filtering based on various parameters like protocol type and ports.

## Compilation and Execution

### Compilation
To compile the sniffer program, ensure you are in the directory containing the source code and the `Makefile`. Run the following command:

```bash
make
```

### Running the Program
After compiling the `ipk-sniffer` using the provided `Makefile`, you can run the program using the following command:

```bash
./ipk-sniffer [options]
```

## Command-Line Arguments

The `ipk-sniffer` executable supports a range of options to control its behavior for capturing and analyzing network traffic. Below is a description of each available command-line argument:

### Network Interface

- `-i interface`, `--interface interface`
  - **Description:** Specifies the network interface to capture packets from.
  - **Usage:**
    - If not provided and no other parameters are specified, the program lists all available network interfaces.
    - If provided without a value and no other parameters are specified, the program will also list available interfaces.

### Protocol Filters

- `-t`, `--tcp`
  - **Description:** Capture only TCP segments.
  - **Complementary Options:** Can be used with `-p`, `--port-destination`, or `--port-source` to filter based on port numbers.

- `-u`, `--udp`
  - **Description:** Capture only UDP datagrams.
  - **Complementary Options:** Can be used with `-p`, `--port-destination`, or `--port-source` for port filtering.

### Port Filters

- `-p port`
  - **Description:** Filters TCP or UDP packets to include only those where the specified port number appears in either the source or destination.

- `--port-destination port`
  - **Description:** Filters TCP or UDP packets to include only those where the specified port number appears in the destination.

- `--port-source port`
  - **Description:** Filters TCP or UDP packets to include only those where the specified port number appears in the source.

### Protocol-Specific Options

- `--icmp4`
  - **Description:** Capture only ICMPv4 packets.

- `--icmp6`
  - **Description:** Capture only ICMPv6 packets, specifically echo request/response.

- `--arp`
  - **Description:** Capture only ARP (Address Resolution Protocol) frames.

- `--ndp`
  - **Description:** Capture only NDP (Neighbor Discovery Protocol) packets, a subset of ICMPv6.

- `--igmp`
  - **Description:** Capture only IGMP (Internet Group Management Protocol) packets.

- `--mld`
  - **Description:** Capture only MLD (Multicast Listener Discovery) packets, also a subset of ICMPv6.

### Additional option
- `--help`, `-h`
  - **Description:** Shows help information about the available command-line options. 

### Packet Count

- `-n num`
  - **Description:** Specifies the number of packets to capture before terminating.
  - **Default:** If not specified, the default is to capture only one packet.

### Examples of Usage

1. **List all available network interfaces:**
   ```bash
   ./ipk-sniffer -i
    ```
2. **Capture 10 TCP packets from a specific interface (eth0):
   If you're interested in monitoring TCP traffic on the eth0 interface, this command will capture the first 10 TCP packets that pass through.**
   ```bash
    ./ipk-sniffer -i eth0 -t -n 10
    ```
3. **Capture ICMPv6 packets with a specific source port:
   To capture ICMPv6 packets with a specific source port (e.g., 1234), you can use the following command:**
   ```bash
    ./ipk-sniffer --icmp6 --port-source 1234
    ```
4. **Monitor all traffic on eth0 without any filters:
   If you want to observe all the traffic passing through the eth0 interface without applying any filters, use this simple command. It's useful for a general overview or initial diagnostics.**  
    ```bash
     ./ipk-sniffer -i eth0
     ```
## System Overview

### Main Handler (`main.c`)

- **Initialization and Loop**: Handles initialization, command-line parsing, and starts a packet capture loop with `pcap_loop()`.
- **Signal Handling**: Uses `signal(SIGINT, close_program)` to gracefully close and exit upon interruption.

### Argument Parser (`args.c`)

- **Command-Line Flexibility**: Uses `getopt_long()` to parse a wide range of network traffic filters, like protocol types and ports, enhancing the sniffer's flexibility and precision.
- **Dynamic Filter Construction**: Builds complex pcap filter expressions dynamically based on user inputs.

### Packet Capture and Processing (`capture_packet.c`)

- **Device Setup**: Opens network devices for sniffing and applies compiled filter expressions.
- **Packet Processing**: Each packet is processed in `packet_handler()`, extracting and printing detailed network data.

## System Workflow

1. **Initialization**: Parses command-line arguments to set up filters and device options.
2. **Packet Capture Setup**: Compiles filters and prepares the network device.
3. **Capture and Display**: Captures packets and processes them to display detailed insights, adjusting dynamically based on user-specified filters.

## Testing

### Test Environment

- **Software:** The project was tested on MacOS and Linux Ubuntu, below will be only test cases for the MacOS environment.
- **Hardware:** Testing interface was a en0 interface on MacOS.

### Test Cases

#### Comparison with Wireshark 
Testing of the packet sniffer was conducted by comparing its performance and output against Wireshark.

1. **Basic Packet Capture**: Capturing a single packet without any filters.
    ```bash
   ./ipk-sniffer -i en0
    ```
    **Wireshark output:**
   ```
    Interface name: en0
    Arrival Time: Apr 22, 2024 16:54:43.794222000 CEST
    Frame Length: 120 bytes 
    Source Port: 53775
    Destination Port: 443
    Source Address: 192.168.1.100
    Destination Address: 162.159.135.234

    0000  0c 80 63 ea c7 42 18 3e ef d7 33 38 08 00 45 00   ..c..B.>..38..E.
    0010  00 6a 00 00 40 00 40 06 4d f8 c0 a8 01 64 a2 9f   .j..@.@.M....d..
    0020  87 ea d2 0f 01 bb ba 3d 67 8b c4 2f 50 65 80 18   .......=g../Pe..
    0030  17 80 cd 1b 00 00 01 01 08 0a 07 f3 d9 ac 74 7d   ..............t}
    0040  0d d1 17 03 03 00 31 9d f7 fd 3b 12 44 7c 72 4e   ......1...;.D|rN
    0050  9a 24 aa 3c e4 2f cb cf 06 b6 e9 61 c5 94 47 c5   .$.<./.....a..G.
    0060  f1 84 1a 5a f7 a0 91 82 7e 64 83 a6 33 aa 44 0a   ...Z....~d..3.D.
    0070  aa 58 28 e1 04 11 29 db                           .X(...).
    ```
   **ipk-sniffer output:**
   ```
    timestamp: 2024-04-22T16:54:43.794+02:00
    src MAC: 18:3e:ef:d7:33:38
    dst MAC: 0c:80:63:ea:c7:42
    frame length: 120 bytes
    src IP: 192.168.1.100
    dst IP: 162.159.135.234
    src port: 53775
    dst port: 443
    info: TCP
    
    0x0000: 0c 80 63 ea c7 42 18 3e ef d7 33 38 08 00 45 00  ..c..B.>..38..E.
    0x0010: 00 6a 00 00 40 00 40 06 4d f8 c0 a8 01 64 a2 9f  .j..@.@.M....d..
    0x0020: 87 ea d2 0f 01 bb ba 3d 67 8b c4 2f 50 65 80 18  .......=g../Pe..
    0x0030: 17 80 cd 1b 00 00 01 01 08 0a 07 f3 d9 ac 74 7d  ..............t}
    0x0040: 0d d1 17 03 03 00 31 9d f7 fd 3b 12 44 7c 72 4e  ......1...;.D|rN
    0x0050: 9a 24 aa 3c e4 2f cb cf 06 b6 e9 61 c5 94 47 c5  .$.<./.....a..G.
    0x0060: f1 84 1a 5a f7 a0 91 82 7e 64 83 a6 33 aa 44 0a  ...Z....~d..3.D.
    0x0070: aa 58 28 e1 04 11 29 db                          .X(...).

   ```

2. **Capture udp packet**: Capturing a single udp packet.
    ```bash
   ./ipk-sniffer -i en0 --udp
    ```
    **Wireshark output:**
    ```
    Interface name: en0
    Arrival Time: Apr 22, 2024 17:18:52.446286000 CEST
    Frame Length: 86 bytes
    Source Port: 57621
    Destination Port: 57621
    Src: 192.168.1.102
    Dst: 192.168.1.255
      
    0000  ff ff ff ff ff ff 96 c4 07 04 c0 92 08 00 45 00   ..............E.
    0010  00 48 f5 c5 00 00 80 11 c0 29 c0 a8 01 66 c0 a8   .H.......)...f..
    0020  01 ff e1 15 e1 15 00 34 ed a7 53 70 6f 74 55 64   .......4..SpotUd
    0030  70 30 e1 6e c6 6b 72 cf 41 71 00 01 00 04 48 95   p0.n.kr.Aq....H.
    0040  c2 03 ba 9e e8 fe 34 35 56 ce ad af ff fb 89 c3   ......45V.......
    0050  cf 06 1e 5b 88 57                                 ...[.W
    ```
    
    **ipk-sniffer output:**
    ```
     timestamp: 2024-04-22T17:18:52.446+02:00
     src MAC: 96:c4:07:04:c0:92
     dst MAC: ff:ff:ff:ff:ff:ff
     frame length: 86 bytes
     src IP: 192.168.1.102
     dst IP: 192.168.1.255
     src port: 57621
     dst port: 57621
     info: UDP
        
     0x0000: ff ff ff ff ff ff 96 c4 07 04 c0 92 08 00 45 00  ..............E.
     0x0010: 00 48 f5 c5 00 00 80 11 c0 29 c0 a8 01 66 c0 a8  .H.......)...f..
     0x0020: 01 ff e1 15 e1 15 00 34 ed a7 53 70 6f 74 55 64  .......4..SpotUd
     0x0030: 70 30 e1 6e c6 6b 72 cf 41 71 00 01 00 04 48 95  p0.n.kr.Aq....H.
     0x0040: c2 03 ba 9e e8 fe 34 35 56 ce ad af ff fb 89 c3  ......45V.......
     0x0050: cf 06 1e 5b 88 57
     ```

3. **Capture arp, igmp**: Capturing a 3 arp or igmp.
   ```bash
   ./ipk-sniffer -i en0 --igmp -- arp -n 3
   ```
    **Wireshark output:**
    ```  
    Interface name: en0
    Arrival Time: Apr 22, 2024 17:35:13.631673000 CEST 
    Frame Length: 42 bytes
    Sender IP address: 192.168.1.1
    Target IP address: 192.168.1.100
   
    0000  18 3e ef d7 33 38 0c 80 63 ea c7 42 08 06 00 01   .>..38..c..B....
    0010  08 00 06 04 00 01 0c 80 63 ea c7 42 c0 a8 01 01   ........c..B....
    0020  00 00 00 00 00 00 c0 a8 01 64                     .........d
   
    Interface name: en0
    Arrival Time: Apr 22, 2024 17:35:13.631806000 CEST
    Frame Length: 42 bytes
    Sender IP address: 192.168.1.100
    Target IP address: 192.168.1.1
   
    0000  0c 80 63 ea c7 42 18 3e ef d7 33 38 08 06 00 01   ..c..B.>..38....
    0010  08 00 06 04 00 02 18 3e ef d7 33 38 c0 a8 01 64   .......>..38...d
    0020  0c 80 63 ea c7 42 c0 a8 01 01                     ..c..B....
   
    Interface name: en0
    Arrival Time: Apr 22, 2024 17:35:28.660104000 CEST
    Frame Length: 42 bytes
    Sender IP address: 192.168.1.1
    Target IP address: 192.168.1.100
   
    0000  18 3e ef d7 33 38 0c 80 63 ea c7 42 08 06 00 01   .>..38..c..B....
    0010  08 00 06 04 00 02 0c 80 63 ea c7 42 c0 a8 01 01   ........c..B....
    0020  18 3e ef d7 33 38 c0 a8 01 64                     .>..38...d
    ``` 
    **ipk-sniffer output:**
    ```
    timestamp: 2024-04-22T17:35:13.631+02:00
    src MAC: 0c:80:63:ea:c7:42
    dst MAC: 18:3e:ef:d7:33:38
    frame length: 42 bytes
    src IP: 192.168.1.1
    dst IP: 192.168.1.100
    info: ARP
    
    0x0000: 18 3e ef d7 33 38 0c 80 63 ea c7 42 08 06 00 01  .>..38..c..B....
    0x0010: 08 00 06 04 00 01 0c 80 63 ea c7 42 c0 a8 01 01  ........c..B....
    0x0020: 00 00 00 00 00 00 c0 a8 01 64                    .........d
    
    timestamp: 2024-04-22T17:35:13.631+02:00
    src MAC: 18:3e:ef:d7:33:38
    dst MAC: 0c:80:63:ea:c7:42
    frame length: 42 bytes
    src IP: 192.168.1.100
    dst IP: 192.168.1.1
    info: ARP
    
    0x0000: 0c 80 63 ea c7 42 18 3e ef d7 33 38 08 06 00 01  ..c..B.>..38....
    0x0010: 08 00 06 04 00 02 18 3e ef d7 33 38 c0 a8 01 64  .......>..38...d
    0x0020: 0c 80 63 ea c7 42 c0 a8 01 01                    ..c..B....
    
    timestamp: 2024-04-22T17:35:28.660+02:00
    src MAC: 0c:80:63:ea:c7:42
    dst MAC: 18:3e:ef:d7:33:38
    frame length: 42 bytes
    src IP: 192.168.1.1
    dst IP: 192.168.1.100
    info: ARP
    
    0x0000: 18 3e ef d7 33 38 0c 80 63 ea c7 42 08 06 00 01  .>..38..c..B....
    0x0010: 08 00 06 04 00 02 0c 80 63 ea c7 42 c0 a8 01 01  ........c..B....
    0x0020: 18 3e ef d7 33 38 c0 a8 01 64                    .>..38...d

    ```
   
#### Testing with complex arguments

The tests below show the work of sniffer with complex arguments in these tests wireshark is not used.

1. **Testing UDP and TCP protocols with specific ports.**
    **Command:**
    ```bash
    ./ipk-sniffer -i en0 --tcp --udp --port-destination 80 --port-source 443 -n 5
    ```
   **Expected Output:**
   The sniffer should capture a total of 5 packets that are either TCP or UDP where the source port is 443.
    
    **Output:**
    ```
    timestamp: 2024-04-22T18:44:56.511+02:00
    src MAC: 0c:80:63:ea:c7:42
    dst MAC: 18:3e:ef:d7:33:38
    frame length: 66 bytes
    src IP: 35.186.224.39
    dst IP: 192.168.1.100
    src port: 443
    dst port: 54078
    info: TCP
    
    0x0000: 18 3e ef d7 33 38 0c 80 63 ea c7 42 08 00 45 00  .>..38..c..B..E.
    0x0010: 00 34 f8 12 00 00 76 06 86 c3 23 ba e0 27 c0 a8  .4....v...#..'..
    0x0020: 01 64 01 bb d3 3e 7d a9 2b c5 5f 95 4b d0 80 10  .d...>}.+._.K...
    0x0030: 01 0d 5e cb 00 00 01 01 08 0a f9 b2 a1 ee 2e 57  ..^............W
    0x0040: 5d 30                                            ]0
    
    timestamp: 2024-04-22T18:44:56.521+02:00
    src MAC: 0c:80:63:ea:c7:42
    dst MAC: 18:3e:ef:d7:33:38
    frame length: 106 bytes
    src IP: 35.186.224.39
    dst IP: 192.168.1.100
    src port: 443
    dst port: 54078
    info: TCP
    
    0x0000: 18 3e ef d7 33 38 0c 80 63 ea c7 42 08 00 45 00  .>..38..c..B..E.
    0x0010: 00 5c f8 13 00 00 76 06 86 9a 23 ba e0 27 c0 a8  .\....v...#..'..
    0x0020: 01 64 01 bb d3 3e 7d a9 2b c5 5f 95 4b d0 80 18  .d...>}.+._.K...
    0x0030: 01 0d 78 0b 00 00 01 01 08 0a f9 b2 a1 f7 2e 57  ..x............W
    0x0040: 5d 30 17 03 03 00 23 87 8e 71 1e c5 33 ce 51 d7  ]0....#..q..3.Q.
    0x0050: da 7b 71 83 b5 d3 5d 54 99 64 02 93 fd 8e 8c ad  .{q...]T.d......
    0x0060: 18 ea fc 33 35 50 f7 ce ae 87                    ...35P....
    
    timestamp: 2024-04-22T18:45:01.621+02:00
    src MAC: 0c:80:63:ea:c7:42
    dst MAC: 18:3e:ef:d7:33:38
    frame length: 338 bytes
    src IP: 162.159.135.234
    dst IP: 192.168.1.100
    src port: 443
    dst port: 54067
    info: TCP
    
    0x0000: 18 3e ef d7 33 38 0c 80 63 ea c7 42 08 00 45 00  .>..38..c..B..E.
    0x0010: 01 44 7f 5d 40 00 36 06 d7 c0 a2 9f 87 ea c0 a8  .D.]@.6.........
    0x0020: 01 64 01 bb d3 33 d2 2b 3c 4a 0e e0 c0 a6 80 18  .d...3.+<J......
    0x0030: 00 05 a5 23 00 00 01 01 08 0a c7 40 28 c3 fb 81  ...#.......@(...
    0x0040: ba 54 17 03 03 01 0b d3 cf 22 db b5 71 df a6 44  .T......."..q..D
    0x0050: 20 c3 26 4c f1 24 fb 77 8d a6 95 a9 e2 b6 d9 35   .&L.$.w.......5
    0x0060: 27 71 84 bb 92 93 d6 cc 8f 6c 4a 92 12 bb 73 d2  'q.......lJ...s.
    0x0070: 7a 34 61 5c d3 3c c3 2d 96 fe cf b8 71 61 2c 2f  z4a\.<.-....qa,/
    0x0080: 67 68 b2 af b3 22 79 65 f8 a3 ea 63 5a 75 af 9a  gh..."ye...cZu..
    0x0090: e1 9a da 1a 81 bb 4f 4a 57 f7 21 d6 89 79 75 a1  ......OJW.!..yu.
    0x00a0: df c9 fe 98 6e 71 af 3b ba 22 e9 85 ff a3 bb 24  ....nq.;.".....$
    0x00b0: 77 17 dc 4c c2 ab 56 69 fc 4b 55 60 d0 d6 8c fd  w..L..Vi.KU`....
    0x00c0: e8 bc 68 2c 94 f8 e4 33 57 68 7f 06 aa d9 0e 1e  ..h,...3Wh......
    0x00d0: ee e3 da 58 54 19 12 f1 91 2a 03 0c c5 d3 1a 58  ...XT....*.....X
    0x00e0: f2 f7 36 b5 67 2f 54 f6 68 2b 6a b2 8b cf a0 5f  ..6.g/T.h+j...._
    0x00f0: 10 cd 29 8d a2 9e 36 d7 80 f7 d5 5a 72 75 77 c3  ..)...6....Zruw.
    0x0100: 65 0f ad 1a d8 65 c1 97 53 3f 82 61 79 07 aa 6b  e....e..S?.ay..k
    0x0110: cf 01 97 84 36 62 91 39 05 b8 d1 a4 32 73 3e d5  ....6b.9....2s>.
    0x0120: ce e7 5e 3e a9 43 e0 22 0b d7 10 c6 c8 1a 95 0c  ..^>.C."........
    0x0130: fb 41 0a 38 05 f7 3d a8 06 0f 07 1e 8a e7 94 9b  .A.8..=.........
    0x0140: 71 20 cc d8 42 12 47 91 8d ea 99 46 5b 9e df 10  q ..B.G....F[...
    0x0150: d0 32                                            .2
    
    timestamp: 2024-04-22T18:45:02.513+02:00
    src MAC: 0c:80:63:ea:c7:42
    dst MAC: 18:3e:ef:d7:33:38
    frame length: 155 bytes
    src IP: 149.154.167.41
    dst IP: 192.168.1.100
    src port: 443
    dst port: 54079
    info: TCP
    
    0x0000: 18 3e ef d7 33 38 0c 80 63 ea c7 42 08 00 45 00  .>..38..c..B..E.
    0x0010: 00 8d e3 e7 40 00 2f 06 68 b3 95 9a a7 29 c0 a8  ....@./.h....)..
    0x0020: 01 64 01 bb d3 3f 08 75 de e6 23 20 0f 41 80 18  .d...?.u..# .A..
    0x0030: 0a 18 e8 03 00 00 01 01 08 0a df b5 4d 96 ac 52  ............M..R
    0x0040: d0 46 13 3d 6f 39 5a 77 37 51 47 c3 af 65 5c fc  .F.=o9Zw7QG..e\.
    0x0050: 19 74 56 a3 df 24 80 32 ce 72 bb 07 a4 d4 f5 22  .tV..$.2.r....."
    0x0060: ff 43 b3 f2 b2 2e d0 45 bb 5a 86 74 a2 92 a0 42  .C.....E.Z.t...B
    0x0070: 6f 15 9b 45 84 3f 72 18 59 a4 6e 51 3a b4 65 f4  o..E.?r.Y.nQ:.e.
    0x0080: b9 35 ad 50 d9 76 ea e2 bb d5 a1 2e e5 f7 42 0f  .5.P.v........B.
    0x0090: a8 db 7e de 62 07 40 69 ee d5 05                 ..~.b.@i...
    
    timestamp: 2024-04-22T18:45:08.605+02:00
    src MAC: 0c:80:63:ea:c7:42
    dst MAC: 18:3e:ef:d7:33:38
    frame length: 66 bytes
    src IP: 140.82.112.21
    dst IP: 192.168.1.100
    src port: 443
    dst port: 54077
    info: TCP
    
    0x0000: 18 3e ef d7 33 38 0c 80 63 ea c7 42 08 00 45 00  .>..38..c..B..E.
    0x0010: 00 34 bd 83 40 00 2d 06 d1 cc 8c 52 70 15 c0 a8  .4..@.-....Rp...
    0x0020: 01 64 01 bb d3 3d b1 4b 76 f7 06 0c ef 39 80 10  .d...=.Kv....9..
    0x0030: 05 8d 0b 46 00 00 01 01 08 0a db 92 5d 82 3f 44  ...F........].?D
    0x0040: 3c 9b                                            <.

    ```
2. **Testing ARP with udp protocol and specific port.**
    **Command:**
    ```bash
    ./ipk-sniffer -i en0 --arp --udp -n 3 -p 57621
    ```
   **Expected Output:**
   The sniffer should capture a total of 3 packets that are either ARP or UDP with source or destination port 57621.
    
    **Output:**
    ```
    timestamp: 2024-04-22T18:52:35.978+02:00
    src MAC: 40:ed:00:8a:2f:de
    dst MAC: ff:ff:ff:ff:ff:ff
    frame length: 86 bytes
    src IP: 192.168.1.105
    dst IP: 192.168.1.255
    src port: 57621
    dst port: 57621
    info: UDP
    
    0x0000: ff ff ff ff ff ff 40 ed 00 8a 2f de 08 00 45 00  ......@.../...E.
    0x0010: 00 48 bf 31 00 00 80 11 f6 ba c0 a8 01 69 c0 a8  .H.1.........i..
    0x0020: 01 ff e1 15 e1 15 00 34 15 ff 53 70 6f 74 55 64  .......4..SpotUd
    0x0030: 70 30 a3 f2 b5 61 b6 f0 3a 76 00 01 00 04 48 95  p0...a..:v....H.
    0x0040: c2 03 eb 2c a2 5e 8a d5 13 97 79 c8 b5 ca a5 ba  ...,.^....y.....
    0x0050: 91 ea 40 d1 f0 cd                                ..@...
    
    timestamp: 2024-04-22T18:52:38.643+02:00
    src MAC: 96:c4:07:04:c0:92
    dst MAC: ff:ff:ff:ff:ff:ff
    frame length: 86 bytes
    src IP: 192.168.1.102
    dst IP: 192.168.1.255
    src port: 57621
    dst port: 57621
    info: UDP
    
    0x0000: ff ff ff ff ff ff 96 c4 07 04 c0 92 08 00 45 00  ..............E.
    0x0010: 00 48 f6 68 00 00 80 11 bf 86 c0 a8 01 66 c0 a8  .H.h.........f..
    0x0020: 01 ff e1 15 e1 15 00 34 ed a7 53 70 6f 74 55 64  .......4..SpotUd
    0x0030: 70 30 e1 6e c6 6b 72 cf 41 71 00 01 00 04 48 95  p0.n.kr.Aq....H.
    0x0040: c2 03 ba 9e e8 fe 34 35 56 ce ad af ff fb 89 c3  ......45V.......
    0x0050: cf 06 1e 5b 88 57                                ...[.W
    
    timestamp: 2024-04-22T18:54:31.091+02:00
    src MAC: 0c:80:63:ea:c7:42
    dst MAC: 18:3e:ef:d7:33:38
    frame length: 42 bytes
    src IP: 192.168.1.1
    dst IP: 192.168.1.100
    info: ARP
    
    0x0000: 18 3e ef d7 33 38 0c 80 63 ea c7 42 08 06 00 01  .>..38..c..B....
    0x0010: 08 00 06 04 00 02 0c 80 63 ea c7 42 c0 a8 01 01  ........c..B....
    0x0020: 18 3e ef d7 33 38 c0 a8 01 64                    .>..38...d
    ```
   
3. **Testing ICPMv6 with NDP protocol.**
    **Command:**
    ```bash
    ./ipk-sniffer -i en0 --icmp6 -n 3
    ```
   **Expected Output:**
   The sniffer should capture a total of 3 packets that are ICMPv6 echo request/response.
    
    **Output:**
    ```
    timestamp: 2024-04-22T18:58:14.659+02:00
    src MAC: 18:3e:ef:d7:33:38
    dst MAC: 22:fa:9b:50:42:72
    frame length: 86 bytes
    src IP: fe80::4bc:5e80:bf76:a6cd
    dst IP: fe80::1cbc:7e1:97c:697c
    info: ICMPv6:
    
    0x0000: 22 fa 9b 50 42 72 18 3e ef d7 33 38 86 dd 60 00  "..PBr.>..38..`.
    0x0010: 00 00 00 20 3a ff fe 80 00 00 00 00 00 00 04 bc  ... :...........
    0x0020: 5e 80 bf 76 a6 cd fe 80 00 00 00 00 00 00 1c bc  ^..v............
    0x0030: 07 e1 09 7c 69 7c 87 00 48 27 00 00 00 00 fe 80  ...|i|..H'......
    0x0040: 00 00 00 00 00 00 1c bc 07 e1 09 7c 69 7c 01 01  ...........|i|..
    0x0050: 18 3e ef d7 33 38                                .>..38
    
    timestamp: 2024-04-22T18:58:14.707+02:00
    src MAC: 22:fa:9b:50:42:72
    dst MAC: 18:3e:ef:d7:33:38
    frame length: 78 bytes
    src IP: fe80::1cbc:7e1:97c:697c
    dst IP: fe80::4bc:5e80:bf76:a6cd
    info: ICMPv6:
    
    0x0000: 18 3e ef d7 33 38 22 fa 9b 50 42 72 86 dd 60 00  .>..38"..PBr..`.
    0x0010: 00 00 00 18 3a ff fe 80 00 00 00 00 00 00 1c bc  ....:...........
    0x0020: 07 e1 09 7c 69 7c fe 80 00 00 00 00 00 00 04 bc  ...|i|..........
    0x0030: 5e 80 bf 76 a6 cd 88 00 43 7e 40 00 00 00 fe 80  ^..v....C~@.....
    0x0040: 00 00 00 00 00 00 1c bc 07 e1 09 7c 69 7c        ...........|i|
    
    timestamp: 2024-04-22T18:58:14.751+02:00
    src MAC: 22:fa:9b:50:42:72
    dst MAC: 18:3e:ef:d7:33:38
    frame length: 86 bytes
    src IP: fe80::1cbc:7e1:97c:697c
    dst IP: fe80::4bc:5e80:bf76:a6cd
    info: ICMPv6:
    
    0x0000: 18 3e ef d7 33 38 22 fa 9b 50 42 72 86 dd 60 00  .>..38"..PBr..`.
    0x0010: 00 00 00 20 3a ff fe 80 00 00 00 00 00 00 1c bc  ... :...........
    0x0020: 07 e1 09 7c 69 7c fe 80 00 00 00 00 00 00 04 bc  ...|i|..........
    0x0030: 5e 80 bf 76 a6 cd 87 00 50 cd 00 00 00 00 fe 80  ^..v....P.......
    0x0040: 00 00 00 00 00 00 04 bc 5e 80 bf 76 a6 cd 01 01  ........^..v....
    0x0050: 22 fa 9b 50 42 72                                "..PBr
    ```
   
## Extra functionality

My sniffer has the following extra functionality:
- **Writing extra information about the packet that was captured.**

    **Example:**
    ```
    info: ICMPv6:
    ```
- **Writes help message if user enters --help or -h argument.**

## Bibliography

- [Programming with PCAP](https://www.tcpdump.org/pcap.html)
- [getopt_long(3) - Linux man page](https://linux.die.net/man/3/getopt_long)
- [tshark(1) - Linux man page](https://linux.die.net/man/1/tshark#:~:text=TShark%20is%20a%20network%20protocol,the%20packets%20to%20a%20file.)

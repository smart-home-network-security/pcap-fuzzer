# pcap-fuzzer

[PyPI package page](https://pypi.org/project/pcap-fuzzer/)

This program randomly edits packets from a PCAP file,
one field per edited packet.

The edited field will be chosen at random,
starting from the highest layer, and going down until it finds a supported protocol layer.

Example: a DNS packet will have one of its DNS fields edited,
and not one of the UDP or IP fields.


## Installation

```bash
pip install pcap-fuzzer
```

## Usage

Import statement:
```python
import pcap_fuzzer
```

`fuzz_pcaps` function doc:
```python
pcap_fuzzer.fuzz_pcaps(
    pcaps: Union[str, list]       # (List of) input PCAP files
    output: str,                  # [Optional] Output PCAP file path. Used only if a single input file is specified.
    random_range: int = 1,        # [Optional] Upper bound for random range (not included). Defaults to 1.
    packet_numbers: list = None,  # [Optional] List of indices, starting from 1, of packets to edit. If not specified, packets are randomly picked.
    dry_run: bool = False         # [Optional] If True, do not write output PCAP file(s).
) -> None
```

This function produces new, edited PCAP file(s).
If no output file is specified (for a single input file),
or if multiple input files are given,
the output file(s) will have the same name as the input file(s),
but with the suffix `.edit`,
and will be placed in a directory called `edited`,
in the same directory as the input files.
It will be created if it doesn't exist.

The program also produces CSV log files,
indicating which fields were edited for each packet.
The log files will be placed in a directory called `logs`,
in the same directory as the input files.
It will be created if it doesn't exist.


## Supported protocols (for now)

* Datalink Layer (2)
  * ARP
* Network Layer (3)
  * IPv4
  * IPv6
* Transport Layer (4)
  * TCP
  * UDP
  * ICMP
  * IGMP(v2 and v3)
* Application Layer (7)
  * HTTP
  * DNS
  * DHCP
  * SSDP
  * CoAP

import argparse
import logging
from .arg_types import strictly_positive_int
from .pcap_fuzzer import fuzz_pcaps


### MAIN FUNCTION ###
def main() -> None:

    ### ARGUMENT PARSING ###
    parser = argparse.ArgumentParser(
        prog="pcap-fuzzer",
        description="Randomly edit packet fields in a PCAP file."
    )
    # Positional arguments: input PCAP file(s)
    parser.add_argument("input_pcaps", metavar="pcap", type=str, nargs="+", help="Input PCAP file(s).")
    # Optional flag: -o / --output
    parser.add_argument("-o", "--output", type=str, default=None, help="Output PCAP (and CSV) file path. Used only if a single input file is specified. Default: edited/<input_pcap>.edit.pcap")
    # Optional flag: -r / --random-range
    parser.add_argument("-r", "--random-range", type=strictly_positive_int, default=1,
                        help="Upper bound for random range (not included). Must be a strictly positive integer. Default: 1 (edit each packet).")
    # Optional flag: -n / --packet-number
    parser.add_argument("-n", "--packet-number", type=int, action="append",
                        help="Index of the packet to edit, starting form 1. Can be specifed multiple times.")
    # Optional flag: -d / --dry-run
    parser.add_argument("-d", "--dry-run", action="store_true",
                        help="Dry run: do not write output PCAP file.")
    # Parse arguments
    args = parser.parse_args()
    # Verify arguments
    if args.output is not None and len(args.input_pcaps) > 1:
        logging.warning("Multiple input PCAP files specified, ignoring output PCAP file name.")


    ## Start fuzzing PCAP files
    fuzz_pcaps(
        pcaps=args.input_pcaps,
        output=args.output,
        random_range=args.random_range,
        packet_numbers=args.packet_number,
        dry_run=args.dry_run
    )


### ENTRY POINT ###
if __name__ == "__main__":
    main()

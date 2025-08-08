# Imports
import os
from pathlib import Path
import glob
import pcap_fuzzer


### MAIN ###
if __name__ == "__main__":

    # Get paths
    self_path = Path(os.path.abspath(__file__))
    base_dir = self_path.parents[1]
    traces_dir = os.path.join(base_dir, "traces")

    # Get all PCAP files
    all_pcaps = glob.glob(f"{traces_dir}/*.pcap")

    # Run PCAP fuzzer on all PCAP files
    pcap_fuzzer.fuzz_pcaps(all_pcaps)

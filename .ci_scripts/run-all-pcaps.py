#!/bin/python3

# Imports
import os
import glob
import pcap_fuzzer


### MAIN ###
if __name__ == "__main__":

    # Get paths
    workspace_path = os.environ["GITHUB_WORKSPACE"]
    traces_dir = os.path.join(workspace_path, "traces")

    # Get all PCAP files
    all_pcaps = glob.glob(f"{traces_dir}/*.pcap")

    # Run PCAP fuzzer on all PCAP files
    pcap_fuzzer.fuzz_pcaps(all_pcaps)

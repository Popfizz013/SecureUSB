#!/usr/bin/env python3
# src/cli_demo.py
import argparse
import time
from tqdm import tqdm

def do_work(n):
    for _ in tqdm(range(n), desc="dummy work"):
        time.sleep(0.05)

def main():
    parser = argparse.ArgumentParser(prog="secure-usb-cli", description="CLI demo for hackathon")
    parser.add_argument("--status", action="store_true", help="print status")
    parser.add_argument("--work", type=int, default=20, help="run dummy work loop")
    args = parser.parse_args()
    if args.status:
        print("Status: CLI OK — environment set up")
    else:
        print("Starting dummy operation...")
        do_work(args.work)
        print("Done.")

if __name__ == "__main__":
    main()

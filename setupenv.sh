#!/bin/bash
# Create a virtual environment 
python3 -m venv venv 

# Activate the virtual environment
source venv/bin/activate 

# Install required packages 
pip3 install prettytable
pip3 install scapy
pip3 install boto3 
pip3 install pyyaml




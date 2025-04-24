import scapy.all as scapy
import nmap
import requests
from selenium import webdriver
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import subprocess
import logging
import hashlib
import time
import re
import sys
import os

# Configure logging
logging.basicConfig(filename='penetration_tool.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to validate IP address format
def validate_ip(ip):
    pattern = re.compile(r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                         r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                         r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                         r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    return re.match(pattern, ip) is not None

# Function to validate input as a non-empty string
def validate_non_empty(input_str):
    return len(input_str.strip()) > 0

# Function to scan the network for live hosts
def network_scan(target_ip):
    if not validate_ip(target_ip):
        logging.error(f"Invalid IP address format: {target_ip}")
        print("Invalid IP address format!")
        return

    logging.info(f"Starting network scan on IP: {target_ip}")
    print(f"Scanning network for active hosts in {target_ip}...")
    arp_request = scapy.ARP(pdst=target_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if len(answered_list) == 0:
        logging.warning(f"No live hosts found in {target_ip}")
        print("No live hosts found.")
    for element in answered_list:
        print(f"IP: {element[1].psrc}  MAC: {element[1].hwsrc}")
        logging.info(f"Found live host: IP: {element[1].psrc}  MAC: {element[1].hwsrc}")

# Function to scan open ports on a target
def port_scan(target_ip):
    if not validate_ip(target_ip):
        logging.error(f"Invalid IP address format: {target_ip}")
        print("Invalid IP address format!")
        return

    logging.info(f"Starting port scan on IP: {target_ip}")
    print(f"Scanning open ports on {target_ip}...")
    nm = nmap.PortScanner()
    nm.scan(target_ip, '1-1024')  # Scans ports from 1 to 1024
    open_ports = []
    for port in nm[target_ip]['tcp']:
        open_ports.append(port)
        print(f"Port {port} is open")
        logging.info(f"Port {port} is open on {target_ip}")

    if not open_ports:
        logging.warning(f"No open ports found on {target_ip}")
        print("No open ports found.")

# Function to securely encrypt data using AES
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(data.ljust(32))  # Encrypts with padding
    return cipher.iv + ct_bytes

# Function to decrypt data securely using AES
def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:16]  # IV is the first 16 bytes
    ct = encrypted_data[16:]  # The remaining bytes are the cipher text
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    return pt.strip()

# Function to perform brute-force login attempt on a website
def brute_force_login(target_url, username, password_list):
    if not validate_non_empty(target_url):
        logging.error("Invalid URL provided for brute-force login attempt.")
        print("Invalid URL provided!")
        return

    if not validate_non_empty(username):
        logging.error("Invalid username provided.")
        print("Invalid username provided!")
        return

    logging.info(f"Starting brute-force login on {target_url} for username: {username}")
    for password in password_list:
        data = {'username': username, 'password': password}
        try:
            response = requests.post(target_url, data=data, timeout=5)
            if response.status_code == 200 and "Login successful" in response.text:
                logging.info(f"Login successful with username: {username} and password: {password}")
                print(f"Login successful with username: {username} and password: {password}")
                break
        except requests.exceptions.RequestException as e:
            logging.error(f"Error during brute-force attempt: {e}")
            print(f"Error: {e}")
            break

# Function to run Hydra brute-force for SSH
def hydra_brute_force(ip, username, password_list):
    if not validate_ip(ip):
        logging.error(f"Invalid IP address format for Hydra brute-force: {ip}")
        print("Invalid IP address format!")
        return

    if not validate_non_empty(username):
        logging.error("Invalid username provided for Hydra.")
        print("Invalid username provided!")
        return

    logging.info(f"Running Hydra brute-force SSH attack on {ip}...")
    for password in password_list:
        command = f"hydra -l {username} -p {password} ssh://{ip}"
        try:
            subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Hydra failed: {e}")
            print(f"Error: {e}")

# Main function
def main():
    print("Welcome to the Secure Python Penetration Testing Tool")
    print("Choose an option to proceed:")
    print("1. Network Scan")
    print("2. Port Scan")
    print("3. Brute-Force Web Login")
    print("4. AES Encryption/Decryption")
    print("5. Hydra Brute Force SSH")

    choice = input("Enter the number corresponding to your choice: ")

    if choice == '1':
        target_ip = input("Enter target IP address (e.g., 192.168.1.1/24): ")
        network_scan(target_ip)
    
    elif choice == '2':
        target_ip = input("Enter target IP address: ")
        port_scan(target_ip)
    
    elif choice == '3':
        target_url = input("Enter the target URL (login page): ")
        username = input("Enter the username: ")
        password_list = input("Enter the password list (comma-separated): ").split(",")
        brute_force_login(target_url, username, password_list)
    
    elif choice == '4':
        data = input("Enter the data to encrypt (max 32 bytes): ").encode('utf-8')
        key = get_random_bytes(16)  # AES key
        encrypted_data = encrypt_data(data, key)
        print(f"Encrypted data: {encrypted_data}")
        decrypted_data = decrypt_data(encrypted_data, key)
        print(f"Decrypted data: {decrypted_data.decode('utf-8')}")
    
    elif choice == '5':
        ip = input("Enter target IP address: ")
        username = input("Enter username: ")
        password_list = input("Enter the password list (comma-separated): ").split(",")
        hydra_brute_force(ip, username, password_list)

if __name__ == '__main__':
    main()

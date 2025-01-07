import requests
import getpass
from getpass import getpass
import paramiko
import time
import threading
import json
import re
import urllib3
from concurrent.futures import ThreadPoolExecutor
import os
from dotenv import load_dotenv
import atexit
import sys
from datetime import datetime


# Load environment variables
load_dotenv()

# Global variables
device_info = []
created_sessions = []

# Get API version from environment variable, default to v10.13 if not set
api_version = os.getenv('API_VERSION', 'v10.13')
ip_addresses = os.getenv('IP_ADDRESSES')
username = os.getenv('USERNAME')
password = os.getenv('PASSWORD')

# Disable HTTPS untrusted warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Color definition
BLINK = '\033[5m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
WHITE = '\033[97m'
RESET = '\033[0m'

# # Override input
# ip_addresses = "10.9.23.246, 10.9.23.247"
# username = "admin"
# password = "admin"

def show_help():
    """Display help information about the script"""
    help_text = f"""
{CYAN}PCAP Collection Script for Aruba CX Switches{RESET}

This script allows you to capture network traffic on Aruba CX switches using either CPU mirroring or ERSPAN.

{YELLOW}Configuration:{RESET}
The following parameters can be configured in a .env file:
  IP_ADDRESSES  : Comma-separated list of switch IP addresses
  USERNAME      : Switch login username
  PASSWORD      : Switch login password
  API_VERSION   : API version to use (defaults to v10.13)

{YELLOW}Capture Methods:{RESET}
1. CPU Mirror
   - Mirrors traffic directly to switch CPU
   - Captures packets locally on each switch
   - Supports packet count or duration-based captures
   - {RED}Warning: Use with caution in production environments{RESET}
   - Files can be exported via SCP or SFTP after capture

2. ERSPAN (Recommended for Production)
   - Encapsulates mirrored traffic in GRE
   - Sends traffic to a remote capture device
   - Requires destination device running Wireshark or similar
   - Safer for production use
   - Supports source IP configuration per switch
   - Configurable capture duration

{YELLOW}Capture Options:{RESET}
- Packet Count (e.g., "100p") : Capture specific number of packets
- Duration (e.g., "10s")      : Capture for specified duration in seconds

{YELLOW}Export Methods:{RESET}
- SCP  : Secure Copy Protocol transfer
- SFTP : SSH File Transfer Protocol

{YELLOW}Additional Features:{RESET}
- Mirror session reuse capability
- Automatic cleanup of mirror sessions
- Support for multiple switches in parallel
- VRF support for ERSPAN traffic
- Interface selection per switch
- Progress indicators and status messages

{YELLOW}Usage Examples:{RESET}
1. CPU Mirror with packet count:
   - Select CPU mirror
   - Enter "100p" for capture size
   - Select interfaces to mirror
   - Choose export method after capture

2. ERSPAN with duration:
   - Select ERSPAN
   - Enter duration (e.g., "30s")
   - Configure destination and source IPs
   - Select interfaces to mirror
   - Monitor capture on destination device
"""
    print(help_text)

def login(host):
    ip = host["ip"]
    login_url = f"https://{ip}/rest/{api_version}/login"
    login_response = requests.post(
        login_url,
        params={"username": username, "password": password},
        headers={"accept": "*/*", "x-use-csrf-token": "true"},
        verify=False,
    )
    if login_response.status_code != 200:
        print(f"Error: Unable to log in to device {ip}. Please check your credentials and try again.")
        exit()
    return login_response

def handle_failed_upload():
    """Handle failed upload by asking user what to do next"""
    while True:
        choice = input(f"\n{YELLOW}Upload failed. Choose an option:\n1. Retry upload\n0. Exit script (clean up created sessions)\n{RESET}")
        if choice in ['0', '1']:
            return choice
        print(f"{YELLOW}Invalid choice. Please try again.{RESET}")

def handle_post_upload():
    """Handle options after capture completion"""
    while True:
        choice = input(f"\n{CYAN}Choose an option:\n1. Rerun script with new parameters\n2. Rerun same capture\n3. Exit script (clean up created sessions)\n{RESET}")
        if choice == "1":
            print(f"\n{GREEN}Restarting script...{RESET}\n")
            return "rerun_new"
        elif choice == "2":
            print(f"\n{GREEN}Rerunning same capture...{RESET}\n")
            return "rerun_same"
        elif choice == "3":
            print(f"\n{GREEN}Exiting script...{RESET}")
            return "exit"
        else:
            print(f"{YELLOW}Invalid choice. Please try again.{RESET}")

def disable_all_mirror_sessions(devices, keep_configuration=False):
    """Disable all active mirror sessions across devices"""
    print(f"\n{YELLOW}Disabling mirror sessions...{RESET}")
    for device in devices:
        ip = device["ip"]
        # Get current mirror sessions
        mirror_response, mirror_sessions = get_mirror_sessions(device)
        if mirror_sessions:
            for session_id, session in mirror_sessions.items():
                if session["mirror_status"].get("operation_state") == "enabled":
                    if disable_mirror_session(ip, device["headers"], device["cookies"], session_id):
                        print(f"{GREEN}Disabled mirror session {session_id} on device {ip}{RESET}")
                        if not keep_configuration:
                            # Only clear tracked session if we're not keeping configuration
                            track_last_session(ip, None)

def reactivate_mirror_session(ip, headers, cookies, session_id, config=None):
    """Reactivate an existing mirror session with full configuration"""
    api_url = f"https://{ip}/rest/{api_version}/system/mirrors/{session_id}"
  
    # Get existing configuration first
    response = requests.get(api_url, headers=headers, cookies=cookies, verify=False)
    if response.status_code != 200:
        return False
      
    existing_config = response.json()
  
    if config:  # ERSPAN case
        def format_interface(port):
            port = port.strip()
            if port.lower().startswith('lag'):
                return port
            if '/' in port:
                return port.replace('/', '_')
            return port

        formatted_ports = [format_interface(port) for port in config["ports"]]
      
        data = {
            "active": True,
            "comment": None,
            "output_port": None,
            "select_dst_port": {port: f"/rest/{api_version}/system/interfaces/{port}" for port in formatted_ports},
            "select_src_port": {port: f"/rest/{api_version}/system/interfaces/{port}" for port in formatted_ports},
            "session_type": "tunnel",
            "tunnel": config["tunnel_config"],
            "tunnel_vrf": config["tunnel_vrf"]
        }
    else:  # CPU case
        data = {
            "active": True,
            "comment": existing_config.get("comment"),
            "output_port": existing_config.get("output_port"),
            "select_dst_port": existing_config.get("select_dst_port", {}),
            "select_src_port": existing_config.get("select_src_port", {}),
            "session_type": "cpu",
            "tunnel": {"dscp": 0},
            "tunnel_vrf": None
        }

    response = requests.put(api_url, headers=headers, cookies=cookies, json=data, verify=False)
    if response.status_code == 200:
        print(f"{GREEN}Successfully reactivated mirror session {session_id} on device {ip}{RESET}")
        return True
    else:
        print(f"{RED}Failed to reactivate mirror session {session_id} on device {ip}. Status code: {response.status_code}{RESET}")
        return False

def track_last_session(ip, session_id):
    """Track the last used session ID for each device"""
    if not hasattr(track_last_session, 'sessions'):
        track_last_session.sessions = {}
    track_last_session.sessions[ip] = session_id

def get_last_session(ip):
    """Get the last used session ID for a device"""
    if hasattr(track_last_session, 'sessions') and ip in track_last_session.sessions:
        return track_last_session.sessions[ip]
    return None

def handle_exports():
    while True:
        export_method = input("Export files?\n1. SCP\n2. SFTP\n0. Exit script (clean up created sessions)\n")  
        # Modified to include IP in export_info
        export_info = [(local_file, ssh, ip) for ip, _, _, _, local_file, _, ssh in device_info]
      
        if export_method == "1":  
            remote_hostname, remote_username, remote_password, remote_directory, vrf = get_export_info()    
            all_successful = True
            # Include ip in the for loop
            for local_file, ssh, device_ip in export_info:    
                remote_file_path = f"{remote_directory}/{local_file}" if remote_directory else local_file    
                print(f"Executing SCP command on {device_ip}: copy tcpdump-pcap {local_file} scp://{remote_username}@{remote_hostname}/{remote_file_path} vrf {vrf}")    
                if not export_pcap_scp(remote_hostname, ssh, local_file, remote_file_path, remote_username, remote_password, vrf):
                    all_successful = False
                    choice = handle_failed_upload()
                    if choice == '1':
                        break  # Break inner loop to retry from export menu
                    else:
                        return "exit"  # Exit completely
          
            if all_successful:
                return handle_post_upload()  # Return rerun/exit choice
          
        elif export_method == "2":
            export_details = get_export_info()
            if export_details[0] is None:  # If verification failed and user chose not to retry
                continue
              
            remote_hostname, remote_username, remote_password, remote_directory, vrf = export_details
            all_successful = True
            # Include ip in the for loop
            for local_file, ssh, device_ip in export_info:
                remote_file_path = f"{remote_directory}/{local_file}" if remote_directory else local_file
                print(f"Executing SFTP command on {device_ip}: copy tcpdump-pcap {local_file} sftp://{remote_username}@{remote_hostname}/{remote_file_path} vrf {vrf}")
                if not export_pcap_sftp(remote_hostname, ssh, local_file, remote_file_path, remote_username, remote_password, vrf):
                    all_successful = False
                    choice = handle_failed_upload()
                    if choice == '1':
                        break  # Break inner loop to retry from export menu
                    else:
                        return "exit"  # Exit completely
          
            if all_successful:
                return handle_post_upload()  # Return rerun/exit choice

        elif export_method == "0":
            return "exit"
        else:
            print(f"{YELLOW}Please try again.{RESET}")

def export_pcap_scp(remote_hostname, ssh, local_file, remote_file, remote_username, remote_password, vrf):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    remote_file_with_timestamp = f"{os.path.splitext(remote_file)[0]}_{timestamp}{os.path.splitext(remote_file)[1]}"
  
    copy_command = f"copy tcpdump-pcap {local_file} scp://{remote_username}@{remote_hostname}/{remote_file_with_timestamp}"
    if vrf:
        copy_command += f" vrf {vrf}"

    shell = ssh.invoke_shell()
    shell.send(copy_command + "\n")

    output = ""
    success = False
    password_sent = False
    while not success:
        if shell.recv_ready():
            new_output = shell.recv(1024).decode()
            if not new_output:
                break
            output += new_output
            print(new_output, end="")  # Print the CLI output

            if "password:" in output.lower() and not password_sent:
                shell.send(remote_password + "\n")
                password_sent = True
                time.sleep(1)
            elif "Are you sure you want to continue connecting" in output:
                shell.send("yes\n")
            elif "Copied successfully." in output:
                success = True
                break
            elif "Error" in output:
                success = False
                break
        else:
            time.sleep(0.1)

    if success:
        print(f"{GREEN}Exported {local_file} to {remote_hostname}:{remote_file} using SCP.{RESET}")
    else:
        print(f"{RED}Error during export of {local_file} to {remote_hostname}:{remote_file}.{RESET}")

    shell.close()
    return success

def verify_sftp_credentials(hostname, username, password, vrf):
    """Verify SFTP credentials before attempting transfers"""
    try:
        # Create a temporary SSH client for verification
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=username, password=password, timeout=10)
        ssh.close()
        return True
    except paramiko.AuthenticationException:
        print(f"{RED}Authentication failed. Please check username and password.{RESET}")
        return False
    except paramiko.SSHException as e:
        print(f"{RED}SSH error: {str(e)}{RESET}")
        return False
    except Exception as e:
        print(f"{RED}Connection error: {str(e)}{RESET}")
        return False

def export_pcap_sftp(remote_hostname, ssh, local_file, remote_file, remote_username, remote_password, vrf):
    # First verify the credentials
    if not verify_sftp_credentials(remote_hostname, remote_username, remote_password, vrf):
        return False

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    remote_file_with_timestamp = f"{os.path.splitext(remote_file)[0]}_{timestamp}{os.path.splitext(remote_file)[1]}"
  
    copy_command = f"copy tcpdump-pcap {local_file} sftp://{remote_username}@{remote_hostname}/{remote_file_with_timestamp}"
    if vrf:
        copy_command += f" vrf {vrf}"

    shell = ssh.invoke_shell()
    shell.send(copy_command + "\n")

    output = ""
    success = False
    password_sent = False
    max_attempts = 3  # Maximum number of attempts to handle the transfer
    attempts = 0
    timeout = time.time() + 60  # 60 second timeout

    while not success and attempts < max_attempts and time.time() < timeout:
        if shell.recv_ready():
            new_output = shell.recv(1024).decode()
            if not new_output:
                break
            output += new_output
            print(new_output, end="")  # Print the CLI output

            if "password:" in output.lower() and not password_sent:
                shell.send(remote_password + "\n")
                password_sent = True
                time.sleep(1)
            elif "Are you sure you want to continue connecting" in output:
                shell.send("yes\n")
            elif "Copied successfully." in output:
                success = True
                break
            elif "Error" in output or "Permission denied" in output:
                print(f"{RED}Error during file transfer: {output}{RESET}")
                success = False
                break
            elif "Invalid input:" in output:
                print(f"{RED}Transfer failed or timed out{RESET}")
                success = False
                break

        else:
            time.sleep(0.1)
            attempts += 1

    shell.close()

    if success:
        print(f"{GREEN}Exported {local_file} to {remote_hostname}:{remote_file} using SFTP.{RESET}")
        return True
    else:
        print(f"{RED}Failed to export {local_file} to {remote_hostname}:{remote_file}.{RESET}")
        return False
 
 
def get_export_info():
    while True:
        remote_hostname = input("Enter the remote hostname or IP address: ")
        remote_username = input("Enter the remote username: ")
        remote_password = getpass("Enter the remote password: ")
        remote_directory = input("Enter the remote directory (e.g. /home/user/pcaps) or leave empty: ")
        vrf = input("Enter the VRF (e.g. mgmt) or leave empty: ")

        # Verify credentials before returning
        if verify_sftp_credentials(remote_hostname, remote_username, remote_password, vrf):
            return remote_hostname, remote_username, remote_password, remote_directory, vrf
    
        retry = input(f"{YELLOW}Would you like to try again? (y/n): {RESET}").lower()
        if retry != 'y':
            return None, None, None, None, None

def get_mirror_sessions(device):
    ip, headers, cookies = device["ip"], device["headers"], device["cookies"]
    api_url_mirrors = f"https://{ip}/rest/v10.13/system/mirrors?attributes=&depth=2"
    response_mirrors = requests.get(api_url_mirrors, headers=headers, cookies=cookies, verify=False)
    if response_mirrors.status_code == 200:
        return ip, response_mirrors.json()
    else:
        print(f"Error: Unable to get mirror sessions for device {ip}. Status code: {response_mirrors.status_code}, Response: {response_mirrors.text}")
    return ip, None

def get_unused_mirror_sessions(mirror_sessions):
    used_ids = [int(session_id) for session_id in mirror_sessions.keys()]
    for session_id in range(1, 5):
        if session_id not in used_ids:
            return session_id
    return 4

def disable_mirror_session(ip, headers, cookies, session_id):
    data = {"active": False}
    api_url_disable = f"https://{ip}/rest/v10.13/system/mirrors/{session_id}"
    response_disable = requests.put(api_url_disable, headers=headers, cookies=cookies, json=data, verify=False)
    if response_disable.status_code == 200:
        return True
    else:
        print(f"Error: Unable to disable mirror session {session_id} for device {ip}. Status code: {response_disable.status_code}, Response: {response_disable.text}")
        return False

def create_empty_mirror_session(ip, headers, cookies, session_id):
    api_url_create = f"https://{ip}/rest/v10.13/system/mirrors"
    data = {"id": session_id}
    response_create = requests.post(api_url_create, headers=headers, cookies=cookies, json=data, verify=False)

    if response_create.status_code == 201:
        print(f"{GREEN}Successfully created an empty mirror session with ID {session_id} on device {ip}{RESET}")
    else:
        print(f"Error: Unable to create an empty mirror session with ID {session_id} for device {ip}. Status code: {response_create.status_code}, Response: {response_create.text}")

def cleanup_mirror_sessions():
    """Clean up all mirror sessions created during script execution"""
    print(f"\n{YELLOW}Cleaning up mirror sessions...{RESET}")
    for device_ip, session_id, headers, cookies in created_sessions:
        try:
            # First disable the session
            disable_url = f"https://{device_ip}/rest/{api_version}/system/mirrors/{session_id}"
            disable_data = {"active": False}
            response = requests.put(disable_url, headers=headers, cookies=cookies, json=disable_data, verify=False)
        
            if response.status_code == 200:
                # Then delete the session
                delete_url = f"https://{device_ip}/rest/{api_version}/system/mirrors/{session_id}"
                response = requests.delete(delete_url, headers=headers, cookies=cookies, verify=False)
            
                if response.status_code == 204:
                    print(f"{GREEN}Successfully deleted mirror session {session_id} on device {device_ip}{RESET}")
                else:
                    print(f"{RED}Failed to delete mirror session {session_id} on device {device_ip}. Status code: {response.status_code}{RESET}")
            else:
                print(f"{RED}Failed to disable mirror session {session_id} on device {device_ip}. Status code: {response.status_code}{RESET}")
        except Exception as e:
            print(f"{RED}Error cleaning up mirror session {session_id} on device {device_ip}: {str(e)}{RESET}")

# Register the cleanup function to run on script exit
atexit.register(cleanup_mirror_sessions)

def get_capture_method():
    """Get the packet capture method from user"""
    while True:
        print(f"\n{CYAN}Select packet capture method:{RESET}")
        print("1. CPU (Mirror to CPU - Use with caution in production)")
        print("2. ERSPAN (GRE encapsulated remote mirroring - Recommended for production)")
        print("0. Exit script")
      
        choice = input(f"\nEnter your choice: ")
      
        if choice == "1":
            return "cpu"
        elif choice == "2":
            return "tunnel"
        elif choice == "0":
            sys.exit(0)
        else:
            print(f"{YELLOW}Invalid choice. Please try again.{RESET}")

def get_erspan_setup(devices):
    """Get all ERSPAN and interface configurations upfront"""
    configs = {}
  
    # Get common ERSPAN settings
    dest_ip = input(f"{CYAN}Enter destination IP address for ERSPAN: {RESET}")
    vrf = input(f"{CYAN}Enter VRF name for ERSPAN (optional, press Enter to skip): {RESET}")
  
    # Handle duration input with possible 's' suffix
    while True:
        duration_input = input(f"{CYAN}Enter capture duration in seconds: {RESET}")
        # Remove 's' suffix if present
        duration_str = duration_input.rstrip('s')
        try:
            duration = int(duration_str)
            break
        except ValueError:
            print(f"{YELLOW}Please enter a valid number of seconds{RESET}")
  
    # Get per-switch configurations
    for device in devices:
        hostname = ssh_show_hostname(device["ip"], username, password)
        # Get source IP for this switch
        src_ip = input(f"{CYAN}Enter source IP address for ERSPAN for {hostname}: {RESET}")
        # Get interfaces for this switch
        dst_ports_input = input(f"{CYAN}Enter the interface(s) to capture for {hostname} (comma separated, e.g. 1/1/X, lag10): {RESET}")
        dst_ports = [port.strip() for port in dst_ports_input.split(",")]
      
        configs[device["ip"]] = {
            "tunnel_config": {
                "dest_ip_address": dest_ip,
                "src_ip_address": src_ip,
                "dscp": 0
            },
            "tunnel_vrf": vrf if vrf else None,
            "duration": duration,
            "ports": dst_ports
        }
  
    return configs

def modify_mirror_session(ip, headers, cookies, session_id, src_ports, dst_ports, session_type="cpu", tunnel_config=None, tunnel_vrf=None):
    api_url_check = f"https://{ip}/rest/{api_version}/system/mirrors/{session_id}"
    response_check = requests.get(api_url_check, headers=headers, cookies=cookies, verify=False)

    if response_check.status_code != 200:
        # Create a new mirror session with default values
        data = {
            "active": False,
            "comment": None,
            "output_port": None,
            "select_dst_port": {},
            "select_src_port": {},
            "session_type": session_type,
            "tunnel": tunnel_config if session_type == "tunnel" else {"dscp": 0},
            "tunnel_vrf": tunnel_vrf
        }
        response_create = requests.put(api_url_check, headers=headers, cookies=cookies, json=data, verify=False)
        if response_create.status_code != 200:
            print(f"Error: Unable to create mirror session {session_id} for device {ip}. Status code: {response_create.status_code}, Response: {response_create.text}")
            return False

    # Format the interface names correctly
    def format_interface(port):
        port = port.strip()
        if port.lower().startswith('lag'):
            return port
        if '/' in port:
            return port.replace('/', '_')
        return port

    formatted_src_ports = [format_interface(port) for port in src_ports]
    formatted_dst_ports = [format_interface(port) for port in dst_ports]

    # Modify the mirror session
    data = {
        "active": True,
        "comment": None,
        "output_port": None,
        "select_dst_port": {port: f"/rest/{api_version}/system/interfaces/{port}" for port in formatted_dst_ports},
        "select_src_port": {port: f"/rest/{api_version}/system/interfaces/{port}" for port in formatted_src_ports},
        "session_type": session_type,
        "tunnel": tunnel_config if session_type == "tunnel" else {"dscp": 0},
        "tunnel_vrf": tunnel_vrf
    }

    response_modify = requests.put(api_url_check, headers=headers, cookies=cookies, json=data, verify=False)

    if response_modify.status_code == 200:
        print(f"{GREEN}Successfully created mirror session {session_id} on device {ip}{RESET}")
        created_sessions.append((ip, session_id, headers, cookies))
        return True
    else:
        error_response = response_modify.text
        print(f"{RED}Error: Unable to create mirror session {session_id} for device {ip}. Status code: {response_modify.status_code}, Response: {error_response}{RESET}")
        return False

def ssh_show_hostname(ip, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password)
    stdin, stdout, stderr = ssh.exec_command("show hostname")
    hostname = stdout.read().decode().strip()
    ssh.close()
    return hostname

def stop_capture(shell):
    print("Stopping capture")
    shell.send("\x03\n")  # Send Ctrl+C followed by a newline

def ssh_capture_packets_wrapper(args):
    ip, hostname, username, password, packet_count = args
    hostname, local_file, packet_count, ssh = ssh_capture_packets(ip, hostname, username, password, packet_count)
    return hostname, local_file, packet_count, ssh

def ssh_capture_packets(ip, hostname, username, password, capture_packets):  
    local_file = f"{hostname}_{ip}.pcap"
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password)

        # Start an interactive shell
        shell = ssh.invoke_shell()

        # Run the 'diag' command
        shell.send("diag\n")
        time.sleep(1)  # Wait for the command to execute
        output = shell.recv(1024).decode()
        #print(f"Output of 'diag' command:\n{output}")

        # Run the 'diag utilities tcpdump' command
        tcpdump_command = f"diag utilities tcpdump command -c {capture_packets} -nt -v -w {hostname}_{ip}.pcap\n"
        shell.send(tcpdump_command)
        time.sleep(1)  # Wait for the command to execute

        # Continuously read the output until the success message is found
        success_message = "Ending traffic capture."

        while True:
            output = shell.recv(1024).decode()
            print(output, end="")

            if success_message in output:
                time.sleep(5)
                print(f"\n{GREEN}Finished Packet Capture on {hostname} - Goodbye{RESET}")
                break

        # Return the hostname and packet count
        return hostname, local_file, capture_packets, ssh

    except paramiko.SSHException as e:
        print(f"{RED}Error: {e}{RESET}")
        time.sleep(5)  # Wait for 5 seconds before retrying
    else:
        print(f"\n{RED}Failed to capture packets on {hostname} after {max_retries} retries.{RESET}")
    return hostname, 0

def ssh_capture_packets_time_based_wrapper(args):  
    ip, hostname, username, password, capture_duration = args  
    hostname, local_file, capture_duration, ssh = ssh_capture_packets_time_based(ip, hostname, username, password, capture_duration)  
    return hostname, local_file, capture_duration, ssh

def ssh_capture_packets_time_based(ip, hostname, username, password, capture_duration):
    local_file = f"{hostname}_{ip}.pcap"
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password)

        # Start an interactive shell
        shell = ssh.invoke_shell()

        # Run the 'diag' command
        shell.send("diag\n")
        time.sleep(1)  # Wait for the command to execute
        output = shell.recv(1024).decode()
        #print(f"Output of 'diag' command:\n{output}")

        # Run the 'diag utilities tcpdump' command without packet count limit
        tcpdump_command = f"diag utilities tcpdump command -nt -v -w {hostname}_{ip}.pcap\n"
        shell.send(tcpdump_command)
        time.sleep(1)  # Wait for the command to execute

        # Start a timer to stop the capture after capture_duration seconds
        timer = threading.Timer(capture_duration, stop_capture, [shell])
        timer.start()

        # Print a countdown
        for i in range(capture_duration, 0, -1):
            print(f"Time remaining: {i} second", end='\r')
            time.sleep(1)
        print()  # Print a newline to move to the next line after the countdown

        # Continuously read the output until the success message is found
        success_message = "Ending traffic capture."

        while True:
            output = shell.recv(1024).decode()
            print(output, end="")

            if success_message in output:
                time.sleep(5)
                print(f"\n{GREEN}Finished Packet Capture on {hostname} - Goodbye{RESET}")
                break
  
        # Return the hostname, local_file, capture_duration, and ssh session
        return hostname, local_file, capture_duration, ssh

    except paramiko.SSHException as e:  
        print(f"{RED}Error: {e}{RESET}")  
        time.sleep(5)  # Wait for 5 seconds before retrying  
    else:  
        print(f"\n{RED}Failed to capture packets on {hostname} after {max_retries} retries.{RESET}")  
    return hostname, local_file, capture_duration, ssh

def display_safety_warning():
    warning = f"""
{RED}!!! IMPORTANT SAFETY WARNING !!!{RESET}

This script mirrors traffic to the CPU of the switch for packet capture. 
Please be aware of the following risks:

1. {YELLOW}Mirroring high traffic volume to the CPU can cause switch performance issues or outages{RESET}
2. {YELLOW}In production environments or with high traffic volumes, use ERSPAN instead{RESET}
   ERSPAN (GRE encapsulated mirroring) sends traffic to a remote device running Wireshark or similar tools

{RED}Recommended Safety Measures:{RESET}
- Use packet count limits or short duration captures
- Monitor switch CPU during capture
- Consider using ERSPAN for production environments
- Test in lab environment first

Do you understand these risks and wish to continue? (yes/NO): """
  
    response = input(warning).lower()
    if response != 'yes':
        print(f"\n{YELLOW}Script aborted for safety reasons. Consider using ERSPAN instead.{RESET}")
        sys.exit(0)

def main():
  
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        show_help()
        sys.exit(0)
      
    saved_configs = None
    first_run = True
    next_action = None
    capture_packets = None  # Initialize at the start
    devices = []  # Initialize devices list
  
    while True:
        try:
            global device_info, ip_addresses, username, password
            device_info = []  # Reset device_info for each run
          
            if saved_configs is None or first_run:
                display_safety_warning()
              
                # Request parameters if not set in environment
                if not ip_addresses:
                    ip_addresses = input("Enter IP addresses (comma separated): ")
                if not username:
                    username = input("Enter username: ")
                if not password:
                    password = getpass("Enter password: ")

                ips = [ip.strip() for ip in ip_addresses.split(",")]

                # Login to devices and save API tokens
                devices = []  # Reset devices list
                for ip in ips:
                    device = {"ip": ip}
                    login_response = login(device)
                    device["headers"] = {"x-csrf-token": login_response.headers["x-csrf-token"]}
                    device["cookies"] = login_response.cookies
                    devices.append(device)

                # Get capture method
                session_type = get_capture_method()
              
                # Get capture parameters based on type
                if session_type == "cpu":
                    packet_input = input(f"{CYAN}Enter the amount of packets or duration in seconds of the dump (e.g. 100p or 10s): {RESET}")  
                    if packet_input[-1] == "p":  
                        packet_count = int(packet_input[:-1])  
                        capture_duration = None
                    else:  
                        duration_str = packet_input.rstrip('s')
                        capture_duration = int(duration_str)
                        packet_count = None
                    capture_packets = packet_count  # Set capture_packets here
                  
                    saved_configs = {
                        "type": "cpu",
                        "configs": {
                            "duration": capture_duration,
                            "packet_count": capture_packets
                        },
                        "devices": devices,
                        "session_type": session_type
                    }
                else:  # tunnel
                    erspan_configs = get_erspan_setup(devices)
                    capture_duration = next(iter(erspan_configs.values()))["duration"]
                    saved_configs = {
                        "type": "tunnel",
                        "configs": erspan_configs,
                        "devices": devices,
                        "session_type": session_type
                    }
                first_run = False
            else:
                # Reuse saved configurations
                session_type = saved_configs["session_type"]
                devices = saved_configs["devices"]
                if session_type == "tunnel":
                    erspan_configs = saved_configs["configs"]
                    capture_duration = next(iter(erspan_configs.values()))["duration"]
                else:  # CPU
                    capture_duration = saved_configs["configs"]["duration"]
                    capture_packets = saved_configs["configs"]["packet_count"]

            # Rest of your existing code...
            # Initialize results for mirror sessions
            with ThreadPoolExecutor() as executor:
                results = list(executor.map(get_mirror_sessions, devices))

            # Configure all switches
            config_successful = True
            for ip, mirror_sessions in results:
                if mirror_sessions is None:
                    print(f"Error: Unable to get mirror sessions for device {ip}.")
                    config_successful = False
                    continue

                device = next(d for d in devices if d["ip"] == ip)
                headers = device["headers"]
                cookies = device["cookies"]

                if not first_run and next_action == "rerun_same":
                    # Reuse existing session
                    last_session_id = get_last_session(ip)
                    if last_session_id:
                        if session_type == "tunnel":
                            if reactivate_mirror_session(ip, headers, cookies, last_session_id, erspan_configs[ip]):
                                print(f"{GREEN}ERSPAN mirror session reactivated on {ip}{RESET}")
                                continue
                        else:  # CPU
                            hostname = ssh_show_hostname(ip, username, password)
                            # For CPU capture, we don't need the full config reactivation
                            if reactivate_mirror_session(ip, headers, cookies, last_session_id, None):
                                device_info.append((ip, hostname, username, password, capture_packets))
                                continue
                    print(f"{YELLOW}Could not reactivate previous session, creating new one...{RESET}")

                # Create new session
                unused_session_id = get_unused_mirror_sessions(mirror_sessions)
                if unused_session_id is not None:
                    create_empty_mirror_session(device["ip"], headers, cookies, unused_session_id)
                  
                    if session_type == "tunnel":
                        config = erspan_configs[ip]
                        success = modify_mirror_session(
                            device["ip"], 
                            headers, 
                            cookies, 
                            unused_session_id, 
                            config["ports"], 
                            config["ports"],
                            session_type,
                            config["tunnel_config"],
                            config["tunnel_vrf"]
                        )
                        if success:
                            track_last_session(ip, unused_session_id)
                            print(f"{GREEN}ERSPAN mirror session configured successfully on {ip}{RESET}")
                        else:
                            config_successful = False
                    else:  # CPU capture
                        hostname = ssh_show_hostname(ip, username, password)
                        dst_ports_input = input(f"{CYAN}Enter the interface(s) to capture for {hostname} (comma separated, e.g. 1/1/X, lag10): {RESET}")
                        dst_ports = [port.strip() for port in dst_ports_input.split(",")]
                        success = modify_mirror_session(
                            device["ip"], 
                            headers, 
                            cookies, 
                            unused_session_id, 
                            dst_ports, 
                            dst_ports, 
                            "cpu"
                        )
                        if success:
                            track_last_session(ip, unused_session_id)
                            device_info.append((ip, hostname, username, password, capture_packets))
                        else:
                            config_successful = False

            # Handle captures based on type
            if config_successful:
                if session_type == "tunnel":
                    print(f"\n{GREEN}All ERSPAN mirror sessions configured successfully.{RESET}")
                    print(f"{YELLOW}Starting packet capture on destination device ({erspan_configs[ips[0]]['tunnel_config']['dest_ip_address']}).{RESET}")
                  
                    # Countdown timer
                    print(f"\n{CYAN}Capture in progress...{RESET}")
                    for i in range(capture_duration, 0, -1):
                        print(f"Time remaining: {i} seconds", end='\r')
                        time.sleep(1)
                    print("\n")
                    print(f"{GREEN}Capture completed.{RESET}")
                  
                    disable_all_mirror_sessions(devices, keep_configuration=True)
                    next_action = handle_post_upload()
                else:  # CPU capture
                    # Run packet captures in parallel
                    if device_info:
                        with ThreadPoolExecutor() as executor:
                            if capture_duration is not None:
                                device_info = [(ip, hostname, username, password, capture_duration) 
                                             for ip, hostname, username, password, *_ in device_info]
                                capture_results = list(executor.map(ssh_capture_packets_time_based_wrapper, device_info))
                            else:
                                capture_results = list(executor.map(ssh_capture_packets_wrapper, device_info))

                            # Update device_info with results
                            device_info = []
                            for hostname, local_file, count_or_duration, ssh in capture_results:
                                print(f"{hostname}: {count_or_duration} {'seconds' if capture_duration else 'packets'}")
                                device_info.append((ip, hostname, username, password, local_file, packet_count, ssh))

                        print(f"\n{GREEN}Packet capture completed.{RESET}")
                        disable_all_mirror_sessions(devices, keep_configuration=True)
                        next_action = handle_exports()
                if next_action == "exit":
                    break
                elif next_action == "rerun_new":
                    saved_configs = None
                    first_run = True
                # If rerun_same, just continue the loop

        except KeyboardInterrupt:
            print(f"\n{YELLOW}Script interrupted by user. Cleaning up...{RESET}")
            if 'devices' in locals():
                disable_all_mirror_sessions(devices)
            sys.exit(0)
        except Exception as e:
            print(f"\n{RED}An error occurred: {str(e)}{RESET}")
            if 'devices' in locals():
                disable_all_mirror_sessions(devices)
            sys.exit(1)

if __name__ == "__main__":
    main()
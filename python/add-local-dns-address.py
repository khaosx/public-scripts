import requests
import json
from urllib.parse import quote # For URL encoding the IP and domain
import argparse
import sys # To exit if arguments are missing

# --- Helper Functions ---

def get_pihole_session_id(base_url, password):
    """
    Authenticates with the Pi-hole v6 API and retrieves a session ID (SID).

    Args:
        base_url (str): The base URL of your Pi-hole (e.g., "http://pi.hole").
        password (str): The web interface password for your Pi-hole.

    Returns:
        str: The session ID (SID) if authentication is successful, None otherwise.
    """
    auth_endpoint = f"{base_url}/api/auth"
    payload = {"password": password}
    headers = {"Content-Type": "application/json"}

    print(f"Attempting to authenticate with Pi-hole at {auth_endpoint}...")
    try:
        response = requests.post(auth_endpoint, headers=headers, json=payload, timeout=10)
        response.raise_for_status()  # Raises an HTTPError for bad responses (4XX or 5XX)

        auth_data = response.json()
        sid = auth_data.get("session", {}).get("sid")

        if sid:
            print("✅ Authentication successful. Session ID obtained.")
            return sid
        else:
            print("❌ Authentication failed. SID not found in response.")
            print("   Response content:", auth_data)
            return None
    except requests.exceptions.Timeout:
        print(f"❌ Authentication error: The request to {auth_endpoint} timed out.")
        return None
    except requests.exceptions.HTTPError as http_err:
        print(f"❌ Authentication error: HTTP error occurred: {http_err}")
        print(f"   Response status code: {response.status_code}")
        try:
            print(f"   Response content: {response.json()}")
        except json.JSONDecodeError:
            print(f"   Response content: {response.text}")
        return None
    except requests.exceptions.RequestException as req_err:
        print(f"❌ Authentication error: An error occurred: {req_err}")
        return None
    except json.JSONDecodeError:
        print("❌ Authentication error: Could not decode JSON response from Pi-hole.")
        print(f"   Response text: {response.text}")
        return None

def verify_dns_record_exists(base_url, session_id, domain, ip_address):
    """
    Verifies if a specific custom DNS record exists in Pi-hole by fetching all records.

    Args:
        base_url (str): The base URL of your Pi-hole.
        session_id (str): The active session ID (SID) for authentication.
        domain (str): The domain name to check for.
        ip_address (str): The IP address to check for.

    Returns:
        bool: True if the record exists, False otherwise.
    """
    list_hosts_endpoint = f"{base_url}/api/config/dns/hosts"
    headers = {
        "X-FTL-SID": session_id,
        "Accept": "application/json"
    }
    expected_entry = f"{ip_address} {domain}"

    print(f"   Verifying record by fetching all hosts from {list_hosts_endpoint}...")
    try:
        response = requests.get(list_hosts_endpoint, headers=headers, timeout=15) # Timeout for verification
        response.raise_for_status()
        data = response.json()
        
        # Correctly path to the hosts list
        hosts_list = data.get("config", {}).get("dns", {}).get("hosts", [])

        if isinstance(hosts_list, list):
            if expected_entry in hosts_list:
                return True
        print(f"   Record '{expected_entry}' not found in current Pi-hole custom DNS records (or list format unexpected).")
        # print(f"   Current records: {data.get('hosts', 'N/A')}") # Optional: for debugging
        return False
            
    except requests.exceptions.Timeout:
        print(f"   ❌ Verification error: The request to {list_hosts_endpoint} timed out.")
        return False
    except requests.exceptions.HTTPError as http_err:
        print(f"   ❌ Verification error: HTTP error occurred: {http_err}. Response: {response.text}")
        return False
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        print(f"   ❌ Verification error: An error occurred: {e}")
        return False

def find_existing_record_for_domain(base_url, session_id, domain_to_check, debug_mode=False):
    """
    Checks if a domain already exists in Pi-hole's custom DNS records and returns its IP.

    Args:
        base_url (str): The base URL of your Pi-hole.
        session_id (str): The active session ID (SID) for authentication.
        domain_to_check (str): The domain name to look for.
        debug_mode (bool): If True, print detailed debugging information.

    Returns:
        tuple: (ip_address, domain_as_in_pihole) if a record is found.
               Returns a string like "ERROR_TIMEOUT" or "ERROR_REQUEST" on check failure.
               Returns None if the domain is not found and no error occurred.
    """
    # domain_to_check is the user's input (e.g., NEW_DOMAIN)
    list_hosts_endpoint = f"{base_url}/api/config/dns/hosts"
    headers = {
        "X-FTL-SID": session_id,
        "Accept": "application/json"
    }
    # This initial print is moved to the main loop for better context per server
    # print(f"   Checking for existing record for domain '{domain_to_check}' at {list_hosts_endpoint}...")
    
    clean_domain_to_check_input = domain_to_check.strip().lower()
    hostname_to_check_input = clean_domain_to_check_input.split('.', 1)[0]
    try:
        response = requests.get(list_hosts_endpoint, headers=headers, timeout=15)
        response.raise_for_status()
        data = response.json()

        if debug_mode:
            print(f"DEBUG: Full response from /api/config/dns/hosts: {json.dumps(data, indent=2)}") 

        # Correctly path to the hosts list
        hosts_list_from_config = data.get("config", {}).get("dns", {}).get("hosts", [])
        if debug_mode:
            print(f"DEBUG: Extracted hosts_list_from_config: {hosts_list_from_config}")
            print(f"DEBUG: Type of hosts_list_from_config: {type(hosts_list_from_config)}")

        if isinstance(hosts_list_from_config, list):
            if debug_mode:
                print(f"DEBUG: hosts_list_from_config is a list. Number of entries: {len(hosts_list_from_config)}")
            if not hosts_list_from_config:
                if debug_mode:
                    print("DEBUG: Pi-hole returned an empty 'hosts' list during pre-check.")
            for entry in hosts_list_from_config: # entry is "IP DOMAIN"
                if debug_mode:
                    print(f"DEBUG: Processing entry from Pi-hole list: '{entry}'")
                parts = entry.split(maxsplit=1)
                if len(parts) == 2:
                    ip_from_list_raw, domain_from_list_raw = parts
                    
                    if debug_mode:
                        print(f"DEBUG:   Parsed IP_raw: '{ip_from_list_raw}', Domain_raw: '{domain_from_list_raw}'")
                    clean_ip_from_list = ip_from_list_raw.strip()
                    actual_domain_from_pihole = domain_from_list_raw.strip() # Keep original case for return, but compare lowercase
                    clean_domain_from_pihole_lower = actual_domain_from_pihole.lower()
                    hostname_from_pihole_lower = clean_domain_from_pihole_lower.split('.', 1)[0]

                    if debug_mode:
                        print(f"DEBUG:   Cleaned IP: '{clean_ip_from_list}', Actual Pi-hole Domain: '{actual_domain_from_pihole}'")
                        print(f"DEBUG:   Lowercase Pi-hole Domain: '{clean_domain_from_pihole_lower}', Hostname part: '{hostname_from_pihole_lower}'")
                        print(f"DEBUG:   Input Domain (for check, clean, lower): '{clean_domain_to_check_input}', Input Hostname part: '{hostname_to_check_input}'")

                    # Match conditions:
                    # 1. Exact match (after cleaning and lowercasing)
                    # 2. Hostname parts match (after cleaning and lowercasing)
                    is_match = False
                    if clean_domain_from_pihole_lower == clean_domain_to_check_input:
                        if debug_mode: print("DEBUG:     Match 1 (FQDN) is TRUE")
                        is_match = True
                    elif hostname_from_pihole_lower == hostname_to_check_input:
                        if debug_mode: print("DEBUG:     Match 2 (Hostname) is TRUE")
                        is_match = True
                    else:
                        if debug_mode:
                            print("DEBUG:     Match 1 (FQDN) is FALSE")
                            print("DEBUG:     Match 2 (Hostname) is FALSE")
                    
                    if is_match:
                        print(f"   Found existing record: Pi-hole has '{actual_domain_from_pihole}' -> '{clean_ip_from_list}' (matched against input '{domain_to_check}')")
                        return clean_ip_from_list, actual_domain_from_pihole
        else:
            print("DEBUG: hosts_list_from_config is NOT a list. Skipping loop.")
            # The type was already printed above, so this specific line is redundant here now.
        return None # Domain not found and no error
            
    except requests.exceptions.Timeout:
        print(f"   ❌ Error checking existing records: The request to {list_hosts_endpoint} timed out.")
        # The data variable might not be defined if timeout happened before response.json()
        return "ERROR_TIMEOUT"
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        print(f"   ❌ Error checking existing records: An error occurred: {e}")
        return "ERROR_REQUEST"

def delete_local_dns_record(base_url, session_id, domain, ip_address):
    """
    Deletes a custom DNS record from Pi-hole v6 using the API.
    """
    encoded_entry = quote(f"{ip_address} {domain}")
    dns_record_endpoint = f"{base_url}/api/config/dns/hosts/{encoded_entry}"
    headers = {"X-FTL-SID": session_id, "Accept": "application/json"}

    print(f"   Attempting to delete DNS record: {domain} -> {ip_address} from {dns_record_endpoint}...")
    try:
        response = requests.delete(dns_record_endpoint, headers=headers, timeout=30)
        response.raise_for_status() 
        if response.status_code in [200, 204]:
            print(f"   ✅ Successfully deleted DNS record: {domain} -> {ip_address} (status: {response.status_code})")
            # Optionally print response.json() if status_code is 200 and content exists
            return True
        # Fallback, though raise_for_status should catch non-2xx
        print(f"   ⚠️ Failed to delete DNS record. Status: {response.status_code}, Response: {response.text}")
        return False
    except requests.exceptions.Timeout:
        print(f"   ❌ Error deleting DNS record: Request to {dns_record_endpoint} timed out.")
        return False
    except requests.exceptions.HTTPError as e:
        print(f"   ❌ Error deleting DNS record: HTTP error {e.response.status_code} for {dns_record_endpoint}. Response: {e.response.text}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Error deleting DNS record: Request exception for {dns_record_endpoint}: {e}")
        return False

def add_local_dns_record(base_url, session_id, domain, ip_address):
    """
    Adds a custom DNS record to Pi-hole v6 using the API.

    Args:
        base_url (str): The base URL of your Pi-hole.
        session_id (str): The active session ID (SID) for authentication.
        domain (str): The domain name to add.
        ip_address (str): The IP address to associate with the domain.

    Returns:
        bool: True if the record was added successfully, False otherwise.
    """
    # The API endpoint for adding a custom DNS host record is a PUT request.
    # The format is: /api/config/dns/hosts/IP_ADDRESS%20DOMAIN_NAME
    # The IP address and domain name must be URL-encoded and are part of the URL path.
    encoded_entry = quote(f"{ip_address} {domain}")
    dns_record_endpoint = f"{base_url}/api/config/dns/hosts/{encoded_entry}"
    
    headers = {
        "X-FTL-SID": session_id, # Session ID is passed as a header
        "Content-Type": "application/json" # Though no body is sent for this specific PUT, it's good practice
    }

    print(f"\nAttempting to add DNS record: {domain} -> {ip_address} at {dns_record_endpoint}...")
    try:
        response = requests.put(dns_record_endpoint, headers=headers, timeout=30) # Increased timeout
        response.raise_for_status() # Check for HTTP errors

        # A successful PUT request might return 200 OK, 201 Created, or 204 No Content
        if response.status_code in [200, 201, 204]:
            print(f"✅ Successfully added DNS record: {domain} -> {ip_address} (confirmed by initial PUT response, status: {response.status_code})")
            try:
                # Some API endpoints might return the updated config or a success message
                content = response.json()
                if content: # Only print if there's actual content
                    print("   Response from Pi-hole:", content)
                else:
                    print("   Response from Pi-hole: (Empty JSON content, which is OK)")
            except json.JSONDecodeError:
                if response.text:
                    print(f"   Response from Pi-hole (not JSON): {response.text}")
                else:
                    print("   Response from Pi-hole: (No content, which is OK for 200/204)")
            return True
        else:
            # This case might not be reached if raise_for_status() catches the error
            print(f"⚠️ Failed to add DNS record. Pi-hole responded with status: {response.status_code}")
            try:
                print("   Error details:", response.json())
            except json.JSONDecodeError:
                print("   Error details (raw):", response.text)
            return False

    except requests.exceptions.Timeout:
        print(f"🕒 The PUT request to add DNS record timed out. Attempting to verify if the record was created anyway...")
        if verify_dns_record_exists(base_url, session_id, domain, ip_address):
            print(f"✅ Verification successful: DNS record {domain} -> {ip_address} was found after initial timeout.")
            return True
        else:
            print(f"❌ Verification failed: DNS record {domain} -> {ip_address} was NOT found after initial timeout.")
            return False
        return False
    except requests.exceptions.HTTPError as http_err:
        print(f"❌ Error adding DNS record: HTTP error occurred: {http_err}")
        print(f"   Response status code: {response.status_code}")
        try:
            print(f"   Response content: {response.json()}")
        except json.JSONDecodeError:
            print(f"   Response content: {response.text}")
        return False
    except requests.exceptions.RequestException as req_err:
        print(f"❌ Error adding DNS record: An error occurred: {req_err}")
        return False

# --- Main Script Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Add or update a local DNS record in Pi-hole v6. \n"
                    "If the domain exists with a different IP, it will offer to replace it.",
        epilog="Example: python add-local-dns-address.py --url http://pi.hole --password yourpassword --domain mydevice.lan --ip 192.168.1.100\n"
               "Example with backup: python add-local-dns-address.py --url http://pi.hole --backup-url http://pi.hole.backup --password pass --domain dev.lan --ip 10.0.0.1"
    )
    parser.add_argument("--url", required=True, help="The base URL of your Pi-hole (e.g., http://pi.hole or http://192.168.1.5)")
    parser.add_argument("--password", required=True, help="The web interface password for your Pi-hole.")
    parser.add_argument("--domain", required=True, help="The domain name to add (e.g., mydevice.lan).")
    parser.add_argument("--ip", required=True, help="The IP address to map the domain to (e.g., 192.168.1.123).")
    parser.add_argument("--backup-url", help="Optional: The base URL of your backup Pi-hole server. IMPORTANT: Assumes the backup server uses the same password as the primary.")
    parser.add_argument("--debug", action="store_true", help="Enable detailed debug logging.")

    args = parser.parse_args()

    PIHOLE_PASSWORD = args.password
    NEW_DOMAIN = args.domain.strip() # Strip whitespace from input
    NEW_IP_ADDRESS = args.ip.strip() # Strip whitespace from input

    print("--- Pi-hole v6 Local DNS Record Adder ---")

    target_servers = []
    if args.url:
        target_servers.append({"name": "Primary", "url": args.url.rstrip('/')})
    
    if args.backup_url:
        target_servers.append({"name": "Backup", "url": args.backup_url.rstrip('/')})
        print("ℹ️ Backup Pi-hole server specified. Will attempt to add record to both primary and backup.")
        print("   IMPORTANT: This script assumes the backup server uses the SAME password as the primary server.")

    if not target_servers:
        # This case should ideally not be reached if --url is required, but as a safeguard:
        print("❌ No Pi-hole server URL provided. Exiting.")
        sys.exit(1)

    all_operations_successful = True # Track overall success across all servers

    for server_info in target_servers:
        current_server_ok = True # Assume success for this server initially
        server_name = server_info["name"]
        server_url = server_info["url"]

        print(f"\n--- Processing Server: {server_name} ({server_url}) ---")

        # Authenticate
        session_id = get_pihole_session_id(server_url, PIHOLE_PASSWORD)

        if session_id:
            print(f"Checking for existing DNS record for '{NEW_DOMAIN}' on {server_name}...")
            existing_record_info = find_existing_record_for_domain(server_url, session_id, NEW_DOMAIN, debug_mode=args.debug)

            if isinstance(existing_record_info, str) and existing_record_info.startswith("ERROR_"): # Check failed
                print(f"   ❌ Could not complete pre-check for '{NEW_DOMAIN}' on {server_name}. Skipping further actions for this server.")
                current_server_ok = False
            elif existing_record_info is not None:  # Domain found, existing_record_info is (ip, domain_str_from_pihole)
                existing_ip, existing_domain_in_pihole = existing_record_info

                if existing_ip.lower() == NEW_IP_ADDRESS.lower():
                    # The found record (IP and its specific domain string) matches the target IP.
                    # NEW_DOMAIN might be slightly different from existing_domain_in_pihole (e.g. FQDN vs hostname)
                    print(f"   ℹ️  An existing record for '{existing_domain_in_pihole}' on {server_name} already points to the target IP '{NEW_IP_ADDRESS}'. No action taken.")
                    # current_server_ok remains True
                else:
                    print(f"   ⚠️ Record for '{existing_domain_in_pihole}' on {server_name} currently points to '{existing_ip}'.")
                    user_choice = input(f"      Delete this old record ('{existing_domain_in_pihole}' -> '{existing_ip}') and add the new one ('{NEW_DOMAIN}' -> '{NEW_IP_ADDRESS}')? (yes/no): ").strip().lower()
                    if user_choice == 'yes':
                        print(f"      User chose to replace. Attempting to delete old record...")
                        delete_success = delete_local_dns_record(server_url, session_id, existing_domain_in_pihole, existing_ip)
                        if delete_success:
                            print(f"      Old record deleted. Now attempting to add new record...")
                            add_success = add_local_dns_record(server_url, session_id, NEW_DOMAIN, NEW_IP_ADDRESS)
                            if not add_success:
                                current_server_ok = False
                        else:
                            print(f"      ❌ Failed to delete the old record for '{NEW_DOMAIN}' on {server_name}. New record not added.")
                            current_server_ok = False
                    else:
                        print(f"      User chose not to replace. Skipping update for '{NEW_DOMAIN}' on {server_name}.")
                        current_server_ok = False # Intended operation not completed
            else:  # Domain not found (existing_ip is None), proceed to add
                print(f"   Domain '{NEW_DOMAIN}' does not appear to exist on {server_name}. Attempting to add.")
                add_success = add_local_dns_record(server_url, session_id, NEW_DOMAIN, NEW_IP_ADDRESS)
                if not add_success:
                    current_server_ok = False
            
            if not current_server_ok:
                all_operations_successful = False
                print(f"   ⚠️ Operations for '{NEW_DOMAIN}' on server '{server_name}' were not fully completed as intended.")
            else:
                print(f"   ✅ Operations for '{NEW_DOMAIN}' on server '{server_name}' completed successfully or record was already correctly configured.")

        else:
            print(f"❌ Halting operations for {server_name} server due to authentication failure.")
            all_operations_successful = False

    if all_operations_successful:
        print("\n🎉 All DNS record addition processes completed successfully for all specified servers.")
    else:
        print("\n😔 One or more DNS record addition processes failed or were skipped due to authentication issues.")

    print("\n--- Script finished ---")

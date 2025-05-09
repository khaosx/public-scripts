#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Removes inactive client devices from a UniFi Network Application on UniFi OS
devices (like UDM-SE) using UniFi OS login and a deviceToken.

This script authenticates at the UniFi OS level, obtains a deviceToken (JWT),
and uses this token to authorize actions against the Network Application API,
accessing Network Application endpoints via the /proxy/network/ path.
It includes refined CSRF token handling.

WARNING: This script makes changes to your UniFi configuration.
ALWAYS use the --what-if parameter first to test and verify which clients
will be removed before running the script without --what-if.
"""

import argparse
import requests
import json
from datetime import datetime, timedelta, timezone
import getpass # For securely getting password

# Suppress InsecureRequestWarning when skip_certificate_check is True
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def forget_inactive_clients(base_url, username, password, site="default", days_inactive=30, skip_certificate_check=False, what_if=False):
    """
    Connects to UniFi Controller and forgets clients inactive for a specified number of days.
    Uses UniFi OS login to obtain a deviceToken for authorization.
    Network Application API calls are prefixed with /proxy/network/.
    """
    print(f"Script started at {datetime.now()}")
    print(f"UniFi Base URL: {base_url}")
    print(f"Username: {username}")
    print(f"Site: {site}")
    print(f"Days Inactive Threshold: {days_inactive}")

    cutoff_datetime_utc = datetime.now(timezone.utc) - timedelta(days=days_inactive)
    cutoff_epoch = int(cutoff_datetime_utc.timestamp())
    print(f"Cutoff Date UTC: {cutoff_datetime_utc.strftime('%Y-%m-%d %H:%M:%S %Z')}, Epoch: {cutoff_epoch}")

    session = requests.Session()
    session.headers.update({"User-Agent": "Python UniFi Client Script/1.3"}) # Incremented version

    device_token = None
    csrf_token_for_actions = None # This will hold the CSRF token to be used for POSTs

    # --- 0. UniFi OS Login ---
    login_url = f"{base_url}/api/auth/login"
    login_payload = {
        "username": username,
        "password": password,
        "remember": True
    }
    
    print(f"\nAttempting UniFi OS login to {login_url} as '{username}'...")
    login_response_obj = None # To store the login response object
    try:
        login_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
            "Referer": base_url + "/"
        }
        
        login_response_obj = session.post( # Assign to login_response_obj
            login_url,
            headers=login_headers,
            json=login_payload,
            verify=not skip_certificate_check,
            timeout=60
        )
        login_response_obj.raise_for_status()
        login_data = login_response_obj.json()

        device_token = login_data.get("deviceToken")
        if not device_token:
            token_from_header = login_response_obj.headers.get('x-auth-token')
            if token_from_header:
                print("Used x-auth-token from login response header.")
                device_token = token_from_header
            else:
                legacy_token_cookie = session.cookies.get('TOKEN')
                if legacy_token_cookie:
                     print("Used TOKEN cookie for authorization (legacy UDM-Pro style).")
                     device_token = legacy_token_cookie
        
        # Attempt to get CSRF token from OS login (cookie or header)
        csrf_token_for_actions = session.cookies.get('csrf_token')
        if not csrf_token_for_actions and login_response_obj.headers:
            csrf_token_for_actions = login_response_obj.headers.get('x-csrf-token')


        if device_token:
            print(f"UniFi OS Login successful. Device token obtained.")
            if csrf_token_for_actions:
                print(f"Initial CSRF token found from OS login: {csrf_token_for_actions[:10]}...") # Print first 10 chars
        else:
            print(f"UniFi OS Login to {login_url} returned HTTP 200, but no deviceToken or fallback token found in response.")
            print(f"Login response content: {json.dumps(login_data, indent=2)}")
            return

    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error during UniFi OS login to {login_url}: {e}")
        if e.response is not None:
            print(f"  Response Status Code: {e.response.status_code}")
            try:
                print(f"  Response Content: {e.response.json()}")
            except json.JSONDecodeError:
                print(f"  Response Content (not JSON): {e.response.text}")
        return
    except requests.exceptions.RequestException as e:
        print(f"Network or Request Error during UniFi OS login to {login_url}: {e}")
        return

    # --- Prepare API headers for Network Application calls (via proxy) ---
    # These headers will be used for GETting client list and potentially updated for POST
    base_api_headers = {
        "Accept": "application/json",
        "User-Agent": session.headers.get("User-Agent"),
        "Authorization": f"Bearer {device_token}"
    }
    # If CSRF token was found from OS login, add it now. It might be overwritten later if Network App provides its own.
    if csrf_token_for_actions:
        base_api_headers['x-csrf-token'] = csrf_token_for_actions
        print("Including initial x-csrf-token from UniFi OS context in subsequent requests.")


    # --- 1. Get Client Devices (via /proxy/network/ path) ---
    network_api_base = f"{base_url}/proxy/network/api/s/{site}"
    clients_url_alt = f"{network_api_base}/stat/alluser"
    clients_url = f"{network_api_base}/stat/user"

    print(f"\nRetrieving client list from Network Application (via proxy path)...")
    current_clients_url_used = clients_url_alt 
    print(f"  Attempting: {current_clients_url_used}")

    all_clients_data = []
    fetched_successfully = False
    
    get_api_headers = base_api_headers.copy() # Start with headers from OS login (Bearer token, initial CSRF)
    if "Content-Type" in get_api_headers: # Not needed for GET
        del get_api_headers["Content-Type"]

    client_list_response = None # To store the response object from fetching clients
    try:
        client_list_response = session.get(
            current_clients_url_used,
            headers=get_api_headers,
            verify=not skip_certificate_check,
            timeout=120
        )
        client_list_response.raise_for_status()
        clients_json = client_list_response.json()
        all_clients_data = clients_json.get("data", [])
        print(f"Found {len(all_clients_data)} clients using {current_clients_url_used}.")
        fetched_successfully = True
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving clients from {current_clients_url_used}: {e}")
        # (Error printing logic as before)
        if current_clients_url_used == clients_url_alt:
            current_clients_url_used = clients_url
            print(f"\nAttempting fallback client endpoint: {current_clients_url_used}")
            try:
                client_list_response = session.get( # Update client_list_response here too
                    current_clients_url_used,
                    headers=get_api_headers,
                    verify=not skip_certificate_check,
                    timeout=120
                )
                client_list_response.raise_for_status()
                clients_json = client_list_response.json()
                all_clients_data = clients_json.get("data", [])
                print(f"Found {len(all_clients_data)} clients using {current_clients_url_used}.")
                fetched_successfully = True
            except requests.exceptions.RequestException as e_alt:
                print(f"Error retrieving clients from {current_clients_url_used}: {e_alt}")
                # (Error printing logic as before)

    # After fetching clients, check if the Network App set/updated a CSRF token
    if client_list_response: # If we got any response from the Network App GET
        network_app_csrf_cookie = session.cookies.get('csrf_token')
        network_app_csrf_header = client_list_response.headers.get('x-csrf-token')
        if network_app_csrf_header:
            print(f"Network App provided x-csrf-token in GET response header: {network_app_csrf_header[:10]}...")
            csrf_token_for_actions = network_app_csrf_header # Prioritize this
        elif network_app_csrf_cookie:
            print(f"Network App provided csrf_token in GET response cookie: {network_app_csrf_cookie[:10]}...")
            if not csrf_token_for_actions or csrf_token_for_actions != network_app_csrf_cookie : # Update if different or not set
                 csrf_token_for_actions = network_app_csrf_cookie


    if not fetched_successfully:
        print("All attempts to retrieve client list failed. Exiting.")
        return
    if not all_clients_data and fetched_successfully:
        print("Client list successfully retrieved, but it's empty.")

    # --- 2. Identify and Process Inactive Clients ---
    # (This section remains largely the same)
    inactive_clients_to_forget_macs = []
    clients_processed = 0
    clients_marked_for_removal = 0

    print(f"\nIdentifying clients inactive for more than {days_inactive} days (since {cutoff_datetime_utc.strftime('%Y-%m-%d %H:%M:%S %Z')} UTC)...")

    for client in all_clients_data:
        clients_processed += 1
        mac = client.get("mac")
        if not mac:
            print(f"Skipping client with no MAC address: {client.get('hostname', 'N/A')}")
            continue

        client_name = client.get("hostname") or client.get("name", f"N/A (MAC: {mac})")
        if client_name != f"N/A (MAC: {mac})":
             client_name = f"{client_name} (MAC: {mac})"

        last_seen_epoch = client.get("last_seen")

        if last_seen_epoch is not None:
            try:
                last_seen_epoch = int(last_seen_epoch)
                last_seen_datetime_local = datetime.fromtimestamp(last_seen_epoch).astimezone()

                if last_seen_epoch < cutoff_epoch:
                    print(f"  Client '{client_name}' (Last Seen: {last_seen_datetime_local.strftime('%Y-%m-%d %H:%M:%S %Z')}) is older than {days_inactive} days.")
                    inactive_clients_to_forget_macs.append(mac)
                    clients_marked_for_removal += 1
            except (ValueError, TypeError):
                print(f"  Client '{client_name}' has an invalid 'last_seen' timestamp format: {last_seen_epoch}. Considering for removal.")
                inactive_clients_to_forget_macs.append(mac)
                clients_marked_for_removal +=1
        else:
            print(f"  Client '{client_name}' has no 'last_seen' timestamp. Considering for removal.")
            inactive_clients_to_forget_macs.append(mac)
            clients_marked_for_removal += 1

    print(f"\nProcessed {clients_processed} clients. Found {clients_marked_for_removal} clients to forget.")


    if inactive_clients_to_forget_macs:
        if what_if:
            print("\n-- WHAT-IF MODE --")
            print(f"{len(inactive_clients_to_forget_macs)} client(s) would have been forgotten:")
            for mac_addr in inactive_clients_to_forget_macs:
                print(f"  - {mac_addr}")
        else:
            confirm = input(f"Proceed to forget {len(inactive_clients_to_forget_macs)} client(s)? (yes/no): ").lower()
            if confirm == 'yes':
                print(f"\nProceeding to forget {len(inactive_clients_to_forget_macs)} client(s)...")
                
                forget_url = f"{network_api_base}/cmd/stamgr" 
                print(f"Using forget URL: {forget_url}")

                forget_payload = {
                    "cmd": "forget-sta",
                    "macs": inactive_clients_to_forget_macs
                }
                
                # Prepare headers for the POST "forget" command
                post_api_headers = base_api_headers.copy() # Start with base (Auth Bearer)
                post_api_headers["Content-Type"] = "application/json; charset=utf-8"
                if csrf_token_for_actions: # Use the potentially updated CSRF token
                    post_api_headers['x-csrf-token'] = csrf_token_for_actions
                    print(f"Using x-csrf-token for POST: {csrf_token_for_actions[:10]}...")
                else:
                    print("Warning: No CSRF token available for POST operation. This might lead to a 403 error.")


                print(f"Forget Payload: {json.dumps(forget_payload, indent=2)}")

                try:
                    response = session.post(
                        forget_url, 
                        headers=post_api_headers,
                        json=forget_payload,
                        verify=not skip_certificate_check,
                        timeout=180
                    )
                    response.raise_for_status()
                    forget_response_json = response.json()

                    if forget_response_json.get("meta", {}).get("rc") == "ok":
                        print(f"Successfully sent command to forget {len(inactive_clients_to_forget_macs)} client(s).")
                        print("Clients forgotten:")
                        for mac_addr in inactive_clients_to_forget_macs:
                            print(f"  - {mac_addr}")
                    else:
                        print("Command to forget clients was sent, but controller reported an issue.")
                        print(f"Response: {json.dumps(forget_response_json, indent=2)}")

                except requests.exceptions.RequestException as e:
                    print(f"Error forgetting clients: {e}")
                    if hasattr(e, 'response') and e.response is not None:
                        print(f"  Response Status Code: {e.response.status_code}")
                        try:
                            print(f"  Response Content: {e.response.json()}")
                        except json.JSONDecodeError:
                             print(f"  Response Content (not JSON): {e.response.text}")
            else:
                print("Operation cancelled by user.")
    else:
        print("\nNo inactive clients found matching the criteria.")

    # --- 3. UniFi OS Logout ---
    logout_url = f"{base_url}/api/auth/logout"
    print(f"\nAttempting UniFi OS log out from {logout_url}...")
    try:
        # Use the latest headers which include Authorization and potentially CSRF for logout
        logout_post_headers = base_api_headers.copy()
        if csrf_token_for_actions: # Ensure CSRF is included if available
             logout_post_headers['x-csrf-token'] = csrf_token_for_actions
        # Logout usually doesn't need Content-Type if no body, but UniFi can be picky
        # logout_post_headers["Content-Type"] = "application/json; charset=utf-8"


        logout_response = session.post(
            logout_url,
            headers=logout_post_headers, 
            json={}, # Sending an empty JSON body sometimes helps with picky APIs
            verify=not skip_certificate_check,
            timeout=30
        )
        if logout_response.status_code == 200:
            print("UniFi OS Logout successful.")
        else:
            print(f"UniFi OS Logout status: {logout_response.status_code}. This is often not critical.")
            try:
                print(f"Logout response: {logout_response.json()}")
            except json.JSONDecodeError:
                print(f"Logout response (not JSON): {logout_response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error during UniFi OS logout (this is often not critical): {e}")

    print(f"\nScript finished at {datetime.now()}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Removes inactive client devices from a UniFi Network Application on UniFi OS devices using UniFi OS login.",
        epilog="Example usage:\n  python %(prog)s https://192.168.10.1 your_username --what-if\n\n"
               "You will be prompted for your password.\n"
               "If using a self-signed certificate, add --skip-certificate-check.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("base_url", help="The base URL of your UniFi Network Application (e.g., 'https://192.168.10.1')")
    parser.add_argument("username", help="Your UniFi local username for UniFi OS.")
    parser.add_argument("--site", default="default", help="The UniFi site ID (default: 'default').")
    parser.add_argument("--days-inactive", type=int, default=30, help="Number of days a client must be inactive to be removed (default: 30).")
    parser.add_argument("--skip-certificate-check", action="store_true", help="Skip SSL/TLS certificate validation (use with caution for self-signed certs).")
    parser.add_argument("--what-if", action="store_true", help="Show what would happen but do not make changes.")

    args = parser.parse_args()

    password = getpass.getpass(prompt=f"Enter password for UniFi user '{args.username}': ")

    forget_inactive_clients(
        base_url=args.base_url.rstrip('/'),
        username=args.username,
        password=password,
        site=args.site,
        days_inactive=args.days_inactive,
        skip_certificate_check=args.skip_certificate_check,
        what_if=args.what_if
    )
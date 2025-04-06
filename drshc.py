import yaml
import sys
import argparse
import time 
import copy

from rich.console import Console
from rich.panel import Panel
from typing import Dict, List, Tuple, Optional, Any

from splunkrest import SplunkRest
from splunkkv import SplunkKV
from encrutils import generate_or_load_key, handle_config_encryption, decrypt_config

def get_content(status: Dict) -> Optional[Dict]:
    """Extract content safely from API response"""
    if not isinstance(status, dict):
        return None
    
    response = status.get("response", {})
    if not isinstance(response, dict):
        return None
        
    entries = response.get("entry", [])
    if not entries or not isinstance(entries, list):
        return None
        
    first_entry = entries[0]
    if not isinstance(first_entry, dict):
        return None
        
    return first_entry.get("content", {})

def process_shc_status(console: Console, shc_status: Dict) -> Tuple[bool, Optional[List[str]]]:
    """Process and display SHC status information"""
    content = get_content(shc_status)
    if content is None:
        if shc_status['http_code']:
            console.print(f" ❌ SHC responded with HTTP/{shc_status['http_code']}")
        else:    
            console.print(f" ❌ Failed to get SHC content. Invalid data structure. Details: [bold]{shc_status}[/bold]")
        return False, None
    
    captain = content.get("captain", {})
    peers = content.get("peers", {})
    if not captain or not peers:
        console.print(" ❌ Failed to get captain or peers info from SHC response.")
        return False, None

    # Print captain info
    console.print("👑  [bold magenta]Captain Info[/bold magenta]")
    dynamic_captain = captain.get('dynamic_captain', False)
    captain_status = "[green]" if dynamic_captain else "[red]"
    console.print(f"  🔮  dynamic_captain: {captain_status}{dynamic_captain}[/]")
    console.print(f"  🏷   label: [cyan]{captain.get('label', 'N/A')}[/cyan]")
    
    sh_members_online = []
    
    # Print members info
    console.print("👥 [bold cyan]Cluster Members[/bold cyan]")
    for _, peer in sorted(peers.items(), key=lambda item: item[1].get("mgmt_uri", "N/A")):
        mgmt_uri = peer.get("mgmt_uri", "N/A")
        host = mgmt_uri.split("://", 1)[-1].split(':')[0] if "://" in mgmt_uri else mgmt_uri
        status = peer.get("status", "Unknown")
        emoji = "✅" if status.lower() == "up" else "❌"
        if status.lower() == "up":
            sh_members_online.append(host)
        console.print(f"  {emoji}  host: [yellow]{host}[/yellow] — status: [bold]{status}[/bold]")
 
    return True, sh_members_online

def process_kvstore_status(console: Console, kv_status: Dict) -> Tuple[bool, Optional[List[str]], Optional[str]]:
    """Process and display KV Store status information"""
    captain = None
    kv_content = get_content(kv_status)
    if kv_content is None:
        console.print(f"❌  Failed to get KV Store status. Invalid data structure. Details: [bold]{kv_status}[/bold]")
        return False, None, None
    
    members = kv_content.get('members', {})
    if not members:
        console.print("❌  No KV Store members found.")
        return False, None, None
        
    kv_members_online = []
    console.print("👑  [bold magenta]KV Store Info[/bold magenta]")     
    for member_id, member in sorted(members.items(), key=lambda item: item[1].get("hostAndPort", "N/A")):
        host_and_port = member.get("hostAndPort", "N/A")
        if ":" in host_and_port:
            host, port = host_and_port.split(':')
        else:
            host = host_and_port
            
        config_version = member.get("configVersion", -1)
        replication_status = member.get("replicationStatus", "N/A")
        if replication_status == "KV store captain":
            captain = host
        status = "Down" if replication_status == "Down" else "Up"
        if status.lower() == "up":
            kv_members_online.append(host)
        emoji = "✅" if config_version != -1 else "❌"
        console.print(f"  {emoji}  host: [yellow]{host}[/yellow] — status: [bold]{status}[/bold] - replicationStatus: [bold]{replication_status}[/bold]")     
    
    return True, kv_members_online, captain


def load_config(config_file: str, console: Console, key_file: str = ".config.key") -> Dict:
    """Load and validate configuration from YAML file, prompting for missing credentials"""
    try:
        # Generate or load encryption key
        key = generate_or_load_key(key_file)
        
        if key is None:
            console.print(f"❌  [red]Error: unable to load the key. It seems tobe of incorrect size.[/red]")
            return False
        
        # Define which fields should be encrypted
        sensitive_fields = ['password', 'certificate_key_file_password']
        
        # Load the configuration file
        with open(config_file, 'r') as file:
            content = file.read().replace('\t', '  ')
            original_config = yaml.safe_load(content)
            
        # Create a deep copy of the original config to track what came from the file
        file_config = copy.deepcopy(original_config)
            
        # Validate the loaded configuration
        if not original_config:
            console.print(f"❌  [red]Error: Configuration file '{config_file}' is empty[/red]")
            return False
        
        # Working config that will include prompted values
        config = copy.deepcopy(original_config)
        
        # Check if Splunk credentials are missing and prompt if needed
        if 'splunk' in config:
            if not config['splunk'].get('username'):
                config['splunk']['username'] = console.input("👤  Enter [bold]Splunk username[/bold]: ")
            
            if not config['splunk'].get('password'):
                config['splunk']['password'] = console.input("🔑  Enter [bold]Splunk password[/bold]: ", password=True)
        else:
            console.print(f"❌  [red]Error: Missing 'splunk' section in configuration[/red]")
            return False

        if 'kvstore' in config:
            if not config['kvstore'].get('certificate_key_file_password'):
                config['kvstore']['certificate_key_file_password'] = console.input("🔑  Enter [bold]KV Store keyfile password[/bold]: ", password=True)         
        else:
            console.print(f"❌  [red]Error: Missing 'splunk' section in configuration[/red]")
            return False      
          
        # Encrypt sensitive fields, but only if they existed in the original file
        encrypted_config = handle_config_encryption(file_config, key, sensitive_fields, original_config)
        
        # Save the updated config with encrypted values
        with open(config_file, 'w') as file:
            yaml.dump(encrypted_config, file, default_flow_style=False)
        
        # Return the working config with all values (prompted + file) decrypted for use in memory
        return decrypt_config(config, key)
        
    except Exception as e:
        console.print(f"❌  [red]Error loading configuration: {str(e)}[/red]")
        return False

def test_search_heads(splunk_config: Dict, all_members: List[str], console: Console) -> Tuple[List[str], List[str], List[str]]:
    """Test connectivity to all search heads and categorize them"""
    online_members = []
    offline_members = []
    unexpected_members = []

    splunk_username = splunk_config.get('username')
    splunk_password = splunk_config.get('password')
    splunk_verify = splunk_config.get('verify')
    splunk_port = splunk_config.get('port')
    
    for search_head in all_members:
        sh_uri = f"https://{search_head}:{splunk_port}"
        splunk = SplunkRest(base_url=sh_uri, auth=(splunk_username, splunk_password), verify=splunk_verify)
        
        result = splunk.test_connectivty()
        
        if result['success'] and result['http_code'] == 200:
            console.print(f"✅  Search Head [yellow]{search_head}[/yellow] is [bold]Up[/bold]")
            online_members.append(search_head)
        elif result['http_code'] == 401:
            console.print(f"❌  Got HTTP statuc code 401 from [yellow]{search_head}[/yellow] check provided credentials. Details: {result['response']}")
        elif result.get('exception') in ["ConnectionError", "ConnectTimeoutError", "ConnectTimeout"]:
            console.print(f"❌  Search Head [yellow]{search_head}[/yellow] is [bold]Down[/bold]")
            offline_members.append(search_head)
        else:
            console.print(f"💥  Unexpected exception for SH {search_head}. Details: {result.get('details', 'Unknown error')}. Result: {result}")         
            unexpected_members.append(search_head)
            
    return online_members, offline_members, unexpected_members

def get_all_members(config: Dict) -> List[str]:
    """Extract all cluster members from configuration"""
    all_members = []
    for members in config.get("cluster_members", {}).values():
        all_members.extend(members)
    return all_members

def test_action(config: Dict, console: Console) -> None:
    """Execute the test action to check connectivity and status of all search heads using Splunk API /services/server/info"""
    console.print("🔍 [bold blue]Running test action.[/bold blue]")
    
    # Get all members from configuration
    all_members = get_all_members(config)
    
    if not all_members:
        console.print("❌ [red]No cluster members found in configuration[/red]")
        return False

    # Extract credentials and configurations
    splunk_config = config.get('splunk', {})
    splunk_username = splunk_config.get('username')
    splunk_password = splunk_config.get('password')
    splunk_verify = splunk_config.get('verify', False)
    splunk_port = splunk_config.get('port', 8089)
    

    # Test connectivity to all search heads
    online_members, offline_members, unexpected_members = test_search_heads(splunk_config, all_members, console)

    # Report connectivity status
    console.print("\n📊 [bold]Connectivity Summary Splunk API[/bold]")
    console.print(f"  ✅ Online members: [yellow]{', '.join(online_members) if online_members else 'None'}[/yellow]")
    console.print(f"  ❌ Offline members: [yellow]{', '.join(offline_members) if offline_members else 'None'}[/yellow]")
    console.print(f"  💥 Error members: [yellow]{', '.join(unexpected_members) if unexpected_members else 'None'}[/yellow]")
    
    # Exit with error code if unexpected errors occurred
    if unexpected_members:
        console.print(f"💥  Received errors during test connection to Search Heads. Wait a few seconds and retry.")
        return False
    
    # If no online members, we can't proceed with additional tests
    if not online_members:
        console.print("❌ [red]No online members found, cannot proceed with status checks.[/red]")
        return False
    
    # Check if majority of members are online
    majority_status = len(online_members) > len(all_members) / 2
    majority_emoji = "✅" if majority_status else "⚠️"
    console.print(f"{majority_emoji}  SHC has {'a majority' if majority_status else 'lost majority'} of members online.")
        
    # Check SHC status using the first online member
    online_head = online_members[0]
    console.print(f"\n🛠  Checking SHC Status via Splunk APIs on member: [yellow]{online_head}[/yellow]")
    
    splunk_uri = f"https://{online_head}:{splunk_port}"
    splunk = SplunkRest(base_url=splunk_uri, auth=(splunk_username, splunk_password), verify=splunk_verify)
    
    # Get and process SHC status
    shc_status = splunk.shc_status()
    
    # Initialize to empty list by default
    sh_members_online = []
    
    # Check for HTTP/503 status specifically (lost majority indicator)
    if shc_status.get('success') and shc_status.get('http_code') == 503:
        console.print("⚠️ [yellow]Got HTTP/503 from SHC API. This likely means the cluster has lost majority of members.[/yellow]")
        console.print("⚠️ [yellow]Continuing with additional checks...[/yellow]")
    else:
        # Standard processing for other cases
        success, members = process_shc_status(console=console, shc_status=shc_status)
        
        # Use result only if successful
        if success and members:
            sh_members_online = members
        else:
            console.print("❌ [red]Failed to get SHC status, but will continue with further checks.[/red]")

    # Get and process KV store status
    console.print("\n🔍 Checking KV Store status")
    kv_status = splunk.kv_status()
    success, kv_members_online, captain = process_kvstore_status(console, kv_status=kv_status)
    
    if not success:
        console.print("❌ [red]Failed to get KV Store status.[/red]")
    
    # Report KV store captain status
    if captain:
        console.print(f"✅  KVstore captain has been detected: [bold]{captain}[/bold]")
    else:
        console.print(f"❌  KVstore doesn't seem to have a captain.")
    
    # Validate consistency between different API results
    console.print("\n🔄 [bold]Consistency Validation[/bold]")
    
    # If we got HTTP/503 from SHC API, note that in consistency check
    if shc_status.get('http_code') == 503:
        console.print("⚠️  [yellow]SHC API returned HTTP/503 - cluster has likely lost majority[/yellow]")
        console.print("💡  This means consistency validation will be limited to connection test and KV Store API")
    
    # Proceed with validation using available data
    if kv_members_online is not None:  # We at least need KV data
        # Prepare sets for comparison, safely
        online_set = set(online_members) if online_members else set()
        sh_set = set(sh_members_online) if sh_members_online else set()
        kv_set = set(kv_members_online) if kv_members_online else set()
        
        # Create a table-like display for comparison
        console.print("📋 Members reported by different methods:")
        console.print(f"  🔌  Connection Test: [yellow]{', '.join(sorted(online_set)) if online_set else 'None'}[/yellow]")
        
        if shc_status.get('http_code') == 503:
            console.print(f"  🔗  SHC API:         [yellow]Not available (HTTP/503)[/yellow]")
        else:
            console.print(f"  🔗  SHC API:         [yellow]{', '.join(sorted(sh_set)) if sh_set else 'None'}[/yellow]")
            
        console.print(f"  📂  KV Store API:    [yellow]{', '.join(sorted(kv_set)) if kv_set else 'None'}[/yellow]")
        
        # Check for consistency across methods (accounting for HTTP/503 case)
        if shc_status.get('http_code') == 503:
            # When SHC is unreachable due to 503, only compare KV and connection test
            if kv_set == online_set:
                console.print("✅  KV Store API and connection test results are consistent.")
            else:
                console.print("⚠️  [yellow]Inconsistency detected between KV Store API and connection test[/yellow]")
                
                # Identify specific nodes with issues
                missing_in_kv = online_set - kv_set
                extra_in_kv = kv_set - online_set
                if missing_in_kv:
                    console.print(f"  ❌ Nodes missing in KV Store API: [red]{', '.join(sorted(missing_in_kv))}[/red]")
                if extra_in_kv:
                    console.print(f"  ❓ Nodes only in KV Store API: [cyan]{', '.join(sorted(extra_in_kv))}[/cyan]")
        else:
            # Normal case - compare all three sources
            if sh_set == kv_set == online_set:
                console.print("✅  All APIs returned consistent results.")
            else:
                console.print("⚠️  [yellow]Inconsistency detected between API results[/yellow]")
                
                # Identify which specific nodes are inconsistent
                if sh_set != online_set:
                    missing_in_sh = online_set - sh_set
                    extra_in_sh = sh_set - online_set
                    if missing_in_sh:
                        console.print(f"  ❌ Nodes missing in SHC API: [red]{', '.join(sorted(missing_in_sh))}[/red]")
                    if extra_in_sh:
                        console.print(f"  ❓ Nodes only in SHC API: [cyan]{', '.join(sorted(extra_in_sh))}[/cyan]")
                
                if kv_set != online_set:
                    missing_in_kv = online_set - kv_set
                    extra_in_kv = kv_set - online_set
                    if missing_in_kv:
                        console.print(f"  ❌ Nodes missing in KV Store API: [red]{', '.join(sorted(missing_in_kv))}[/red]")
                    if extra_in_kv:
                        console.print(f"  ❓ Nodes only in KV Store API: [cyan]{', '.join(sorted(extra_in_kv))}[/cyan]")

    
    # Final status summary
    console.print("\n📝 [bold]Final Status Summary[/bold]")
    
    # Check if we received HTTP/503 response
    if shc_status.get('http_code') == 503:
        console.print("❌  Search Head Cluster has lost [bold]majority[/bold] and is [bold]offline[/bold] (confirmed by HTTP/503).")
        if online_members:
            console.print(f"🧰  Consider running 'recover' action to restore the cluster with the available members: [yellow]{', '.join(online_members)}[/yellow]")
    elif not majority_status and shc_status.get('success'):
        # Get SHC content
        shc_content = get_content(shc_status)
        if shc_content:
            # Check if running in recovery mode (static captain)
            captain_info = shc_content.get("captain", {})
            is_dynamic_captain = captain_info.get('dynamic_captain', True)
            
            if not is_dynamic_captain:
                console.print("🔄 Search Head Cluster is running in [bold]recovery[/bold] mode with a [bold]static[/bold] captain.")
                console.print(f"   Static captain: [yellow]{captain_info.get('label', 'Unknown')}[/yellow]")
                
                # Check if all online members are correctly reporting via SHC API
                if online_set and sh_set and online_set == sh_set:
                    console.print("✅ [green]All online members are correctly participating in the recovery cluster.[/green]")
                else:
                    console.print("⚠️ [yellow]Some inconsistencies detected in the recovery cluster configuration.[/yellow]")
                    
                console.print("   To restore full cluster functionality, bring the offline members back online and")
                console.print("   consider running 'rollback' action once all members are available.")
            else:
                console.print("❌ [red]Search Head Cluster has lost majority and is in an unusual state.[/red]")
                console.print("   The cluster appears to be operating despite having lost majority, but not in recovery mode.")
                console.print("   This might indicate a misconfiguration or an unstable state.")
        else:
            console.print("❓ [yellow]Search Head Cluster status could not be fully determined.[/yellow]")
            console.print("   The cluster responded but provided incomplete information.")
    elif majority_status:
        if not sh_members_online:
            console.print("⚠️ [yellow]Search Head Cluster has majority of nodes online, but SHC status could not be retrieved.[/yellow]")
        elif online_set and sh_set and kv_set and sh_set == kv_set == online_set:
            # Check if running in recovery mode with majority (unusual but possible)
            shc_content = get_content(shc_status)
            if shc_content:
                captain_info = shc_content.get("captain", {})
                is_dynamic_captain = captain_info.get('dynamic_captain', True)
                
                if not is_dynamic_captain:
                    console.print("ℹ️ [blue]Search Head Cluster has majority and is running with a static captain.[/blue]")
                    console.print("   This indicates the cluster was previously recovered but not rolled back to normal operation.")
                    console.print("   Consider running 'rollback' action to restore normal cluster operation.")
                else:
                    console.print("✅ [green]Search Head Cluster appears to be healthy and consistent with dynamic captain.[/green]")
            else:
                console.print("✅ [green]Search Head Cluster appears to be healthy and consistent.[/green]")
        else:
            console.print("⚠️ [yellow]Search Head Cluster is online but has inconsistencies that may require attention.[/yellow]")
    else:
        console.print("❌ [red]Search Head Cluster has lost majority and is likely offline.[/red]")
        if online_members:
            console.print(f"   Consider running 'recover' action to restore the cluster with the available members: [yellow]{', '.join(online_members)}[/yellow]")

def recover_action(config: Dict, console: Console) -> None:
    # """Execute the recovery procedure for the Search Head Cluster"""
    # console.print("🔄 [bold blue]Running recovery action[/bold blue]")
    
    # Get all members from configuration
    all_members = get_all_members(config)
    
    if not all_members:
        console.print("❌ [red]No cluster members found in configuration[/red]")
        return False

    # # Extract credentials and configurations
    splunk_config = config.get('splunk', {})
    splunk_username = splunk_config.get('username')
    splunk_password = splunk_config.get('password')
    splunk_verify = splunk_config.get('verify', False)
    splunk_port = splunk_config.get('port', 8089)

    kv_config = config.get('kvstore', {})
    kv_username = kv_config.get('username')
    kv_password = kv_config.get('password')
    kv_port = kv_config.get('port', 8191)
    kv_certificate_key_file = kv_config.get('certificate_key_file')
    kv_certificate_key_file_password = kv_config.get('certificate_key_file_password')
        
    online_members, _, unexpected_members = test_search_heads(splunk_config, all_members, console)
    if unexpected_members:
        console.print(f"💥  Received errors during test connection to Search Heads. Wait few seconds and retry. SH: [bold red]{', '.join(unexpected_members)}[/bold red]")
        return False

    # If no online members, we can't proceed with additional tests
    if not online_members:
        console.print("❌ [red]No online members found, cannot proceed with status checks.[/red]")
        return False
    
    # Split the list: designate the first as captain (👑) and the rest as members (👥)
    captain = online_members[0]
    members = online_members[1:]
    console.print("🚀  Starting recovery procedure... 🔄")
    
    # Force the captain role
    captain_uri = f"https://{captain}:{splunk_port}"
    splunk_captain = SplunkRest(base_url=captain_uri, auth=(splunk_username, splunk_password), verify=splunk_verify)
    status = splunk_captain.shc_status()

    if status['success']:
        if status['http_code'] == 200:
            console.print("⚠️  Cluster appears to be [bold]online[/bold] even if has lost its majority of members.")
            process_shc_status(console=console, shc_status=status)
            return False
        if status['http_code'] == 503:
            console.print(f"⚠️  Got status HTTP/503 from {captain_uri} confirming cluster has lost majority.")

    console.print(f"  👑 Forcing SH {captain_uri} as a static captain.")
    captain_result = splunk_captain.set_sh_captain(captain_uri)
    if not captain_result['success'] or captain_result['http_code'] > 299:
        console.print(f"  🚫  Failure setting static captain at {captain_uri}")
        return False
        
    # Process each remaining member as a static member
    for member in members:
        member_uri = f"https://{member}:{splunk_port}"
        splunk = SplunkRest(base_url=member_uri, auth=(splunk_username, splunk_password), verify=splunk_verify)
        console.print(f"  👥 Forcing SH {member_uri} as a static member of the cluster.")
        member_result = splunk.set_sh_member(captain_uri)
        
        if not member_result['success']:
            console.print("  🚫  Failure setting static member")
            return False
    
    max_attempts = 6
    attempt = 0
    sleep_seconds = 10 
    
    while attempt < max_attempts:
        console.print(f"💤  Sleeping {sleep_seconds} s to allow the cluster to accept the new configuration... ⏳")
        time.sleep(sleep_seconds)

        shc_status = splunk_captain.shc_status()
        success, sh_members = process_shc_status(console=console, shc_status=shc_status)
        
        if success:
            break  # Exit the loop if successful
        
        attempt += 1
    
    if not success:
        return False
    
    if set(sh_members) == set(online_members):
        console.print(f"✅  SHC status returned all online hosts as part of the cluster: [yellow]{', '.join(online_members)}[/yellow]")
    else:
        console.print(f"🚫  SHC status is not consistent with online members. Online members: [bold]{', '.join(online_members)}[/bold]. Cluster online: [bold]{', '.join(sh_members)}[/bold]")
        return False
        
    # Test KV store connectivity
    kvstore = SplunkKV(
        host=captain,
        port=kv_port,
        username=kv_username,
        password=kv_password, 
        tlsCertificateKeyFile=kv_certificate_key_file, 
        tlsCertificateKeyFilePassword=kv_certificate_key_file_password
    )
    kv_result = kvstore.test_connectivty()
    if kv_result.get('success', False):
        console.print("✅  Direct KV Store connection successful")
    else:
        console.print(f"❌  Direct KV Store connection failed: {kv_result.get('details', 'Unknown error')}")
        return False
    
    console.print("✅  Reconfiguring KVStore")
    status = kvstore.reconfigure_replicaset()
    
    max_attempts = 6
    attempt = 0
    sleep_seconds = 10 
    
    while attempt < max_attempts:
        console.print(f"💤  Sleeping {sleep_seconds}s to allow the replicaset to accept the new configuration...  ⏳")
        time.sleep(sleep_seconds)

        kv_status = splunk_captain.kv_status()
        success, kv_members, captain = process_kvstore_status(console=console, kv_status=kv_status)
        
        if captain and success:
            break  # Exit the loop if successful
        
        attempt += 1
    
    if not success:
        return False
        
    if captain:
        console.print(f"✅  KVstore captain has been detected: [yellow]{captain}[/yellow]")
    else:
        console.print(f"❌  KVstore doesn't seem to have a captain.")
    console.print(f"✅  Cluster recovery [bold]DONE![/bold]")

def rollback_action(config: Dict, console: Console) -> None:
    """Execute the rollback procedure for the Search Head Cluster
    
    Restores the cluster to normal operation with dynamic captain mode.
    Requires all cluster members to be online.
    """
    console.print("↩️ [bold blue]Running rollback action[/bold blue]")
    
    # Get all members from configuration
    all_members = get_all_members(config)
    
    if not all_members:
        console.print("❌ [red]No cluster members found in configuration[/red]")
        return False

    # # Extract credentials and configurations
    splunk_config = config.get('splunk', {})
    splunk_username = splunk_config.get('username')
    splunk_password = splunk_config.get('password')
    splunk_verify = splunk_config.get('verify', False)
    splunk_port = splunk_config.get('port', 8089)

    # Test connectivity to all search heads
    console.print("🔍 Verifying connectivity to all cluster members...")        
    online_members, offline_members, unexpected_members = test_search_heads(splunk_config, all_members, console)
    
    # Check if all members are online
    if offline_members or unexpected_members:
        console.print("❌  [red]Cannot perform rollback. All cluster members must be online.[/red]")
        console.print(f"   Offline members: [yellow]{', '.join(offline_members) if offline_members else 'None'}[/yellow]")
        console.print(f"   Error members: [yellow]{', '.join(unexpected_members) if unexpected_members else 'None'}[/yellow]")
        console.print("    Ensure all members are online before attempting rollback.")
        return False

    # If no online members, we can't proceed with additional tests
    if not online_members:
        console.print("❌  [red]No online members found, cannot proceed with status checks.[/red]")
        return False
        
    console.print("✅  [green]All cluster members are online. Proceeding with rollback.[/green]")
    
    # First check current cluster status
    first_member = online_members[0]
    first_member_uri = f"https://{first_member}:{splunk_port}"
    splunk_first_member = SplunkRest(base_url=first_member_uri, auth=(splunk_username, splunk_password), verify=splunk_verify)
    shc_status = splunk_first_member.shc_status()

    # Process SHC status to determine if we're in recovery mode
    shc_content = get_content(shc_status)
    if not shc_content:
        console.print("❌ [red]Failed to get SHC status. Cannot determine cluster state.[/red]")
        return False
    
    captain_info = shc_content.get("captain", {})
    is_dynamic_captain = captain_info.get('dynamic_captain', True)
    
    if is_dynamic_captain:
        console.print("⚠️ [yellow]Cluster is already using dynamic captain mode. No rollback needed.[/yellow]")
        # Run a quick test to show cluster status
        test_action(config, console)
        return False
    
    # If we're here, we need to perform the rollback by cycling through all members
    console.print("🔄 Switching all cluster members to dynamic captain mode...")
    
    for member in online_members:
        member_uri = f"https://{member}:{splunk_port}"

        splunk = SplunkRest(base_url=member_uri, auth=(splunk_username, splunk_password), verify=splunk_verify)
        result = splunk.set_sh_dynamic_captain()
        
        if result.get('success') and result.get('http_code', 500) < 300:
            console.print(f"  ✅ Successfully set dynamic captain mode on {member}")
        else:
            console.print(f"  ❌ Failed to set dynamic captain mode on {member}. Details: {result.get('details', 'Unknown error')}")
            console.print("Continuing with other members...")
    

    max_attempts = 12
    attempt = 0
    sleep_seconds = 10 
    
    while attempt < max_attempts:
        console.print(f"💤  Sleeping {sleep_seconds} s to allow the cluster to accept the new configuration... ⏳")
        time.sleep(sleep_seconds)

        shc_status = splunk_first_member.shc_status()
        shc_success, sh_members = process_shc_status(console=console, shc_status=shc_status)
        
        kv_status = splunk_first_member.kv_status()
        kv_success, kv_members, kv_captain = process_kvstore_status(console=console, kv_status=kv_status)

        if kv_success and shc_success and kv_captain and set(sh_members) == set(kv_members) == set(all_members):
            console.print("✅ Cluster appears to be back online.")
            break  # Exit the loop if successful
        
        attempt += 1
    
    if attempt == max_attempts:
        console.print(f"  ❌ Could not establish cluster health after {max_attempts * sleep_seconds}s...")
        
    # Run a test action to verify the cluster status after rollback
    console.print("🔍 Verifying cluster status after rollback...")
    test_action(config, console)
    
    console.print("✅ [green]Rollback procedure completed.[/green]")

def setup_console() -> Console:
    """Initialize and configure the Rich console"""
    return Console()

def main():
    # Create the parser
    parser = argparse.ArgumentParser(
        description='Splunk Search Head Cluster (SHC) management tool for testing, recovery, and rollback.'
    )
    
    # Positional argument for the action, with limited choices
    parser.add_argument(
        "action",
        choices=["test", "recover", "rollback"],
        help="Action to perform: test, recover, or rollback."
    )
    
    # Add the configuration file argument
    parser.add_argument(
        'config_file',
        help='Path to the YAML configuration file'
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Initialize console
    console = setup_console()
    console.print(Panel("[bold blue]Search Head Cluster DR utility[/bold blue] :wrench:", expand=False))
    console.print(f"⚙️  Reading SHC DR configuration file [yellow]{args.config_file}[/yellow]")
    
    # Load configuration
    config = load_config(args.config_file, console)
    if not config:
        sys.exit(1)

    # Execute the specified action
    if args.action == "test":
        test_action(config, console)
    elif args.action == "recover":
        recover_action(config, console)
    elif args.action == "rollback":
        rollback_action(config, console)

if __name__ == "__main__":
    main()
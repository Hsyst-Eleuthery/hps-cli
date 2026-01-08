import asyncio
import aiohttp
import socketio
import json
import os
import hashlib
import base64
import time
import threading
import uuid
from pathlib import Path
import mimetypes
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import tempfile
import sqlite3
import ssl
import struct
import secrets
import sys
import argparse
import getpass
from datetime import datetime
import shutil
import platform
import subprocess
import re
from typing import Dict, List, Optional, Any, Callable
import signal
import pickle
import atexit
import grp
import pwd
import stat
import fcntl
import multiprocessing
import setproctitle
import traceback
import select

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("HPS-CLI")

class ControllerFileMonitor:
    def __init__(self, client_core, display):
        self.client_core = client_core
        self.display = display
        self.controller_file = os.path.join(os.path.expanduser("~"), ".hps_cli", "controller_hpscli")
        self.controller_dir = os.path.dirname(self.controller_file)
        self.logs_dir = os.path.join(self.controller_dir, "logs")
        self.is_monitoring = False
        self.monitor_thread = None
        self.last_modified = 0
        self.command_lock = threading.Lock()
        self.pid_file = os.path.join(self.controller_dir, "controller.pid")
        self.active_commands = {}
        self.loop = None
        self.connection_state = None

        os.makedirs(self.controller_dir, exist_ok=True)
        os.makedirs(self.logs_dir, exist_ok=True)

        self.current_command_id = None
        self.current_log_file = None
        self.command_callbacks = {}
        self.cleanup_old_files()

    def cleanup_old_files(self):
        try:
            if os.path.exists(self.pid_file):
                with open(self.pid_file, 'r') as f:
                    old_pid = int(f.read().strip())
                    try:
                        os.kill(old_pid, 0)
                        os.kill(old_pid, signal.SIGTERM)
                    except:
                        pass
                os.remove(self.pid_file)

            if os.path.exists(self.controller_file):
                try:
                    content = self.read_controller_file()
                    if content.startswith(self.logs_dir):
                        log_file = content
                        if os.path.exists(log_file):
                            os.remove(log_file)
                except:
                    pass
                try:
                    os.remove(self.controller_file)
                except:
                    pass

            for f in os.listdir(self.logs_dir):
                file_path = os.path.join(self.logs_dir, f)
                if os.path.isfile(file_path):
                    try:
                        os.remove(file_path)
                    except:
                        pass
        except Exception as e:
            self.display.print_error(f"Cleanup error: {e}")

    def read_controller_file(self):
        try:
            with open(self.controller_file, 'r') as f:
                return f.read().strip()
        except:
            return ""

    def write_controller_file(self, content):
        try:
            with open(self.controller_file, 'w') as f:
                f.write(content)
        except Exception as e:
            self.display.print_error(f"Write controller error: {e}")

    def start_monitoring(self):
        if self.is_monitoring:
            return

        with open(self.pid_file, 'w') as f:
            f.write(str(os.getpid()))

        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.display.print_success("Controller file monitor started")

    def stop_monitoring(self):
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.cleanup_old_files()

    def _monitor_loop(self):
        self.display.print_info(f"Monitoring controller file: {self.controller_file}")

        while self.is_monitoring:
            try:
                if not os.path.exists(self.controller_file):
                    time.sleep(0.1)
                    continue

                current_modified = os.path.getmtime(self.controller_file)
                if current_modified > self.last_modified:
                    self.last_modified = current_modified

                    with self.command_lock:
                        content = self.read_controller_file()

                        if content and not content.startswith(self.logs_dir):
                            command_content = content
                            self.display.print_info(f"Received command from controller: {command_content}")

                            command_id = str(uuid.uuid4())
                            log_file = os.path.join(self.logs_dir, f"{command_id}.log")

                            self.write_controller_file(log_file)

                            threading.Thread(
                                target=self._execute_command_with_log,
                                args=(command_id, log_file, command_content),
                                daemon=True
                            ).start()

            except Exception as e:
                self.display.print_error(f"Monitor error: {e}")

            time.sleep(0.1)

    def _write_log_status(self, log_file, status, message=""):
        try:
            with open(log_file, 'w') as f:
                f.write(f"{status}\n")
                if message:
                    f.write(f"{message}\n")
        except Exception as e:
            self.display.print_error(f"Write log error: {e}")

    def _append_log_result(self, log_file, result):
        try:
            with open(log_file, 'a') as f:
                f.write(f"{result}\n")
        except Exception as e:
            self.display.print_error(f"Append log error: {e}")

    def _read_log_file(self, log_file):
        try:
            if not os.path.exists(log_file):
                return None
            with open(log_file, 'r') as f:
                lines = f.readlines()
                if len(lines) >= 1:
                    status = lines[0].strip()
                    message = lines[1].strip() if len(lines) > 1 else ""
                    result = lines[2].strip() if len(lines) > 2 else ""
                    return {
                        'status': status,
                        'message': message,
                        'result': result
                    }
                return None
        except Exception as e:
            self.display.print_error(f"Read log error: {e}")
            return None

    def _execute_command_with_log(self, command_id, log_file, command_content):
        try:
            self.active_commands[command_id] = True
            self._write_log_status(log_file, "1", "Command execution started")

            result = self._execute_controller_command(command_content, log_file)

            if result['success']:
                self._write_log_status(log_file, "1", result['output'])
                self._append_log_result(log_file, "1")
            else:
                self._write_log_status(log_file, "0", result['output'])
                self._append_log_result(log_file, "0")

            self.active_commands[command_id] = False

        except Exception as e:
            self.display.print_error(f"Command execution error: {e}")
            self._write_log_status(log_file, "0", str(e))
            self._append_log_result(log_file, "0")

    def _execute_controller_command(self, command_content, log_file):
        try:
            parts = command_content.strip().split()
            if not parts:
                return {'success': False, 'output': 'Empty command'}

            command = parts[0].lower()
            args = parts[1:] if len(parts) > 1 else []

            if command in self.client_core.command_handlers:
                import io
                from contextlib import redirect_stdout, redirect_stderr

                old_stdout = sys.stdout
                old_stderr = sys.stderr
                stdout_capture = io.StringIO()
                stderr_capture = io.StringIO()

                sys.stdout = stdout_capture
                sys.stderr = stderr_capture

                try:
                    self.connection_state = self.client_core.get_connection_state()

                    if command == 'dns-res':
                        self.client_core.command_handlers[command](args, self.connection_state)
                    else:
                        self.client_core.command_handlers[command](args)

                    output = stdout_capture.getvalue()
                    error = stderr_capture.getvalue()

                    if error:
                        output = f"{output}\n{error}"

                    output = output.strip()

                    with sqlite3.connect(self.client_core.db_path, timeout=10) as conn:
                        cursor = conn.cursor()
                        cursor.execute('INSERT INTO cli_history (command, timestamp, success, result) VALUES (?, ?, ?, ?)',
                                     (command_content, time.time(), 1, "Executed via controller"))
                        conn.commit()

                    return {'success': True, 'output': output}

                except Exception as e:
                    output = stdout_capture.getvalue()
                    error = stderr_capture.getvalue()

                    error_msg = f"{str(e)}\n{error}".strip()

                    with sqlite3.connect(self.client_core.db_path, timeout=10) as conn:
                        cursor = conn.cursor()
                        cursor.execute('INSERT INTO cli_history (command, timestamp, success, result) VALUES (?, ?, ?, ?)',
                                     (command_content, time.time(), 0, str(e)))
                        conn.commit()

                    return {'success': False, 'output': error_msg}

                finally:
                    sys.stdout = old_stdout
                    sys.stderr = old_stderr

            else:
                return {'success': False, 'output': f"Unknown command: {command}"}

        except Exception as e:
            return {'success': False, 'output': str(e)}

    def send_command(self, command, args):
        try:
            command_content = f"{command} {' '.join(args)}".strip()

            self.write_controller_file(command_content)

            start_time = time.time()
            timeout = 300
            log_file = None

            while time.time() - start_time < timeout:
                if not os.path.exists(self.controller_file):
                    time.sleep(0.1)
                    continue

                content = self.read_controller_file()
                if content.startswith(self.logs_dir):
                    log_file = content
                    break
                time.sleep(0.1)

            if not log_file:
                return False, "Timeout waiting for log file creation"

            if not os.path.exists(log_file):
                return False, f"Log file not found: {log_file}"

            result = None
            start_wait = time.time()

            while time.time() - start_wait < timeout:
                log_data = self._read_log_file(log_file)

                if log_data:
                    status = log_data['status']
                    message = log_data['message']

                    if status == "1" and log_data.get('result'):
                        result = log_data['result']
                        if result == "1":
                            return True, message if message else "Command executed successfully"
                        else:
                            return False, message if message else "Command failed"

                    elif status == "0":
                        return False, message if message else "Command failed immediately"

                time.sleep(0.1)

            return False, "Timeout waiting for command execution"

        except Exception as e:
            return False, str(e)

class CLIDisplay:
    def __init__(self, no_cli=False):
        self.no_cli = no_cli
        try:
            self.console_width = shutil.get_terminal_size().columns
        except:
            self.console_width = 80
        self.colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'magenta': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'reset': '\033[0m',
            'bold': '\033[1m',
            'dim': '\033[2m',
            'underline': '\033[4m',
            'blink': '\033[5m'
        }
        self.logo_colors = ['cyan', 'magenta', 'yellow', 'green', 'blue']
        self.color_index = 0

    def _next_color(self):
        color = self.logo_colors[self.color_index]
        self.color_index = (self.color_index + 1) % len(self.logo_colors)
        return self.colors[color]

    def print_header(self, text):
        if self.no_cli:
            print(f"\n{'='*80}\n{text}\n{'='*80}")
            return

        border = '╔' + '═' * (self.console_width - 2) + '╗'
        middle = '║' + text.center(self.console_width - 2) + '║'
        print(f"\n{self.colors['bold']}{self._next_color()}{border}{self.colors['reset']}")
        print(f"{self.colors['bold']}{self._next_color()}{middle}{self.colors['reset']}")
        print(f"{self.colors['bold']}{self._next_color()}{border.replace('╔', '╚').replace('╗', '╝')}{self.colors['reset']}\n")

    def print_section(self, text):
        if self.no_cli:
            print(f"\n{text}\n{'-'*len(text)}")
            return

        print(f"\n{self.colors['bold']}{self.colors['magenta']}▐ {text}{self.colors['reset']}")
        print(f"{self.colors['dim']}{'─' * (len(text) + 2)}{self.colors['reset']}")

    def print_success(self, text):
        if self.no_cli:
            print(f"[✓] {text}")
        else:
            print(f"{self.colors['green']}┃ ✓ {text}{self.colors['reset']}")

    def print_error(self, text):
        if self.no_cli:
            print(f"[✗] {text}")
        else:
            print(f"{self.colors['red']}┃ ✗ {text}{self.colors['reset']}")

    def print_warning(self, text):
        if self.no_cli:
            print(f"[!] {text}")
        else:
            print(f"{self.colors['yellow']}┃ ! {text}{self.colors['reset']}")

    def print_alert(self, text):
        if self.no_cli:
            print(f"[ALERT] {text}")
        else:
            print(f"{self.colors['red']}{self.colors['blink']}┃ ⚠ {text}{self.colors['reset']}")

    def print_info(self, text):
        if self.no_cli:
            print(f"[i] {text}")
        else:
            print(f"{self.colors['blue']}┃ ℹ {text}{self.colors['reset']}")

    def print_progress(self, current, total, text="", bar_length=40):
        if self.no_cli:
            if current == total:
                print(f"[{text}] - 100%")
            return

        percent = float(current) / total
        arrow = '█' * int(round(percent * bar_length))
        spaces = '░' * (bar_length - len(arrow))

        bar_color = self.colors['green'] if percent > 0.7 else self.colors['yellow'] if percent > 0.3 else self.colors['red']

        sys.stdout.write(f"\r{bar_color}┃ [{arrow}{spaces}] {int(round(percent * 100))}% - {text}{self.colors['reset']}")
        sys.stdout.flush()

        if current == total:
            print()

    def print_table(self, headers, rows, max_width=80):
        if self.no_cli:
            print(" | ".join(headers))
            print("-+-".join(["-" * len(h) for h in headers]))
            for row in rows:
                print(" | ".join(str(cell) for cell in row))
            return

        col_widths = []
        for i, header in enumerate(headers):
            max_len = len(str(header))
            for row in rows:
                max_len = max(max_len, len(str(row[i])))
            col_widths.append(min(max_len, max_width // len(headers)))

        header_line = " │ ".join(f"{self.colors['bold']}{str(h).ljust(w)}{self.colors['reset']}"
                                for h, w in zip(headers, col_widths))
        separator = "─┼─".join("─" * w for w in col_widths)

        print(f"\n{header_line}")
        print(separator)

        for row_idx, row in enumerate(rows):
            row_line = " │ ".join(str(cell)[:w].ljust(w) for cell, w in zip(row, col_widths))
            if row_idx % 2 == 0:
                row_line = f"{self.colors['dim']}{row_line}{self.colors['reset']}"
            print(row_line)

    def print_key_value(self, key, value, indent=0):
        if self.no_cli:
            print(f"{' ' * indent}{key}: {value}")
        else:
            print(f"{' ' * indent}{self.colors['bold']}┃ {key}:{self.colors['reset']} {value}")

    def print_json(self, data, indent=2):
        formatted = json.dumps(data, indent=indent, ensure_ascii=False)
        if self.no_cli:
            print(formatted)
        else:
            formatted = re.sub(r'"(.*?)":', f'{self.colors["yellow"]}"\\1"{self.colors["reset"]}:', formatted)
            formatted = re.sub(r'(\d+)', f'{self.colors["cyan"]}\\1{self.colors["reset"]}', formatted)
            formatted = re.sub(r'(true|false|null)', f'{self.colors["magenta"]}\\1{self.colors["reset"]}', formatted)
            print(formatted)

    def clear_screen(self):
        if self.no_cli:
            return
        os.system('cls' if platform.system() == 'Windows' else 'clear')

    def get_input(self, prompt, password=False):
        if self.no_cli:
            if password:
                return getpass.getpass(prompt)
            return input(prompt)

        prompt_text = f"{self.colors['cyan']}┃ ➤ {prompt}{self.colors['reset']}"
        if password:
            return getpass.getpass(prompt_text)
        else:
            return input(prompt_text)

    def print_logo(self):
        if self.no_cli:
            return

        logo = f"""
{self.colors['bold']}{self.colors['cyan']}
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║        {self.colors['magenta']}╦ ╦ {self.colors['yellow']}╔═╗ {self.colors['green']}╔═╗      {self.colors['blue']}╔═╗╦  ╦{self.colors['cyan']}                                          ║
║        {self.colors['magenta']}╠═╣ {self.colors['yellow']}╠═╝ {self.colors['green']}╚═╗      {self.colors['blue']}║  ║  ║{self.colors['cyan']}                                          ║
║        {self.colors['magenta']}╩ ╩ {self.colors['yellow']}╩   {self.colors['green']}╚═╝      {self.colors['blue']}╚═╝╩═╝╩{self.colors['cyan']}                                          ║
║                                                                          ║
║                {self.colors['bold']}{self.colors['white']}HPS Command Line Interface{self.colors['cyan']}                                ║
║                {self.colors['dim']}{self.colors['white']}Decentralized P2P Network Client{self.colors['cyan']}                          ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
{self.colors['reset']}"""

        print(logo)

    def print_status_bar(self, user=None, server=None, reputation=None):
        if self.no_cli:
            return

        status = []
        if user:
            status.append(f"{self.colors['green']}👤 {user}")
        if server:
            status.append(f"{self.colors['blue']}🌐 {server}")
        if reputation:
            status.append(f"{self.colors['yellow']}⭐ {reputation}")

        if status:
            status_text = f"{self.colors['dim']}┃{self.colors['reset']} " + f" {self.colors['dim']}│{self.colors['reset']} ".join(status)
            print(f"\n{status_text}")

class CLIPowSolver:
    def __init__(self, display):
        self.display = display
        self.is_solving = False
        self.solution_found = threading.Event()
        self.nonce_solution = None
        self.hashrate_observed = 0.0
        self.start_time = None
        self.total_hashes = 0

    def leading_zero_bits(self, h: bytes) -> int:
        count = 0
        for byte in h:
            if byte == 0:
                count += 8
            else:
                count += bin(byte)[2:].zfill(8).index('1')
                break
        return count

    def calibrate_hashrate(self, seconds: float = 1.0) -> float:
        message = secrets.token_bytes(16)
        end = time.time() + seconds
        count = 0
        nonce = 0

        while time.time() < end:
            data = message + struct.pack(">Q", nonce)
            _ = hashlib.sha256(data).digest()
            nonce += 1
            count += 1

        elapsed = seconds
        return count / elapsed if elapsed > 0 else 0.0

    def solve_challenge(self, challenge: str, target_bits: int, target_seconds: float, action_type: str = "login"):
        if self.is_solving:
            return

        self.is_solving = True
        self.solution_found.clear()
        self.nonce_solution = None
        self.start_time = time.time()
        self.total_hashes = 0

        self.display.print_section(f"Proof of Work - {action_type}")
        self.display.print_info(f"Target bits: {target_bits}")
        self.display.print_info(f"Target time: {target_seconds:.1f}s")

        def solve_thread():
            try:
                challenge_bytes = base64.b64decode(challenge)
                nonce = 0
                hash_count = 0
                last_update = self.start_time
                last_progress_update = self.start_time

                hashrate = self.calibrate_hashrate(0.5)
                self.hashrate_observed = hashrate

                self.display.print_info(f"Estimated hashrate: {hashrate:,.0f} H/s")
                self.display.print_info("Starting mining...")

                current_hashrate = 0.0
                attempts_per_second = 0
                stats_updates = 0

                while self.is_solving and time.time() - self.start_time < 600:
                    data = challenge_bytes + struct.pack(">Q", nonce)
                    hash_result = hashlib.sha256(data).digest()
                    hash_count += 1
                    attempts_per_second += 1
                    self.total_hashes += 1

                    lzb = self.leading_zero_bits(hash_result)

                    current_time = time.time()
                    elapsed = current_time - self.start_time

                    if current_time - last_update >= 1.0:
                        current_hashrate = attempts_per_second / (current_time - last_update)
                        last_update = current_time
                        attempts_per_second = 0

                        if current_time - last_progress_update >= 0.3:
                            progress_percent = min(int(elapsed/target_seconds*100), 99)
                            progress_text = f"Nonce: {nonce:,} | Time: {elapsed:.1f}s | Hashrate: {current_hashrate:,.0f} H/s | Hashes: {self.total_hashes:,}"
                            self.display.print_progress(progress_percent, 100, progress_text)
                            last_progress_update = current_time
                            stats_updates += 1

                    if lzb >= target_bits:
                        solve_time = current_time - self.start_time
                        self.nonce_solution = str(nonce)
                        self.hashrate_observed = current_hashrate

                        self.display.print_progress(100, 100, "Solution found!")
                        self.display.print_success(f"Solution found! Nonce: {nonce:,}")
                        self.display.print_info(f"Total time: {solve_time:.2f}s")
                        self.display.print_info(f"Final hashrate: {current_hashrate:,.0f} H/s")
                        self.display.print_info(f"Total hashes: {self.total_hashes:,}")

                        self.solution_found.set()
                        break

                    nonce += 1

                    if nonce % 10000 == 0:
                        time.sleep(0.001)

                    if nonce % 1000 == 0 and not self.is_solving:
                        break

                if not self.nonce_solution and self.is_solving:
                    self.display.print_error("Time limit exceeded")

            except Exception as e:
                logger.error(f"PoW mining error: {e}")
                self.display.print_error(f"Error: {e}")
            finally:
                self.is_solving = False

        threading.Thread(target=solve_thread, daemon=True).start()

    def wait_for_solution(self, timeout=600):
        return self.solution_found.wait(timeout)

    def stop_solving(self):
        self.is_solving = False

class HPSClientCore:
    def __init__(self, display=None, no_cli=False):
        self.display = display or CLIDisplay(no_cli)
        self.no_cli = no_cli

        self.current_user = None
        self.username = None
        self.password = None
        self.private_key = None
        self.public_key_pem = None
        self.session_id = str(uuid.uuid4())
        self.node_id = hashlib.sha256(self.session_id.encode()).hexdigest()[:32]
        self.connected = False
        self.peers = []
        self.content_cache = {}
        self.dns_cache = {}
        self.local_files = {}
        self.known_servers = []
        self.current_server = None
        self.server_nodes = []
        self.content_verification_cache = {}
        self.node_type = "client"
        self.connection_attempts = 0
        self.max_connection_attempts = 3
        self.reputation = 100
        self.rate_limits = {}
        self.banned_until = None
        self.client_identifier = self.generate_client_identifier()
        self.upload_blocked_until = 0
        self.login_blocked_until = 0
        self.dns_blocked_until = 0
        self.report_blocked_until = 0
        self.ban_duration = 0
        self.ban_reason = ""
        self.pow_solver = CLIPowSolver(self.display)
        self.max_upload_size = 100 * 1024 * 1024
        self.disk_quota = 500 * 1024 * 1024
        self.used_disk_space = 0
        self.private_key_passphrase = None
        self.server_public_keys = {}
        self.session_key = None
        self.server_auth_challenge = None
        self.client_auth_challenge = None
        self.ssl_verify = False
        self.use_ssl = False
        self.backup_server = None
        self.auto_reconnect = True
        self.via_controller = False
        self.active_contract_violations = {}
        self.pending_transfers = []
        self.pending_transfers_by_contract = {}
        self.pending_transfer_accept_id = None
        self.pending_contract_reissue = None
        self.contract_certify_callback = None
        self.contract_transfer_callback = None
        self.contract_reset_callback = None
        self.missing_contract_certify_callback = None
        self.usage_contract_callback = None
        self.pending_usage_contract = None
        self.pending_contract_analyzer_id = None
        self.contract_alert_message = ""
        self.last_pending_transfer_notice = 0.0
        self.last_contract_alert_time = 0.0
        self.last_contract_alert_key = None

        self.stats_data = {
            'session_start': 0,
            'data_sent': 0,
            'data_received': 0,
            'content_downloaded': 0,
            'content_uploaded': 0,
            'dns_registered': 0,
            'pow_solved': 0,
            'pow_time': 0,
            'content_reported': 0,
            'hashes_calculated': 0
        }

        self.loop = None
        self.sio = None
        self.network_thread = None
        self.reconnect_thread = None
        self.is_running = True
        self.reconnect_lock = threading.Lock()
        self.connection_ready = threading.Event()

        self.crypto_dir = os.path.join(os.path.expanduser("~"), ".hps_cli")
        os.makedirs(self.crypto_dir, exist_ok=True)
        self.db_path = os.path.join(self.crypto_dir, "hps_cli.db")

        self.init_database()
        self.load_known_servers()
        self.load_session_state()
        self.setup_cryptography()

        self.start_network_thread()

        self.calculate_disk_usage()

        self.command_handlers = {}
        self.setup_command_handlers()

        self.auth_event = threading.Event()
        self.auth_result = None
        self.upload_event = threading.Event()
        self.upload_result = None
        self.dns_event = threading.Event()
        self.dns_result = None
        self.report_event = threading.Event()
        self.report_result = None
        self.content_event = threading.Event()
        self.content_result = None
        self.search_event = threading.Event()
        self.search_result = None
        self.network_event = threading.Event()
        self.network_result = None
        self.contracts_event = threading.Event()
        self.contracts_result = None
        self.contract_event = threading.Event()
        self.contract_result = None
        self.pending_transfers_event = threading.Event()
        self.pending_transfers_result = None

    def init_database(self):
        with sqlite3.connect(self.db_path, timeout=30) as conn:
            cursor = conn.cursor()

            cursor.execute('PRAGMA journal_mode=WAL')
            cursor.execute('PRAGMA synchronous=NORMAL')
            cursor.execute('PRAGMA foreign_keys=ON')

            cursor.execute('''
CREATE TABLE IF NOT EXISTS cli_network_nodes (
node_id TEXT PRIMARY KEY,
address TEXT NOT NULL,
node_type TEXT NOT NULL,
reputation INTEGER DEFAULT 100,
status TEXT NOT NULL,
last_seen REAL NOT NULL
)
            ''')

            cursor.execute('''
CREATE TABLE IF NOT EXISTS cli_dns_records (
domain TEXT PRIMARY KEY,
content_hash TEXT NOT NULL,
username TEXT NOT NULL,
verified INTEGER DEFAULT 0,
timestamp REAL NOT NULL,
ddns_hash TEXT NOT NULL DEFAULT ''
)
            ''')

            cursor.execute('''
CREATE TABLE IF NOT EXISTS cli_known_servers (
server_address TEXT PRIMARY KEY,
reputation INTEGER DEFAULT 100,
last_connected REAL NOT NULL,
is_active INTEGER DEFAULT 1,
use_ssl INTEGER DEFAULT 0
)
            ''')

            cursor.execute('''
CREATE TABLE IF NOT EXISTS cli_content_cache (
content_hash TEXT PRIMARY KEY,
file_path TEXT NOT NULL,
file_name TEXT NOT NULL,
mime_type TEXT NOT NULL,
size INTEGER NOT NULL,
last_accessed REAL NOT NULL,
title TEXT,
description TEXT,
username TEXT,
signature TEXT,
public_key TEXT,
verified INTEGER DEFAULT 0
)
            ''')

            cursor.execute('''
CREATE TABLE IF NOT EXISTS cli_ddns_cache (
domain TEXT PRIMARY KEY,
ddns_hash TEXT NOT NULL,
content_hash TEXT NOT NULL,
username TEXT NOT NULL,
verified INTEGER DEFAULT 0,
timestamp REAL NOT NULL
)
            ''')

            cursor.execute('''
CREATE TABLE IF NOT EXISTS cli_contracts_cache (
contract_id TEXT PRIMARY KEY,
action_type TEXT NOT NULL,
content_hash TEXT,
domain TEXT,
username TEXT NOT NULL,
signature TEXT,
timestamp REAL NOT NULL,
verified INTEGER DEFAULT 0,
contract_content TEXT
)
            ''')

            cursor.execute('''
CREATE TABLE IF NOT EXISTS cli_settings (
key TEXT PRIMARY KEY,
value TEXT NOT NULL
)
            ''')

            cursor.execute('''
CREATE TABLE IF NOT EXISTS cli_reports (
report_id TEXT PRIMARY KEY,
content_hash TEXT NOT NULL,
reported_user TEXT NOT NULL,
reporter_user TEXT NOT NULL,
timestamp REAL NOT NULL,
status TEXT NOT NULL,
reason TEXT
)
            ''')

            cursor.execute('''
CREATE TABLE IF NOT EXISTS cli_history (
id INTEGER PRIMARY KEY AUTOINCREMENT,
command TEXT NOT NULL,
timestamp REAL NOT NULL,
success INTEGER DEFAULT 0,
result TEXT
)
            ''')

            cursor.execute('''
CREATE TABLE IF NOT EXISTS cli_session (
key TEXT PRIMARY KEY,
value TEXT NOT NULL,
updated REAL NOT NULL
)
            ''')

            cursor.execute('''
CREATE TABLE IF NOT EXISTS cli_stats (
stat_key TEXT PRIMARY KEY,
stat_value INTEGER NOT NULL,
updated REAL NOT NULL
)
            ''')

            cursor.execute('PRAGMA table_info(cli_ddns_cache)')
            ddns_columns = {row[1] for row in cursor.fetchall()}
            if 'signature' not in ddns_columns:
                cursor.execute("ALTER TABLE cli_ddns_cache ADD COLUMN signature TEXT DEFAULT ''")
            if 'public_key' not in ddns_columns:
                cursor.execute("ALTER TABLE cli_ddns_cache ADD COLUMN public_key TEXT DEFAULT ''")

            conn.commit()

    def load_known_servers(self):
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT server_address, use_ssl FROM cli_known_servers WHERE is_active = 1')
            self.known_servers = []
            for row in cursor.fetchall():
                self.known_servers.append(row[0])
                if row[1]:
                    self.use_ssl = True

    def save_known_servers(self):
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            cursor = conn.cursor()
            for server_address in self.known_servers:
                use_ssl = 1 if server_address.startswith('https://') else 0
                cursor.execute(
                    '''INSERT OR REPLACE INTO cli_known_servers
(server_address, last_connected, is_active, use_ssl)
                    VALUES (?, ?, ?, ?)''',
                    (server_address, time.time(), 1, use_ssl)
                )
            conn.commit()

    def load_session_state(self):
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT key, value FROM cli_session')
            for key, value in cursor.fetchall():
                if key == 'current_user':
                    self.current_user = value
                elif key == 'current_server':
                    self.current_server = value
                elif key == 'reputation':
                    self.reputation = int(value)
                elif key == 'username':
                    self.username = value

            cursor.execute('SELECT stat_key, stat_value FROM cli_stats')
            for stat_key, stat_value in cursor.fetchall():
                if stat_key in self.stats_data:
                    self.stats_data[stat_key] = int(stat_value)

    def save_session_state(self):
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            cursor = conn.cursor()
            session_data = [
                ('current_user', str(self.current_user or ''), time.time()),
                ('current_server', str(self.current_server or ''), time.time()),
                ('reputation', str(self.reputation), time.time()),
                ('username', str(self.username or ''), time.time())
            ]

            for key, value, updated in session_data:
                cursor.execute('INSERT OR REPLACE INTO cli_session (key, value, updated) VALUES (?, ?, ?)',
                             (key, value, updated))

            for stat_key, stat_value in self.stats_data.items():
                cursor.execute('INSERT OR REPLACE INTO cli_stats (stat_key, stat_value, updated) VALUES (?, ?, ?)',
                             (stat_key, stat_value, time.time()))

            conn.commit()

    def calculate_disk_usage(self):
        if os.path.exists(self.crypto_dir):
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(self.crypto_dir):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    if os.path.exists(fp):
                        total_size += os.path.getsize(fp)
            self.used_disk_space = total_size

    def generate_client_identifier(self):
        machine_id = hashlib.sha256(str(uuid.getnode()).encode()).hexdigest()
        return hashlib.sha256((machine_id + self.session_id).encode()).hexdigest()

    def setup_cryptography(self):
        private_key_path = os.path.join(self.crypto_dir, "private_key.pem")
        public_key_path = os.path.join(self.crypto_dir, "public_key.pem")
        browser_dir = os.path.join(os.path.expanduser("~"), ".hps_browser")
        browser_private_path = os.path.join(browser_dir, "private_key.pem")
        browser_public_path = os.path.join(browser_dir, "public_key.pem")

        if os.path.exists(browser_private_path) and os.path.exists(browser_public_path):
            try:
                with open(browser_private_path, "rb") as f:
                    browser_private = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
                with open(browser_public_path, "rb") as f:
                    browser_public = f.read()
                use_browser_keys = True
                if os.path.exists(public_key_path):
                    try:
                        with open(public_key_path, "rb") as f:
                            cli_public = f.read()
                        use_browser_keys = (cli_public != browser_public)
                    except Exception:
                        use_browser_keys = True
                if use_browser_keys:
                    if os.path.exists(private_key_path):
                        try:
                            shutil.copy2(private_key_path, private_key_path + ".bak")
                            shutil.copy2(public_key_path, public_key_path + ".bak")
                        except Exception:
                            pass
                    self.private_key = browser_private
                    self.public_key_pem = browser_public
                    self.save_keys()
                    if not self.no_cli:
                        self.display.print_info("Using shared keys from HPS Browser.")
                    return
            except Exception as e:
                if not self.no_cli:
                    self.display.print_warning(f"Failed to load HPS Browser keys: {e}")

        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            try:
                with open(private_key_path, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
                with open(public_key_path, "rb") as f:
                    self.public_key_pem = f.read()
                if not self.no_cli:
                    self.display.print_info("Cryptographic keys loaded from local storage.")
            except Exception as e:
                self.display.print_error(f"Error loading existing keys: {e}")
                self.generate_keys()
        else:
            self.generate_keys()

    def generate_keys(self):
        try:
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
            self.public_key_pem = self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            if not self.no_cli:
                self.display.print_info("New cryptographic keys generated.")
            self.save_keys()
        except Exception as e:
            self.display.print_error(f"Error generating keys: {e}")

    def save_keys(self):
        try:
            private_key_path = os.path.join(self.crypto_dir, "private_key.pem")
            public_key_path = os.path.join(self.crypto_dir, "public_key.pem")

            with open(private_key_path, "wb") as f:
                f.write(self.private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption()
                        ))

            with open(public_key_path, "wb") as f:
                f.write(self.public_key_pem)

            if not self.no_cli:
                self.display.print_info("Cryptographic keys saved locally.")
        except Exception as e:
            self.display.print_error(f"Error saving keys: {e}")

    def start_network_thread(self):
        def run_network():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)

            ssl_context = None
            if self.use_ssl:
                ssl_context = ssl.create_default_context()
                if not self.ssl_verify:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

            self.sio = socketio.AsyncClient(
                ssl_verify=ssl_context if ssl_context else False,
                reconnection=True,
                reconnection_attempts=5,
                reconnection_delay=1,
                reconnection_delay_max=5,
                request_timeout=120
            )
            self.setup_socket_handlers()

            self.connection_ready.set()
            self.loop.run_forever()

        self.network_thread = threading.Thread(target=run_network, daemon=True)
        self.network_thread.start()
        self.connection_ready.wait(timeout=10)

    def setup_socket_handlers(self):
        @self.sio.event
        async def connect():
            self.connected = True
            self.display.print_success(f"Connected to server {self.current_server}")
            self.connection_attempts = 0
            await self.sio.emit('request_server_auth_challenge', {})

        @self.sio.event
        async def disconnect():
            self.connected = False
            self.display.print_warning(f"Disconnected from server {self.current_server}")
            if self.auto_reconnect and self.is_running:
                self.start_reconnect_thread()

        @self.sio.event
        async def connect_error(data):
            self.display.print_error(f"Connection error: {data}")

        @self.sio.event
        async def server_auth_challenge(data):
            challenge = data.get('challenge')
            server_public_key_b64 = data.get('server_public_key')
            server_signature_b64 = data.get('signature')

            if not all([challenge, server_public_key_b64, server_signature_b64]):
                self.display.print_error("Server authentication challenge incomplete")
                return

            try:
                server_public_key = serialization.load_pem_public_key(base64.b64decode(server_public_key_b64), backend=default_backend())
                server_public_key.verify(
                    base64.b64decode(server_signature_b64),
                    challenge.encode('utf-8'),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )

                self.server_public_keys[self.current_server] = server_public_key_b64

                client_challenge = secrets.token_urlsafe(32)
                self.client_auth_challenge = client_challenge

                client_signature = self.private_key.sign(
                    client_challenge.encode('utf-8'),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )

                await self.sio.emit('verify_server_auth_response', {
                    'client_challenge': client_challenge,
                    'client_signature': base64.b64encode(client_signature).decode('utf-8'),
                    'client_public_key': base64.b64encode(self.public_key_pem).decode('utf-8')
                })

            except InvalidSignature:
                self.display.print_error("Invalid server signature")
            except Exception as e:
                self.display.print_error(f"Server authentication error: {str(e)}")

        @self.sio.event
        async def server_auth_result(data):
            success = data.get('success', False)
            if success:
                self.display.print_info("Server authenticated successfully")
                if hasattr(self, 'pending_login'):
                    await self.request_usage_contract()
            else:
                error = data.get('error', 'Unknown error')
                self.display.print_error(f"Server authentication failed: {error}")

        @self.sio.event
        async def pow_challenge(data):
            if 'error' in data:
                error = data['error']
                self.display.print_error(f"PoW challenge error: {error}")
                if 'blocked_until' in data:
                    blocked_until = data['blocked_until']
                    duration = blocked_until - time.time()
                    self.handle_ban(duration, "Rate limit exceeded")
                return

            challenge = data.get('challenge')
            target_bits = data.get('target_bits')
            target_seconds = data.get('target_seconds', 30.0)
            action_type = data.get('action_type', 'login')

            self.display.print_info(f"PoW challenge received: {target_bits} bits")

            self.pow_solver.solve_challenge(challenge, target_bits, target_seconds, action_type)

            if self.pow_solver.wait_for_solution():
                nonce = self.pow_solver.nonce_solution
                hashrate = self.pow_solver.hashrate_observed
                pow_time = time.time() - self.pow_solver.start_time

                self.stats_data['pow_solved'] += 1
                self.stats_data['pow_time'] += pow_time
                self.stats_data['hashes_calculated'] += self.pow_solver.total_hashes

                if action_type == "login":
                    await self.send_authentication(nonce, hashrate)
                elif action_type == "upload":
                    if hasattr(self, 'pending_upload'):
                        await self._upload_file(*self.pending_upload, nonce, hashrate)
                elif action_type == "dns":
                    if hasattr(self, 'pending_dns'):
                        await self._register_dns(*self.pending_dns, nonce, hashrate)
                elif action_type == "report":
                    if hasattr(self, 'pending_report'):
                        await self._report_content(*self.pending_report, nonce, hashrate)
                elif action_type == "usage_contract":
                    if self.usage_contract_callback:
                        self.usage_contract_callback(nonce, hashrate)
                        self.usage_contract_callback = None
                elif action_type == "contract_certify":
                    if self.contract_certify_callback:
                        self.contract_certify_callback(nonce, hashrate)
                        self.contract_certify_callback = None
                    elif self.missing_contract_certify_callback:
                        self.missing_contract_certify_callback(nonce, hashrate)
                        self.missing_contract_certify_callback = None
                elif action_type == "contract_transfer":
                    if self.contract_transfer_callback:
                        self.contract_transfer_callback(nonce, hashrate)
                        self.contract_transfer_callback = None
                elif action_type == "contract_reset":
                    if self.contract_reset_callback:
                        self.contract_reset_callback(nonce, hashrate)
                        self.contract_reset_callback = None
            else:
                self.display.print_error("PoW solution failed")

        @self.sio.event
        async def usage_contract_required(data):
            threading.Thread(
                target=self.start_usage_contract_flow,
                args=(data,),
                daemon=True
            ).start()

        @self.sio.event
        async def usage_contract_status(data):
            success = data.get('success', False)
            if not success:
                error = data.get('error', 'Unknown error')
                self.display.print_error(f"Usage contract error: {error}")
                return
            if not data.get('required', False):
                await self.request_pow_challenge("login")

        @self.sio.event
        async def usage_contract_ack(data):
            success = data.get('success', False)
            if success:
                self.display.print_info("Usage contract accepted. Starting login PoW...")
                await self.request_pow_challenge("login")
            else:
                error = data.get('error', 'Unknown error')
                self.display.print_error(f"Usage contract rejected: {error}")

        @self.sio.event
        async def authentication_result(data):
            success = data.get('success', False)
            if success:
                username = data.get('username')
                reputation = data.get('reputation', 100)
                self.current_user = username
                self.username = username
                self.reputation = reputation
                self.stats_data['session_start'] = time.time()

                if self.via_controller:
                    print("Login successful")
                else:
                    self.display.print_success(f"Login successful: {username}")
                    self.display.print_info(f"Reputation: {reputation}")

                if self.current_server and self.current_server not in self.known_servers:
                    self.known_servers.append(self.current_server)
                    self.save_known_servers()

                self.auth_result = data
                self.auth_event.set()

                await self.join_network()
                await self.sync_client_files()
                await self.sync_client_dns_files()
                await self.sync_client_contracts()
                await self.request_pending_transfers()
                self.save_session_state()
                if hasattr(self, 'pending_login'):
                    del self.pending_login
            else:
                error = data.get('error', 'Unknown error')
                if self.via_controller:
                    print(f"Login failed: {error}")
                else:
                    self.display.print_error(f"Login failed: {error}")
                self.auth_result = data
                self.auth_event.set()
                if hasattr(self, 'pending_login'):
                    del self.pending_login

        @self.sio.event
        async def content_response(data):
            if 'error' in data:
                error = data['error']
                if error == 'contract_violation':
                    self.handle_contract_violation_response("content", data)
                    self.content_result = data
                    self.content_event.set()
                    return
                if self.via_controller:
                    print(f"Content error: {error}")
                else:
                    self.display.print_error(f"Content error: {error}")
                self.content_result = {'error': error}
                self.content_event.set()
                return

            content_b64 = data.get('content')
            title = data.get('title', 'No title')
            description = data.get('description', '')
            mime_type = data.get('mime_type', 'text/plain')
            username = data.get('username', 'Unknown')
            signature = data.get('signature', '')
            public_key = data.get('public_key', '')
            verified = data.get('verified', False)
            content_hash = data.get('content_hash', '')
            contracts = data.get('contracts', []) or []

            try:
                content = base64.b64decode(content_b64)
                self.stats_data['data_received'] += len(content)
                self.stats_data['content_downloaded'] += 1

                integrity_ok = True
                actual_hash = hashlib.sha256(content).hexdigest()
                if actual_hash != content_hash:
                    integrity_ok = False
                    if not self.via_controller:
                        self.display.print_warning("File integrity compromised!")

                self.save_content_to_storage(content_hash, content, {
                    'title': title,
                    'description': description,
                    'mime_type': mime_type,
                    'username': username,
                    'signature': signature,
                    'public_key': public_key,
                    'verified': verified
                })

                content_info = {
                    'title': title,
                    'description': description,
                    'mime_type': mime_type,
                    'username': username,
                    'signature': signature,
                    'public_key': public_key,
                    'verified': verified,
                    'content': content,
                    'content_hash': content_hash,
                    'reputation': data.get('reputation', 100),
                    'integrity_ok': integrity_ok,
                    'contracts': contracts,
                    'original_owner': data.get('original_owner', username),
                    'certifier': data.get('certifier', '')
                }

                if contracts:
                    self.store_contracts(contracts)

                self.content_result = content_info
                self.content_event.set()
                self.save_session_state()

            except Exception as e:
                if self.via_controller:
                    print(f"Error decoding content: {e}")
                else:
                    self.display.print_error(f"Error decoding content: {e}")
                self.content_result = {'error': str(e)}
                self.content_event.set()

        @self.sio.event
        async def publish_result(data):
            success = data.get('success', False)
            if success:
                content_hash = data.get('content_hash')
                self.stats_data['content_uploaded'] += 1
                if self.via_controller:
                    print(f"Upload successful! Hash: {content_hash}")
                else:
                    self.display.print_success(f"Upload successful! Hash: {content_hash}")
                self.upload_result = data
                self.upload_event.set()
                self.save_session_state()
            else:
                error = data.get('error', 'Unknown error')
                if self.via_controller:
                    print(f"Upload failed: {error}")
                else:
                    self.display.print_error(f"Upload failed: {error}")
                self.upload_result = data
                self.upload_event.set()
            if hasattr(self, 'pending_upload'):
                del self.pending_upload

        @self.sio.event
        async def dns_result(data):
            success = data.get('success', False)
            if success:
                domain = data.get('domain')
                self.stats_data['dns_registered'] += 1
                if self.via_controller:
                    print(f"DNS registered: {domain}")
                else:
                    self.display.print_success(f"DNS registered: {domain}")
                self.dns_result = data
                self.dns_event.set()
                self.save_session_state()
            else:
                error = data.get('error', 'Unknown error')
                if self.via_controller:
                    print(f"DNS registration failed: {error}")
                else:
                    self.display.print_error(f"DNS registration failed: {error}")
                self.dns_result = data
                self.dns_event.set()
            if hasattr(self, 'pending_dns'):
                del self.pending_dns

        @self.sio.event
        async def dns_resolution(data):
            success = data.get('success', False)
            if success:
                domain = data.get('domain')
                content_hash = data.get('content_hash')
                username = data.get('username')
                verified = data.get('verified', False)
                contracts = data.get('contracts', []) or []
                certifier = data.get('certifier', '')

                if self.via_controller:
                    print(content_hash)
                else:
                    self.display.print_success(f"DNS resolved: {domain} -> {content_hash}")
                    self.display.print_info(f"Owner: {username}")
                    self.display.print_info(f"Verified: {'Yes' if verified else 'No'}")
                    if certifier:
                        self.display.print_info(f"Certifier: {certifier}")

                with sqlite3.connect(self.db_path, timeout=10) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
INSERT OR REPLACE INTO cli_dns_records
(domain, content_hash, username, verified, timestamp, ddns_hash)
VALUES (?, ?, ?, ?, ?, ?)
                        ''', (domain, content_hash, username, verified, time.time(), ""))
                    conn.commit()

                if contracts:
                    self.store_contracts(contracts)

                self.dns_result = data
                self.dns_event.set()
            else:
                error = data.get('error', 'Unknown error')
                if error == 'contract_violation':
                    self.handle_contract_violation_response("domain", data)
                    self.dns_result = data
                    self.dns_event.set()
                    return
                if self.via_controller:
                    print(f"DNS resolution failed: {error}")
                else:
                    self.display.print_error(f"DNS resolution failed: {error}")
                self.dns_result = data
                self.dns_event.set()

        @self.sio.event
        async def search_results(data):
            if 'error' in data:
                error = data['error']
                if self.via_controller:
                    print(f"Search error: {error}")
                else:
                    self.display.print_error(f"Search error: {error}")
                self.search_result = {'error': error}
                self.search_event.set()
                return

            results = data.get('results', [])
            if self.via_controller:
                for result in results:
                    print(f"{result.get('content_hash')}|{result.get('title')}|{result.get('username')}")
            self.search_result = results
            self.search_event.set()

        @self.sio.event
        async def network_state(data):
            if 'error' in data:
                self.network_result = {'error': data['error']}
                self.network_event.set()
                return

            self.network_result = data
            self.network_event.set()

        @self.sio.event
        async def report_result(data):
            success = data.get('success', False)
            if success:
                self.stats_data['content_reported'] += 1
                if self.via_controller:
                    print("Content reported successfully!")
                else:
                    self.display.print_success("Content reported successfully!")
                self.report_result = data
                self.report_event.set()
                self.save_session_state()
            else:
                error = data.get('error', 'Unknown error')
                if self.via_controller:
                    print(f"Report failed: {error}")
                else:
                    self.display.print_error(f"Report failed: {error}")
                self.report_result = data
                self.report_event.set()
            if hasattr(self, 'pending_report'):
                del self.pending_report

        @self.sio.event
        async def contracts_results(data):
            if 'error' in data:
                self.contracts_result = {'error': data.get('error')}
                self.contracts_event.set()
                return
            contracts = data.get('contracts', []) or []
            if contracts:
                self.store_contracts(contracts)
            self.contracts_result = contracts
            self.contracts_event.set()

        @self.sio.event
        async def contract_details(data):
            if 'error' in data:
                self.contract_result = {'error': data.get('error')}
                self.contract_event.set()
                return
            contract_info = data.get('contract')
            if contract_info:
                self.save_contract_to_storage(contract_info)
            self.contract_result = contract_info
            self.contract_event.set()
            if self.pending_contract_analyzer_id and contract_info:
                self.pending_contract_analyzer_id = None
                threading.Thread(
                    target=self.show_contract_analyzer,
                    args=(contract_info,),
                    daemon=True
                ).start()

        @self.sio.event
        async def contract_violation_notice(data):
            self.handle_contract_violation_notice(data)

        @self.sio.event
        async def contract_violation_cleared(data):
            content_hash = data.get('content_hash')
            domain = data.get('domain')
            if domain:
                self.active_contract_violations.pop(("domain", domain), None)
            elif content_hash:
                self.active_contract_violations.pop(("content", content_hash), None)
            if not self.active_contract_violations and not self.pending_transfers:
                self.clear_contract_alert()

        @self.sio.event
        async def pending_transfers(data):
            if 'error' in data:
                return
            transfers = data.get('transfers', []) or []
            self.pending_transfers = transfers
            self.pending_transfers_by_contract = {t.get('contract_id'): t for t in transfers if t.get('contract_id')}
            self.pending_transfers_result = transfers
            self.pending_transfers_event.set()
            if transfers:
                self.show_contract_alert("Você está com pendências contratuais. Use 'contracts pending'.")
                now = time.time()
                if now - self.last_pending_transfer_notice > 10:
                    self.last_pending_transfer_notice = now
                    self.display.print_warning(
                        f"Você tem {len(transfers)} pendência(s) contratual(is)."
                    )
            else:
                if not self.active_contract_violations:
                    self.clear_contract_alert()

        @self.sio.event
        async def pending_transfer_notice(data):
            count = data.get('count', 1)
            if count > 0:
                self.show_contract_alert("Você está com pendências contratuais. Use 'contracts pending'.")
                now = time.time()
                if now - self.last_pending_transfer_notice > 10:
                    self.last_pending_transfer_notice = now
                    self.display.print_warning(
                        f"Você tem {count} pendência(s) contratual(is)."
                    )

        @self.sio.event
        async def transfer_payload(data):
            if 'error' in data:
                self.display.print_error(f"Falha ao obter transferencia: {data.get('error')}")
                return
            content_b64 = data.get('content_b64')
            if not content_b64:
                self.display.print_error("Arquivo de transferencia nao encontrado.")
                return
            try:
                content = base64.b64decode(content_b64)
            except Exception:
                self.display.print_error("Arquivo de transferencia invalido.")
                return
            title = data.get('title', '')
            description = data.get('description', '')
            mime_type = data.get('mime_type', 'application/octet-stream')
            threading.Thread(
                target=self.upload_content_bytes,
                args=(title, description, mime_type, content),
                daemon=True
            ).start()

        @self.sio.event
        async def reject_transfer_ack(data):
            success = data.get('success', False)
            if not success:
                error = data.get('error', 'Erro desconhecido')
                self.display.print_error(f"Falha ao rejeitar transferencia: {error}")
                return
            self.display.print_success("Transferencia rejeitada.")
            await self.request_pending_transfers()

        @self.sio.event
        async def renounce_transfer_ack(data):
            success = data.get('success', False)
            if not success:
                error = data.get('error', 'Erro desconhecido')
                self.display.print_error(f"Falha ao renunciar transferencia: {error}")
                return
            self.display.print_success("Transferencia renunciada.")
            await self.request_pending_transfers()

        @self.sio.event
        async def invalidate_contract_ack(data):
            success = data.get('success', False)
            if not success:
                error = data.get('error', 'Erro desconhecido')
                self.display.print_error(f"Falha ao invalidar contrato: {error}")
                return
            self.clear_contract_alert()
            self.handle_contract_reissue_success(data)

        @self.sio.event
        async def certify_contract_ack(data):
            success = data.get('success', False)
            if not success:
                error = data.get('error', 'Erro desconhecido')
                self.display.print_error(f"Falha ao certificar contrato: {error}")
                return
            self.clear_contract_alert()
            self.display.print_success("Contrato certificado com sucesso.")

        @self.sio.event
        async def certify_missing_contract_ack(data):
            success = data.get('success', False)
            if not success:
                error = data.get('error', 'Erro desconhecido')
                self.display.print_error(f"Falha ao certificar contrato: {error}")
                return
            self.clear_contract_alert()
            self.display.print_success("Contrato certificado com sucesso.")

        @self.sio.event
        async def sync_client_dns_files(data):
            try:
                dns_files = data.get('dns_files', [])
                await self.process_client_dns_files_sync(dns_files)
            except Exception as e:
                self.display.print_error(f"Erro ao sincronizar DNS do cliente: {e}")

        @self.sio.event
        async def client_dns_files_response(data):
            try:
                missing_dns = data.get('missing_dns', [])
                await self.share_missing_dns_files(missing_dns)
            except Exception as e:
                self.display.print_error(f"Erro ao compartilhar DNS: {e}")

        @self.sio.event
        async def sync_client_contracts(data):
            try:
                contracts = data.get('contracts', [])
                await self.process_client_contracts_sync(contracts)
            except Exception as e:
                self.display.print_error(f"Erro ao sincronizar contratos do cliente: {e}")

        @self.sio.event
        async def client_contracts_response(data):
            try:
                missing_contracts = data.get('missing_contracts', [])
                await self.share_missing_contracts(missing_contracts)
            except Exception as e:
                self.display.print_error(f"Erro ao compartilhar contratos: {e}")

        @self.sio.event
        async def request_ddns_from_client(data):
            try:
                domain = data.get('domain')
                if not domain:
                    return
                await self.send_ddns_to_server(domain)
            except Exception as e:
                self.display.print_error(f"Erro ao compartilhar DNS: {e}")

        @self.sio.event
        async def request_contract_from_client(data):
            try:
                contract_id = data.get('contract_id')
                if not contract_id:
                    return
                await self.send_contract_to_server(contract_id)
            except Exception as e:
                self.display.print_error(f"Erro ao compartilhar contrato: {e}")

        @self.sio.event
        async def ddns_from_client(data):
            try:
                domain = data.get('domain')
                ddns_content_b64 = data.get('ddns_content')
                content_hash = data.get('content_hash')
                username = data.get('username')
                signature = data.get('signature', '')
                public_key = data.get('public_key', '')
                verified = data.get('verified', False)
                if not all([domain, ddns_content_b64, content_hash, username]):
                    return
                ddns_content = base64.b64decode(ddns_content_b64)
                self.save_ddns_to_storage(domain, ddns_content, {
                    'content_hash': content_hash,
                    'username': username,
                    'verified': verified,
                    'signature': signature,
                    'public_key': public_key
                })
            except Exception as e:
                self.display.print_error(f"Erro ao processar DNS da rede: {e}")

        @self.sio.event
        async def contract_from_client(data):
            try:
                contract_id = data.get('contract_id')
                contract_content_b64 = data.get('contract_content')
                if not contract_id or not contract_content_b64:
                    return
                contract_info = {
                    'contract_id': contract_id,
                    'action_type': data.get('action_type', ''),
                    'content_hash': data.get('content_hash'),
                    'domain': data.get('domain'),
                    'username': data.get('username', ''),
                    'signature': data.get('signature', ''),
                    'verified': data.get('verified', False),
                    'timestamp': time.time(),
                    'contract_content': base64.b64decode(contract_content_b64).decode('utf-8', errors='replace')
                }
                self.save_contract_to_storage(contract_info)
            except Exception as e:
                self.display.print_error(f"Erro ao processar contrato da rede: {e}")

    def start_reconnect_thread(self):
        if self.reconnect_thread and self.reconnect_thread.is_alive():
            return

        def reconnect():
            time.sleep(2)
            if not self.is_running:
                return
            with self.reconnect_lock:
                if not self.connected and self.current_server and self.is_running:
                    self.display.print_info(f"Attempting to reconnect to {self.current_server}...")
                    asyncio.run_coroutine_threadsafe(self._reconnect(), self.loop)

        self.reconnect_thread = threading.Thread(target=reconnect, daemon=True)
        self.reconnect_thread.start()

    async def _reconnect(self):
        try:
            if self.sio and not self.sio.connected:
                await self.sio.connect(self.current_server, wait_timeout=10)
        except Exception as e:
            self.display.print_error(f"Reconnection failed: {e}")

    async def request_pow_challenge(self, action_type):
        if not self.connected:
            self.display.print_error("Not connected to server")
            return

        await self.sio.emit('request_pow_challenge', {
            'client_identifier': self.client_identifier,
            'action_type': action_type
        })

    async def request_usage_contract(self):
        if not self.connected:
            return
        if not self.username:
            return
        await self.sio.emit('request_usage_contract', {
            'username': self.username
        })

    async def request_pending_transfers(self):
        if not self.connected:
            return
        await self.sio.emit('get_pending_transfers', {})

    async def send_authentication(self, pow_nonce, hashrate_observed):
        if not self.connected:
            return

        password_hash = hashlib.sha256(self.password.encode()).hexdigest()

        if not self.client_auth_challenge:
            self.display.print_error("Client authentication challenge missing")
            return

        client_challenge_signature = self.private_key.sign(
            self.client_auth_challenge.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        await self.sio.emit('authenticate', {
            'username': self.username,
            'password_hash': password_hash,
            'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
            'node_type': 'client',
            'client_identifier': self.client_identifier,
            'pow_nonce': pow_nonce,
            'hashrate_observed': hashrate_observed,
            'client_challenge_signature': base64.b64encode(client_challenge_signature).decode('utf-8'),
            'client_challenge': self.client_auth_challenge
        })

    async def join_network(self):
        if not self.connected or not self.current_user:
            return

        await self.sio.emit('join_network', {
            'node_id': self.node_id,
            'address': f"client_{self.client_identifier}",
            'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
            'username': self.current_user,
            'node_type': 'client',
            'client_identifier': self.client_identifier
        })

    async def sync_client_files(self):
        if not self.connected or not self.current_user:
            return

        files = []
        content_dir = os.path.join(self.crypto_dir, "content")
        if os.path.exists(content_dir):
            for filename in os.listdir(content_dir):
                if filename.endswith('.dat'):
                    file_path = os.path.join(content_dir, filename)
                    content_hash = filename[:-4]
                    file_size = os.path.getsize(file_path)
                    files.append({
                        'content_hash': content_hash,
                        'file_name': filename,
                        'file_size': file_size
                    })

        await self.sio.emit('sync_client_files', {
            'files': files
        })

    async def sync_client_dns_files(self):
        if not self.connected or not self.current_user:
            return
        dns_files = []
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT domain, ddns_hash FROM cli_ddns_cache')
            for row in cursor.fetchall():
                dns_files.append({'domain': row[0], 'ddns_hash': row[1]})
        await self.sio.emit('sync_client_dns_files', {
            'dns_files': dns_files
        })
        await self.process_client_dns_files_sync(dns_files)

    async def sync_client_contracts(self):
        if not self.connected or not self.current_user:
            return
        contracts = []
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT contract_id, content_hash, domain FROM cli_contracts_cache')
            for row in cursor.fetchall():
                contracts.append({
                    'contract_id': row[0],
                    'content_hash': row[1],
                    'domain': row[2]
                })
        await self.sio.emit('sync_client_contracts', {
            'contracts': contracts
        })
        await self.process_client_contracts_sync(contracts)

    def handle_ban(self, duration, reason):
        self.banned_until = time.time() + duration
        self.ban_duration = duration
        self.ban_reason = reason
        self.display.print_warning(f"Banned for {int(duration)}s: {reason}")

    def save_content_to_storage(self, content_hash, content, metadata=None):
        content_dir = os.path.join(self.crypto_dir, "content")
        os.makedirs(content_dir, exist_ok=True)

        file_path = os.path.join(content_dir, f"{content_hash}.dat")
        with open(file_path, 'wb') as f:
            f.write(content)

        with sqlite3.connect(self.db_path, timeout=10) as conn:
            cursor = conn.cursor()
            if metadata:
                cursor.execute('''
INSERT OR REPLACE INTO cli_content_cache
(content_hash, file_path, file_name, mime_type, size, last_accessed, title, description, username, signature, public_key, verified)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        content_hash, file_path, f"{content_hash}.dat",
                        metadata.get('mime_type', 'application/octet-stream'),
                        len(content), time.time(),
                        metadata.get('title', ''),
                        metadata.get('description', ''),
                        metadata.get('username', ''),
                        metadata.get('signature', ''),
                        metadata.get('public_key', ''),
                        metadata.get('verified', 0)
                    ))
            else:
                cursor.execute('''
INSERT OR REPLACE INTO cli_content_cache
(content_hash, file_path, file_name, mime_type, size, last_accessed)
VALUES (?, ?, ?, ?, ?, ?)
                    ''', (content_hash, file_path, f"{content_hash}.dat", 'application/octet-stream', len(content), time.time()))
            conn.commit()

        self.calculate_disk_usage()

    def save_ddns_to_storage(self, domain, ddns_content, metadata=None):
        ddns_hash = hashlib.sha256(ddns_content).hexdigest()
        ddns_dir = os.path.join(self.crypto_dir, "ddns")
        os.makedirs(ddns_dir, exist_ok=True)
        file_path = os.path.join(ddns_dir, f"{ddns_hash}.ddns")
        with open(file_path, 'wb') as f:
            f.write(ddns_content)

        with sqlite3.connect(self.db_path, timeout=10) as conn:
            cursor = conn.cursor()
            if metadata:
                cursor.execute('''
INSERT OR REPLACE INTO cli_ddns_cache
(domain, ddns_hash, content_hash, username, verified, timestamp, signature, public_key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    domain,
                    ddns_hash,
                    metadata.get('content_hash', ''),
                    metadata.get('username', ''),
                    1 if metadata.get('verified') else 0,
                    time.time(),
                    metadata.get('signature', ''),
                    metadata.get('public_key', '')
                ))
            conn.commit()

        return ddns_hash

    def get_ddns_record(self, domain):
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT ddns_hash, content_hash, username, verified, signature, public_key
                              FROM cli_ddns_cache WHERE domain = ?''', (domain,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                'ddns_hash': row[0],
                'content_hash': row[1],
                'username': row[2],
                'verified': bool(row[3]),
                'signature': row[4] or '',
                'public_key': row[5] or ''
            }

    async def send_ddns_to_server(self, domain):
        record = self.get_ddns_record(domain)
        if not record:
            return
        ddns_file_path = os.path.join(self.crypto_dir, "ddns", f"{record['ddns_hash']}.ddns")
        if not os.path.exists(ddns_file_path):
            return
        with open(ddns_file_path, 'rb') as f:
            ddns_content = f.read()
        await self.sio.emit('ddns_from_client', {
            'domain': domain,
            'ddns_content': base64.b64encode(ddns_content).decode('utf-8'),
            'content_hash': record['content_hash'],
            'username': record['username'],
            'signature': record['signature'],
            'public_key': record['public_key'],
            'verified': record['verified']
        })

    def save_contract_to_storage(self, contract_info):
        contract_id = contract_info.get('contract_id')
        if not contract_id:
            return
        contract_content = contract_info.get('contract_content')
        contract_text = None
        if isinstance(contract_content, bytes):
            contract_text = contract_content.decode('utf-8', errors='replace')
        elif isinstance(contract_content, str):
            contract_text = contract_content

        if contract_text:
            contracts_dir = os.path.join(self.crypto_dir, "contracts")
            os.makedirs(contracts_dir, exist_ok=True)
            contract_path = os.path.join(contracts_dir, f"{contract_id}.contract")
            with open(contract_path, 'wb') as f:
                f.write(contract_text.encode('utf-8'))

        with sqlite3.connect(self.db_path, timeout=10) as conn:
            cursor = conn.cursor()
            verified_value = contract_info.get('integrity_ok')
            if verified_value is None:
                verified_value = contract_info.get('verified')
            cursor.execute('''
INSERT OR REPLACE INTO cli_contracts_cache
(contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                contract_id,
                contract_info.get('action_type', ''),
                contract_info.get('content_hash'),
                contract_info.get('domain'),
                contract_info.get('username', ''),
                contract_info.get('signature', ''),
                contract_info.get('timestamp', time.time()),
                1 if verified_value else 0,
                contract_text
            ))
            conn.commit()

    def store_contracts(self, contracts):
        for contract_info in contracts or []:
            self.save_contract_to_storage(contract_info)

    def get_contract_record(self, contract_id):
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT action_type, content_hash, domain, username, signature, verified, contract_content
                              FROM cli_contracts_cache WHERE contract_id = ?''', (contract_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                'action_type': row[0],
                'content_hash': row[1],
                'domain': row[2],
                'username': row[3],
                'signature': row[4] or '',
                'verified': bool(row[5]),
                'contract_content': row[6]
            }

    async def send_contract_to_server(self, contract_id):
        record = self.get_contract_record(contract_id)
        if not record:
            return
        contracts_dir = os.path.join(self.crypto_dir, "contracts")
        contract_path = os.path.join(contracts_dir, f"{contract_id}.contract")
        contract_text = record.get('contract_content')
        if os.path.exists(contract_path):
            with open(contract_path, 'rb') as f:
                contract_text = f.read().decode('utf-8', errors='replace')
        if not contract_text:
            return
        await self.sio.emit('contract_from_client', {
            'contract_id': contract_id,
            'contract_content': base64.b64encode(contract_text.encode('utf-8')).decode('utf-8'),
            'action_type': record.get('action_type', ''),
            'content_hash': record.get('content_hash'),
            'domain': record.get('domain'),
            'username': record.get('username', ''),
            'signature': record.get('signature', ''),
            'verified': record.get('verified', False)
        })

    def get_contract_from_cache(self, contract_id):
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content
                              FROM cli_contracts_cache WHERE contract_id = ?''', (contract_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                'contract_id': row[0],
                'action_type': row[1],
                'content_hash': row[2],
                'domain': row[3],
                'username': row[4],
                'signature': row[5],
                'timestamp': row[6],
                'verified': bool(row[7]),
                'integrity_ok': bool(row[7]),
                'contract_content': row[8]
            }

    def load_cached_content(self, content_hash):
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT file_path, title, description, mime_type, username, signature, public_key, verified
                              FROM cli_content_cache WHERE content_hash = ?''', (content_hash,))
            row = cursor.fetchone()
            if not row:
                return None
            file_path, title, description, mime_type, username, signature, public_key, verified = row
        if not os.path.exists(file_path):
            return None
        with open(file_path, 'rb') as f:
            content = f.read()
        return {
            'content': content,
            'title': title or '',
            'description': description or '',
            'mime_type': mime_type or 'application/octet-stream',
            'username': username or '',
            'signature': signature or '',
            'public_key': public_key or '',
            'verified': bool(verified)
        }

    async def _connect_to_server(self, server_address):
        try:
            if self.sio and self.sio.connected:
                await self.sio.disconnect()

            protocol = "https" if server_address.startswith('https://') else "http"
            if not server_address.startswith(('http://', 'https://')):
                server_address = f"{protocol}://{server_address}"

            self.display.print_info(f"Connecting to {server_address}...")

            await self.sio.connect(server_address, wait_timeout=10)
            return True

        except Exception as e:
            self.display.print_error(f"Connection error: {e}")
            return False

    async def _connect_and_login(self, args):
        if len(args) < 3:
            return False

        server, username, password = args[0], args[1], args[2]

        self.current_server = server
        self.username = username
        self.password = password
        self.pending_login = True

        self.display.print_info(f"Connecting to {server}...")

        try:
            result = await self._connect_to_server(server)
            if not result:
                return False

            self.auth_event.clear()
            self.auth_result = None

            start_time = time.time()
            while time.time() - start_time < 30:
                if self.auth_event.is_set():
                    break
                await asyncio.sleep(0.1)

            if self.auth_event.is_set():
                return self.auth_result and self.auth_result.get('success')
            else:
                return False

        except Exception as e:
            self.display.print_error(f"Connection error: {e}")
            return False

    def setup_command_handlers(self):
        self.command_handlers = {
            'login': self.handle_login,
            'logout': self.handle_logout,
            'upload': self.handle_upload,
            'download': self.handle_download,
            'dns-reg': self.handle_dns_register,
            'dns-res': self.handle_dns_resolve,
            'search': self.handle_search,
            'network': self.handle_network,
            'stats': self.handle_stats,
            'report': self.handle_report,
            'security': self.handle_security,
            'contracts': self.handle_contracts,
            'contract': self.handle_contracts,
            'actions': self.handle_hps_actions,
            'hps-actions': self.handle_hps_actions,
            'servers': self.handle_servers,
            'keys': self.handle_keys,
            'sync': self.handle_sync,
            'history': self.handle_history,
            'clear': self.handle_clear,
            'help': self.handle_help,
            'exit': self.handle_exit,
            'quit': self.handle_exit,
        }

    def handle_login(self, args):
        if len(args) < 3:
            if not self.no_cli:
                server = self.display.get_input("Server (ex: localhost:8080): ")
                username = self.display.get_input("Username: ")
                password = self.display.get_input("Password: ", password=True)
            else:
                self.display.print_error("Usage: login <server> <username> <password>")
                return
        else:
            server, username, password = args[0], args[1], args[2]

        self.current_server = server
        self.username = username
        self.password = password
        self.pending_login = True

        self.display.print_info(f"Connecting to {server}...")

        try:
            future = asyncio.run_coroutine_threadsafe(self._connect_and_login([server, username, password]), self.loop)
            result = future.result(30)
        except Exception as e:
            self.display.print_error(f"Connection failed: {e}")
            result = None

        if result:
            if self.via_controller:
                print("Login successful")
            else:
                self.display.print_success("Login successful!")
        else:
            if self.via_controller:
                print("Login failed")
            else:
                self.display.print_error("Login failed")

    def handle_logout(self, args):
        if not self.current_user:
            self.display.print_warning("You are not logged in")
            return

        self.current_user = None
        self.username = None
        self.connected = False
        if self.sio and self.sio.connected:
            self.run_async(self.sio.disconnect())
        if self.via_controller:
            print("Logout successful")
        else:
            self.display.print_success("Logout successful")
        self.save_session_state()

    def handle_upload(self, args):
        if not self.current_user:
            self.display.print_error("You need to be logged in to upload")
            return

        if len(args) < 1:
            if not self.no_cli:
                file_path = self.display.get_input("File path: ")
                title = self.display.get_input("Title (Enter for filename): ")
                description = self.display.get_input("Description (optional): ")
                mime_type = self.display.get_input("MIME type (Enter for auto-detect): ")
            else:
                self.display.print_error("Usage: upload <file_path> [--title TITLE] [--desc DESCRIPTION] [--mime MIME_TYPE]")
                return
        else:
            file_path = args[0]
            title = None
            description = ""
            mime_type = None

            i = 1
            while i < len(args):
                if args[i] == '--title' and i+1 < len(args):
                    title = args[i+1]
                    i += 2
                elif args[i] == '--desc' and i+1 < len(args):
                    description = args[i+1]
                    i += 2
                elif args[i] == '--mime' and i+1 < len(args):
                    mime_type = args[i+1]
                    i += 2
                else:
                    self.display.print_error(f"Unknown argument: {args[i]}")
                    return

        if not os.path.exists(file_path):
            self.display.print_error(f"File not found: {file_path}")
            return

        if title is None:
            title = os.path.basename(file_path)

        if mime_type is None:
            mime_type, _ = mimetypes.guess_type(file_path)
            if not mime_type:
                mime_type = 'application/octet-stream'

        if not self.via_controller:
            self.display.print_section("File Upload")
            self.display.print_info(f"File: {file_path}")
            self.display.print_info(f"Title: {title}")
            self.display.print_info(f"MIME type: {mime_type}")

        try:
            with open(file_path, 'rb') as f:
                content = f.read()

            if len(content) > self.max_upload_size:
                self.display.print_error(f"File too large. Max size: {self.max_upload_size // (1024*1024)}MB")
                return

            file_hash = hashlib.sha256(content).hexdigest()
            details = [
                ("FILE_NAME", os.path.basename(file_path)),
                ("FILE_SIZE", str(len(content))),
                ("FILE_HASH", file_hash),
                ("TITLE", title),
                ("MIME", mime_type),
                ("DESCRIPTION", description),
                ("PUBLIC_KEY", base64.b64encode(self.public_key_pem).decode('utf-8'))
            ]
            app_name = self.extract_app_name(title)
            if app_name:
                details.append(("APP", app_name))
            transfer_type, transfer_to, transfer_app = self.parse_transfer_title(title)
            if title == '(HPS!dns_change){change_dns_owner=true, proceed=true}':
                domain, new_owner = self.parse_domain_transfer_target(content)
                if new_owner:
                    transfer_type = "domain"
                    transfer_to = new_owner
                if domain:
                    details.append(("DOMAIN", domain))
            if transfer_to:
                details.append(("TRANSFER_TO", transfer_to))
            if transfer_type:
                details.append(("TRANSFER_TYPE", transfer_type))
            if transfer_app:
                details.append(("APP", transfer_app))

            allowed_actions = ["upload_file"]
            if title == '(HPS!dns_change){change_dns_owner=true, proceed=true}':
                allowed_actions = ["transfer_domain"]
            elif transfer_type == "file":
                allowed_actions = ["transfer_content"]
            elif transfer_type == "api_app":
                allowed_actions = ["transfer_api_app"]
            elif title.startswith('(HPS!api)'):
                allowed_actions = ["upload_file", "change_api_app"]

            contract_template = self.build_contract_template(allowed_actions[0], details)
            if self.via_controller or self.no_cli:
                try:
                    contract_text = self.sign_contract_template(contract_template, allowed_actions)
                except ValueError as e:
                    self.display.print_error(str(e))
                    return
            else:
                contract_text = self.prompt_contract_signature(contract_template, allowed_actions, "Contrato (Upload)")
                if not contract_text:
                    self.display.print_error("Contrato de upload não aceito")
                    return

            full_content = content + contract_text.encode('utf-8')
            content_hash = hashlib.sha256(content).hexdigest()

            signature = self.private_key.sign(
                content,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )

            self.save_content_to_storage(content_hash, content, {
                'title': title,
                'description': description,
                'mime_type': mime_type,
                'username': self.current_user,
                'signature': base64.b64encode(signature).decode('utf-8'),
                'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
                'verified': True
            })

            self.pending_upload = (content_hash, title, description, mime_type, len(content), signature, full_content)
            self.upload_event.clear()
            self.upload_result = None

            self.run_async(self.request_pow_challenge("upload"))

            if not self.upload_event.wait(300):
                self.display.print_error("Upload timeout")
                if hasattr(self, 'pending_upload'):
                    del self.pending_upload
                return

            if self.upload_result and self.upload_result.get('success'):
                hash_value = self.upload_result.get('content_hash', '')
                if self.via_controller:
                    print(f"Upload completed. Hash: {hash_value}")
                else:
                    self.display.print_success(f"Upload completed successfully!")
                    self.display.print_info(f"Hash: {hash_value}")
            else:
                if self.via_controller:
                    print("Upload failed")
                else:
                    self.display.print_error("Upload failed")

        except Exception as e:
            if self.via_controller:
                print(f"Upload error: {e}")
            else:
                self.display.print_error(f"Upload error: {e}")

    def upload_content_bytes(self, title, description, mime_type, content):
        if not self.current_user:
            self.display.print_error("You need to be logged in to upload")
            return

        if not title:
            title = "upload.bin"

        if mime_type is None:
            mime_type, _ = mimetypes.guess_type(title)
            if not mime_type:
                mime_type = 'application/octet-stream'

        if len(content) > self.max_upload_size:
            self.display.print_error(f"File too large. Max size: {self.max_upload_size // (1024*1024)}MB")
            return
        file_hash = hashlib.sha256(content).hexdigest()
        details = [
            ("FILE_NAME", title),
            ("FILE_SIZE", str(len(content))),
            ("FILE_HASH", file_hash),
            ("TITLE", title),
            ("MIME", mime_type),
            ("DESCRIPTION", description),
            ("PUBLIC_KEY", base64.b64encode(self.public_key_pem).decode('utf-8'))
        ]
        app_name = self.extract_app_name(title)
        if app_name:
            details.append(("APP", app_name))
        transfer_type, transfer_to, transfer_app = self.parse_transfer_title(title)
        if title == '(HPS!dns_change){change_dns_owner=true, proceed=true}':
            domain, new_owner = self.parse_domain_transfer_target(content)
            if new_owner:
                transfer_type = "domain"
                transfer_to = new_owner
            if domain:
                details.append(("DOMAIN", domain))
        if transfer_to:
            details.append(("TRANSFER_TO", transfer_to))
        if transfer_type:
            details.append(("TRANSFER_TYPE", transfer_type))
        if transfer_app:
            details.append(("APP", transfer_app))

        allowed_actions = ["upload_file"]
        if title == '(HPS!dns_change){change_dns_owner=true, proceed=true}':
            allowed_actions = ["transfer_domain"]
        elif transfer_type == "file":
            allowed_actions = ["transfer_content"]
        elif transfer_type == "api_app":
            allowed_actions = ["transfer_api_app"]
        elif title.startswith('(HPS!api)'):
            allowed_actions = ["upload_file", "change_api_app"]

        contract_template = self.build_contract_template(allowed_actions[0], details)
        if self.via_controller or self.no_cli:
            try:
                contract_text = self.sign_contract_template(contract_template, allowed_actions)
            except ValueError as e:
                self.display.print_error(str(e))
                return
        else:
            contract_text = self.prompt_contract_signature(contract_template, allowed_actions, "Contrato (Upload)")
            if not contract_text:
                self.display.print_error("Contrato de upload não aceito")
                return

        full_content = content + contract_text.encode('utf-8')
        content_hash = hashlib.sha256(content).hexdigest()

        signature = self.private_key.sign(
            content,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        self.save_content_to_storage(content_hash, content, {
            'title': title,
            'description': description,
            'mime_type': mime_type,
            'username': self.current_user,
            'signature': base64.b64encode(signature).decode('utf-8'),
            'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
            'verified': True
        })

        self.pending_upload = (content_hash, title, description, mime_type, len(content), signature, full_content)
        self.upload_event.clear()
        self.upload_result = None

        self.run_async(self.request_pow_challenge("upload"))

        if not self.upload_event.wait(300):
            self.display.print_error("Upload timeout")
            if hasattr(self, 'pending_upload'):
                del self.pending_upload
            return

        if self.upload_result and self.upload_result.get('success'):
            hash_value = self.upload_result.get('content_hash', '')
            self.display.print_success(f"Upload completed successfully! Hash: {hash_value}")
        else:
            self.display.print_error("Upload failed")

    async def _upload_file(self, content_hash, title, description, mime_type, size, signature, full_content, pow_nonce, hashrate_observed):
        if not self.connected:
            return

        try:
            content_b64 = base64.b64encode(full_content).decode('utf-8')
            data = {
                'content_hash': content_hash,
                'title': title,
                'description': description,
                'mime_type': mime_type,
                'size': size,
                'signature': base64.b64encode(signature).decode('utf-8'),
                'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
                'content_b64': content_b64,
                'pow_nonce': pow_nonce,
                'hashrate_observed': hashrate_observed
            }

            await self.sio.emit('publish_content', data)

        except Exception as e:
            self.display.print_error(f"Upload error: {e}")

    def handle_download(self, args):
        if not self.current_user:
            self.display.print_error("You need to be logged in to download")
            return

        if len(args) < 1:
            self.display.print_error("Usage: download <hash_or_url> [--output PATH]")
            return

        target = args[0]
        output_path = None

        i = 1
        while i < len(args):
            if args[i] == '--output' and i+1 < len(args):
                output_path = args[i+1]
                i += 2
            else:
                self.display.print_error(f"Unknown argument: {args[i]}")
                return

        if not self.via_controller:
            self.display.print_section("Content Download")

        if target.startswith('hps://'):
            if target == 'hps://rede':
                self.display.print_info("Showing P2P network...")
                self.handle_network([])
                return
            elif target.startswith('hps://dns:'):
                domain = target[len('hps://dns:'):]
                self.display.print_info(f"Resolving DNS: {domain}")
                self.handle_dns_resolve([domain])
                return
            else:
                content_hash = target[len('hps://'):]
        else:
            content_hash = target

        self.content_event.clear()
        self.content_result = None

        self.run_async(self._request_content_by_hash(content_hash))

        if not self.content_event.wait(30):
            self.display.print_error("Download timeout")
            return

        if self.content_result and 'error' not in self.content_result:
            content_info = self.content_result

            if output_path is None:
                output_path = f"./{content_info['title']}"
                if not os.path.splitext(output_path)[1]:
                    ext = mimetypes.guess_extension(content_info['mime_type']) or '.dat'
                    output_path += ext

            try:
                with open(output_path, 'wb') as f:
                    f.write(content_info['content'])

                if self.via_controller:
                    print(output_path)
                else:
                    self.display.print_success(f"Content saved to: {output_path}")
                    self.display.print_info(f"Title: {content_info['title']}")
                    self.display.print_info(f"Author: {content_info['username']}")
                    self.display.print_info(f"Type: {content_info['mime_type']}")
                    self.display.print_info(f"Size: {len(content_info['content'])} bytes")
                    self.display.print_info(f"Verified: {'Yes' if content_info['verified'] else 'No'}")
            except Exception as e:
                if self.via_controller:
                    print(f"Error saving file: {e}")
                else:
                    self.display.print_error(f"Error saving file: {e}")
        else:
            if self.via_controller:
                print("Download failed")
            else:
                self.display.print_error("Download failed")

    async def _request_content_by_hash(self, content_hash):
        if not self.connected:
            return

        await self.sio.emit('request_content', {'content_hash': content_hash})

    def handle_dns_register(self, args):
        if not self.current_user:
            self.display.print_error("You need to be logged in to register DNS")
            return

        if len(args) < 2:
            self.display.print_error("Usage: dns-reg <domain> <content_hash>")
            return

        domain = args[0].lower()
        content_hash = args[1]

        if not self.is_valid_domain(domain):
            self.display.print_error("Invalid domain. Use only letters, numbers and hyphens.")
            return

        if not self.via_controller:
            self.display.print_section("DNS Registration")
            self.display.print_info(f"Domain: {domain}")
            self.display.print_info(f"Hash: {content_hash}")

        details = [
            ("DOMAIN", domain),
            ("CONTENT_HASH", content_hash),
            ("PUBLIC_KEY", base64.b64encode(self.public_key_pem).decode('utf-8'))
        ]
        contract_template = self.build_contract_template("register_dns", details)
        if self.via_controller or self.no_cli:
            try:
                contract_text = self.sign_contract_template(contract_template, ["register_dns"])
            except ValueError as e:
                self.display.print_error(str(e))
                return
        else:
            contract_text = self.prompt_contract_signature(contract_template, ["register_dns"], "Contrato (DNS)")
            if not contract_text:
                self.display.print_error("Contrato de DNS não aceito")
                return

        ddns_content = self.create_ddns_file(domain, content_hash)
        ddns_hash = hashlib.sha256(ddns_content).hexdigest()
        ddns_content_full = ddns_content + contract_text.encode('utf-8')

        header_end = b'### :END START'
        if header_end in ddns_content:
            _, ddns_data_signed = ddns_content.split(header_end, 1)
        else:
            ddns_data_signed = ddns_content

        signature = self.private_key.sign(
            ddns_data_signed,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        self.save_ddns_to_storage(domain, ddns_content, {
            'content_hash': content_hash,
            'username': self.current_user,
            'verified': True,
            'signature': base64.b64encode(signature).decode('utf-8'),
            'public_key': base64.b64encode(self.public_key_pem).decode('utf-8')
        })

        self.pending_dns = (domain, ddns_content_full, signature)
        self.dns_event.clear()
        self.dns_result = None

        self.run_async(self.request_pow_challenge("dns"))

        if not self.dns_event.wait(300):
            self.display.print_error("DNS registration timeout")
            if hasattr(self, 'pending_dns'):
                del self.pending_dns
            return

        if self.dns_result and self.dns_result.get('success'):
            self.display.print_success("DNS registered successfully!")
        else:
            self.display.print_error("DNS registration failed")

        if self.dns_result and self.dns_result.get('success'):
            if self.via_controller:
                print("DNS registered successfully")
            else:
                self.display.print_success("DNS registered successfully!")
        else:
            if self.via_controller:
                print("DNS registration failed")
            else:
                self.display.print_error("DNS registration failed")

    def register_dns_with_hash(self, domain, content_hash):
        if not self.current_user:
            self.display.print_error("You need to be logged in to register DNS")
            return
        if not self.is_valid_domain(domain):
            self.display.print_error("Invalid domain. Use only letters, numbers and hyphens.")
            return

        details = [
            ("DOMAIN", domain),
            ("CONTENT_HASH", content_hash),
            ("PUBLIC_KEY", base64.b64encode(self.public_key_pem).decode('utf-8'))
        ]
        contract_template = self.build_contract_template("register_dns", details)
        if self.via_controller or self.no_cli:
            try:
                contract_text = self.sign_contract_template(contract_template, ["register_dns"])
            except ValueError as e:
                self.display.print_error(str(e))
                return
        else:
            contract_text = self.prompt_contract_signature(contract_template, ["register_dns"], "Contrato (DNS)")
            if not contract_text:
                self.display.print_error("Contrato de DNS não aceito")
                return

        ddns_content = self.create_ddns_file(domain, content_hash)
        ddns_content_full = ddns_content + contract_text.encode('utf-8')

        header_end = b'### :END START'
        if header_end in ddns_content:
            _, ddns_data_signed = ddns_content.split(header_end, 1)
        else:
            ddns_data_signed = ddns_content

        signature = self.private_key.sign(
            ddns_data_signed,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        self.save_ddns_to_storage(domain, ddns_content, {
            'content_hash': content_hash,
            'username': self.current_user,
            'verified': True,
            'signature': base64.b64encode(signature).decode('utf-8'),
            'public_key': base64.b64encode(self.public_key_pem).decode('utf-8')
        })

        self.pending_dns = (domain, ddns_content_full, signature)
        self.dns_event.clear()
        self.dns_result = None

        self.run_async(self.request_pow_challenge("dns"))

        if not self.dns_event.wait(300):
            self.display.print_error("DNS registration timeout")
            if hasattr(self, 'pending_dns'):
                del self.pending_dns
            return

    async def _register_dns(self, domain, ddns_content, signature, pow_nonce, hashrate_observed):
        if not self.connected:
            return

        try:
            ddns_content_b64 = base64.b64encode(ddns_content).decode('utf-8')
            await self.sio.emit('register_dns', {
                'domain': domain,
                'ddns_content': ddns_content_b64,
                'signature': base64.b64encode(signature).decode('utf-8'),
                'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
                'pow_nonce': pow_nonce,
                'hashrate_observed': hashrate_observed
            })
        except Exception as e:
            self.display.print_error(f"DNS registration error: {e}")

    def create_ddns_file(self, domain, content_hash):
        ddns_content = f"""# HSYST P2P SERVICE
### START:
# USER: {self.current_user}
# KEY: {base64.b64encode(self.public_key_pem).decode('utf-8')}
### :END START
### DNS:
# DNAME: {domain} = {content_hash}
### :END DNS
"""
        return ddns_content.encode('utf-8')

    def build_hps_transfer_title(self, transfer_type, target_user, app_name=None):
        if transfer_type == "api_app" and app_name:
            return f"(HPS!transfer){{type={transfer_type}, to={target_user}, app={app_name}}}"
        return f"(HPS!transfer){{type={transfer_type}, to={target_user}}}"

    def build_hps_api_title(self, app_name):
        return f'(HPS!api){{app}}:{{"{app_name}"}}'

    def build_hps_dns_change_title(self):
        return "(HPS!dns_change){change_dns_owner=true, proceed=true}"

    def build_domain_transfer_payload(self, domain, new_owner):
        username = self.current_user or self.username
        lines = [
            "# HSYST P2P SERVICE",
            "### START:",
            f"# USER: {username}",
            "### :END START",
            "### DNS:",
            f"# NEW_DNAME: DOMAIN = {domain}",
            f"# NEW_DOWNER: OWNER = {new_owner}",
            "### :END DNS",
            "### MODIFY:",
            "# change_dns_owner = true",
            "# proceed = true",
            "### :END MODIFY"
        ]
        return "\n".join(lines).encode("utf-8")

    def extract_app_name(self, title):
        match = re.search(r'\(HPS!api\)\{app\}:\{"([^"]+)"\}', title)
        if match:
            return match.group(1).strip()
        return None

    def parse_transfer_title(self, title):
        if not title:
            return None, None, None
        match = re.search(r'\(HPS!transfer\)\{type=([^,}]+),\s*to=([^,}]+)(?:,\s*app=([^}]+))?\}', title)
        if match:
            transfer_type = match.group(1).strip().lower()
            target_user = match.group(2).strip()
            app_name = match.group(3).strip() if match.group(3) else None
            return transfer_type, target_user, app_name
        return None, None, None

    def parse_domain_transfer_target(self, content):
        try:
            content_str = content.decode('utf-8')
        except Exception:
            return None, None
        domain = None
        new_owner = None
        in_dns_section = False
        for line in content_str.splitlines():
            line = line.strip()
            if line == '### DNS:':
                in_dns_section = True
                continue
            if line == '### :END DNS':
                in_dns_section = False
                continue
            if in_dns_section and line.startswith('# NEW_DNAME:'):
                tail = line.split(':', 1)[1].strip()
                if '=' in tail:
                    domain = tail.split('=', 1)[1].strip()
                else:
                    domain = tail.strip()
            if line.startswith('# NEW_DOWNER:'):
                tail = line.split(':', 1)[1].strip()
                if '=' in tail:
                    new_owner = tail.split('=', 1)[1].strip()
                else:
                    new_owner = tail.strip()
        return domain, new_owner

    def build_contract_template(self, action_type, details):
        lines = [
            "# HSYST P2P SERVICE",
            "## CONTRACT:",
            "### DETAILS:",
            f"# ACTION: {action_type}"
        ]
        for key, value in details:
            lines.append(f"# {key}: {value}")
        lines.extend([
            "### :END DETAILS",
            "### START:",
            f"# USER: {self.current_user}",
            "# SIGNATURE: ",
            "### :END START",
            "## :END CONTRACT"
        ])
        return "\n".join(lines) + "\n"

    def build_usage_contract_template(self, terms_text, contract_hash):
        username = self.current_user or self.username
        lines = [
            "# HSYST P2P SERVICE",
            "## CONTRACT:",
            "### DETAILS:",
            "# ACTION: accept_usage",
            f"# USAGE_CONTRACT_HASH: {contract_hash}",
            "### :END DETAILS",
            "### TERMS:"
        ]
        for line in terms_text.splitlines():
            lines.append(f"# {line}")
        lines.extend([
            "### :END TERMS",
            "### START:",
            f"# USER: {username}",
            "# SIGNATURE: ",
            "### :END START",
            "## :END CONTRACT"
        ])
        return "\n".join(lines) + "\n"

    def build_certify_contract_template(self, target_type, target_id, reason=None,
                                        contract_id=None, original_owner=None, original_action=None):
        details = [
            ("TARGET_TYPE", target_type),
            ("TARGET_ID", target_id)
        ]
        if reason:
            details.append(("REASON", reason))
        if contract_id:
            details.append(("SOURCE_CONTRACT", contract_id))
        if original_owner:
            details.append(("ORIGINAL_OWNER", original_owner))
        if original_action:
            details.append(("ORIGINAL_ACTION", original_action))
        return self.build_contract_template("certify_contract", details)

    def parse_contract_info(self, contract_text):
        info = {'action': None, 'user': None, 'signature': None}
        current_section = None
        for line in contract_text.splitlines():
            line = line.strip()
            if line.startswith("### "):
                if line.endswith(":"):
                    current_section = line[4:-1].lower()
            elif line.startswith("### :END "):
                current_section = None
            elif line.startswith("# "):
                if current_section == "details" and line.startswith("# ACTION:"):
                    info['action'] = line.split(":", 1)[1].strip()
                elif current_section == "start" and line.startswith("# USER:"):
                    info['user'] = line.split(":", 1)[1].strip()
                elif current_section == "start" and line.startswith("# SIGNATURE:"):
                    info['signature'] = line.split(":", 1)[1].strip()
        return info

    def validate_contract_text(self, contract_text, expected_action):
        if not contract_text.startswith("# HSYST P2P SERVICE"):
            return False, "Cabeçalho HSYST não encontrado"
        if "## :END CONTRACT" not in contract_text:
            return False, "Final do contrato não encontrado"
        info = self.parse_contract_info(contract_text)
        if not info['action']:
            return False, "Ação não informada no contrato"
        if info['action'] != expected_action:
            return False, f"Ação inválida no contrato (esperado {expected_action})"
        if not info['user']:
            return False, "Usuário não informado no contrato"
        expected_user = self.current_user or self.username
        if info['user'] != expected_user:
            return False, "Usuário do contrato não corresponde ao usuário logado"
        return True, ""

    def validate_contract_text_allowed(self, contract_text, allowed_actions):
        if not contract_text.startswith("# HSYST P2P SERVICE"):
            return False, "Cabeçalho HSYST não encontrado"
        if "## :END CONTRACT" not in contract_text:
            return False, "Final do contrato não encontrado"
        info = self.parse_contract_info(contract_text)
        if not info['action']:
            return False, "Ação não informada no contrato"
        if info['action'] not in allowed_actions:
            return False, f"Ação inválida no contrato (permitido: {', '.join(allowed_actions)})"
        if not info['user']:
            return False, "Usuário não informado no contrato"
        expected_user = self.current_user or self.username
        if info['user'] != expected_user:
            return False, "Usuário do contrato não corresponde ao usuário logado"
        return True, ""

    def apply_contract_signature(self, contract_text):
        lines = contract_text.splitlines()
        signature_index = None
        signed_lines = []
        for idx, line in enumerate(lines):
            if line.strip().startswith("# SIGNATURE:"):
                signature_index = idx
                continue
            signed_lines.append(line)
        if signature_index is None:
            raise ValueError("Linha de assinatura não encontrada no contrato")
        signed_text = "\n".join(signed_lines)
        signature = self.private_key.sign(
            signed_text.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        lines[signature_index] = f"# SIGNATURE: {signature_b64}"
        return "\n".join(lines).strip() + "\n", signature_b64

    def extract_contract_details_lines(self, contract_text):
        if not contract_text:
            return []
        details_lines = []
        in_details = False
        for line in contract_text.splitlines():
            line = line.strip()
            if line == "### DETAILS:":
                in_details = True
                continue
            if line == "### :END DETAILS":
                break
            if in_details and line.startswith("# "):
                details_lines.append(line[2:])
        return details_lines

    def build_contract_summary(self, contract_info, contract_text):
        contract_hash = hashlib.sha256(contract_text.encode('utf-8')).hexdigest() if contract_text else ""
        verified_text = "Sim" if contract_info.get('verified') else "Não"
        integrity_ok = contract_info.get('integrity_ok')
        if integrity_ok is None:
            integrity_ok = contract_info.get('verified', False)
        integrity_text = "OK" if integrity_ok else "ADULTERADO"
        timestamp = contract_info.get('timestamp')
        timestamp_str = ""
        if timestamp:
            try:
                timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                timestamp_str = str(timestamp)
        summary = [
            f"ID: {contract_info.get('contract_id', '')}",
            f"Ação: {contract_info.get('action_type', '')}",
            f"Hash do conteúdo: {contract_info.get('content_hash', '')}",
            f"Domínio: {contract_info.get('domain', '')}",
            f"Usuário: {contract_info.get('username', '')}",
            f"Verificado: {verified_text}",
            f"Integridade: {integrity_text}",
            f"Data: {timestamp_str}",
            f"Hash do contrato: {contract_hash}",
            ""
        ]
        details_lines = self.extract_contract_details_lines(contract_text)
        if details_lines:
            summary.append("Detalhes:")
            summary.extend(details_lines)
        return summary

    def show_contract_analyzer(self, contract_info, title="Analisador de Contratos"):
        contract_text = contract_info.get('contract_content') or ""
        summary_lines = self.build_contract_summary(contract_info, contract_text)
        integrity_ok = contract_info.get('integrity_ok')
        if integrity_ok is None:
            integrity_ok = contract_info.get('verified', False)
        contract_id = contract_info.get('contract_id')
        owner = contract_info.get('username')
        is_owner = bool(self.current_user and owner and self.current_user == owner)

        if self.via_controller:
            print(title)
            for line in summary_lines:
                print(line)
            if contract_text:
                print(contract_text)
            return

        self.display.print_section(title)
        for line in summary_lines:
            print(line)
        if contract_text:
            print(contract_text)

        actions = []
        if contract_id:
            actions.append(("Atualizar detalhes", lambda: self.refresh_contract_analyzer(contract_id)))
        pending_transfer = self.pending_transfers_by_contract.get(contract_id)
        if pending_transfer and pending_transfer.get('target_user') == self.current_user:
            self.display.print_warning(
                f"{pending_transfer.get('original_owner')} quer transferir para você. "
                "Use as ações para aceitar, rejeitar ou renunciar."
            )
            actions.append(("Aceitar transferência", lambda: self.start_transfer_accept(pending_transfer)))
            actions.append(("Rejeitar transferência", lambda: self.start_transfer_reject(pending_transfer)))
            actions.append(("Renunciar transferência", lambda: self.start_transfer_renounce(pending_transfer)))

        if not integrity_ok:
            if is_owner:
                actions.append(("Emitir novo contrato", lambda: self.start_contract_reissue(contract_info)))
            else:
                actions.append(("Certificar contrato", lambda: self.start_contract_certify(contract_info)))
        if is_owner:
            actions.append(("Invalidar contrato", lambda: self.start_contract_invalidate(contract_info)))

        if not actions:
            return

        self.display.print_section("Ações Disponíveis")
        for idx, (label, _) in enumerate(actions, start=1):
            self.display.print_info(f"{idx}) {label}")
        choice = self.display.get_input("Escolha uma ação ou Enter para sair: ").strip()
        if not choice:
            return
        try:
            index = int(choice) - 1
        except ValueError:
            self.display.print_warning("Opção inválida.")
            return
        if 0 <= index < len(actions):
            actions[index][1]()

    def refresh_contract_analyzer(self, contract_id):
        if not contract_id:
            return
        self.pending_contract_analyzer_id = contract_id
        asyncio.run_coroutine_threadsafe(self.sio.emit('get_contract', {'contract_id': contract_id}), self.loop)

    def prompt_contract_signature(self, contract_template, allowed_actions, title="Contrato"):
        if self.via_controller:
            return None
        self.display.print_section(title)
        print(contract_template)
        confirm = self.display.get_input("Assinar contrato? (y/n): ").strip().lower()
        if confirm != 'y':
            return None
        signed_text, _ = self.apply_contract_signature(contract_template)
        signed_text = signed_text.strip()
        valid, error = self.validate_contract_text_allowed(signed_text, allowed_actions)
        if not valid:
            self.display.print_error(error)
            return None
        return signed_text

    def sign_contract_template(self, contract_template, allowed_actions):
        signed_text, _ = self.apply_contract_signature(contract_template)
        signed_text = signed_text.strip()
        valid, error = self.validate_contract_text_allowed(signed_text, allowed_actions)
        if not valid:
            raise ValueError(error)
        return signed_text

    def start_usage_contract_flow(self, data):
        terms_text = data.get('contract_text', '') or ""
        contract_hash = data.get('contract_hash', '')
        if not contract_hash:
            self.display.print_error("Contrato de uso indisponível no servidor.")
            return
        contract_template = self.build_usage_contract_template(terms_text, contract_hash)
        contract_text = self.prompt_contract_signature(contract_template, ["accept_usage"], "Contrato de Uso")
        if not contract_text:
            self.display.print_error("Contrato de uso não aceito. Login cancelado.")
            return

        def do_accept(pow_nonce, hashrate_observed):
            asyncio.run_coroutine_threadsafe(
                self.sio.emit('accept_usage_contract', {
                    'contract_content': base64.b64encode(contract_text.encode('utf-8')).decode('utf-8'),
                    'public_key': base64.b64encode(self.public_key_pem).decode('utf-8'),
                    'client_identifier': self.client_identifier,
                    'pow_nonce': pow_nonce,
                    'hashrate_observed': hashrate_observed
                }),
                self.loop
            )
        self.usage_contract_callback = do_accept
        asyncio.run_coroutine_threadsafe(self.request_pow_challenge("usage_contract"), self.loop)

    def start_contract_invalidate(self, contract_info):
        contract_id = contract_info.get('contract_id')
        if not contract_id:
            return
        def do_invalidate(pow_nonce, hashrate_observed):
            asyncio.run_coroutine_threadsafe(
                self.sio.emit('invalidate_contract', {
                    'contract_id': contract_id,
                    'pow_nonce': pow_nonce,
                    'hashrate_observed': hashrate_observed
                }),
                self.loop
            )
        self.contract_reset_callback = do_invalidate
        asyncio.run_coroutine_threadsafe(self.request_pow_challenge("contract_reset"), self.loop)

    def start_contract_reissue(self, contract_info):
        self.pending_contract_reissue = contract_info
        self.start_contract_invalidate(contract_info)

    def handle_contract_reissue_success(self, data):
        contract_info = self.pending_contract_reissue
        self.pending_contract_reissue = None
        if not contract_info:
            self.display.print_success("Contrato invalidado com sucesso.")
            return
        action_type = contract_info.get('action_type')
        content_hash = contract_info.get('content_hash')
        domain = contract_info.get('domain')
        if action_type == "register_dns" and domain:
            if not content_hash:
                content_hash = self.display.get_input("Hash do conteúdo para DNS: ").strip()
            if not content_hash:
                self.display.print_warning("Hash do conteúdo não informado.")
                return
            self.register_dns_with_hash(domain, content_hash)
            return
        if content_hash:
            cached = self.load_cached_content(content_hash)
            if not cached:
                self.display.print_warning("Arquivo não encontrado no cache local para reenvio.")
                return
            self.upload_content_bytes(
                cached['title'],
                cached.get('description', ''),
                cached.get('mime_type', 'application/octet-stream'),
                cached['content']
            )

    def start_contract_certify(self, contract_info):
        contract_id = contract_info.get('contract_id')
        if not contract_id:
            return
        target_type = "domain" if contract_info.get('domain') else "content"
        target_id = contract_info.get('domain') or contract_info.get('content_hash')
        if not target_id:
            self.display.print_error("Contrato sem alvo válido para certificação.")
            return
        contract_template = self.build_certify_contract_template(
            target_type=target_type,
            target_id=target_id,
            reason="invalid_contract",
            contract_id=contract_id,
            original_owner=contract_info.get('username'),
            original_action=contract_info.get('action_type')
        )
        contract_text = self.prompt_contract_signature(contract_template, ["certify_contract"], "Certificação de Contrato")
        if not contract_text:
            return

        def do_certify(pow_nonce, hashrate_observed):
            payload = {
                'contract_content': base64.b64encode(contract_text.encode('utf-8')).decode('utf-8'),
                'pow_nonce': pow_nonce,
                'hashrate_observed': hashrate_observed,
                'contract_id': contract_id
            }
            asyncio.run_coroutine_threadsafe(self.sio.emit('certify_contract', payload), self.loop)

        self.contract_certify_callback = do_certify
        asyncio.run_coroutine_threadsafe(self.request_pow_challenge("contract_certify"), self.loop)

    def start_missing_contract_certify(self, target_type, target_id):
        contract_template = self.build_certify_contract_template(
            target_type=target_type,
            target_id=target_id,
            reason="missing_contract"
        )
        contract_text = self.prompt_contract_signature(
            contract_template,
            ["certify_contract"],
            "Certificação de Contrato Ausente"
        )
        if not contract_text:
            return

        def do_certify(pow_nonce, hashrate_observed):
            payload = {
                'contract_content': base64.b64encode(contract_text.encode('utf-8')).decode('utf-8'),
                'pow_nonce': pow_nonce,
                'hashrate_observed': hashrate_observed,
                'target_type': target_type,
                'target_id': target_id
            }
            asyncio.run_coroutine_threadsafe(self.sio.emit('certify_missing_contract', payload), self.loop)

        self.missing_contract_certify_callback = do_certify
        asyncio.run_coroutine_threadsafe(self.request_pow_challenge("contract_certify"), self.loop)

    def start_transfer_accept(self, pending_transfer):
        transfer_id = pending_transfer.get('transfer_id')
        if not transfer_id:
            return
        self.pending_transfer_accept_id = transfer_id
        asyncio.run_coroutine_threadsafe(
            self.sio.emit('get_transfer_payload', {'transfer_id': transfer_id}),
            self.loop
        )

    def start_transfer_reject(self, pending_transfer):
        transfer_id = pending_transfer.get('transfer_id')
        if not transfer_id:
            return
        def do_reject(pow_nonce, hashrate_observed):
            asyncio.run_coroutine_threadsafe(
                self.sio.emit('reject_transfer', {
                    'transfer_id': transfer_id,
                    'pow_nonce': pow_nonce,
                    'hashrate_observed': hashrate_observed
                }),
                self.loop
            )
        self.contract_transfer_callback = do_reject
        asyncio.run_coroutine_threadsafe(self.request_pow_challenge("contract_transfer"), self.loop)

    def start_transfer_renounce(self, pending_transfer):
        transfer_id = pending_transfer.get('transfer_id')
        if not transfer_id:
            return
        def do_renounce(pow_nonce, hashrate_observed):
            asyncio.run_coroutine_threadsafe(
                self.sio.emit('renounce_transfer', {
                    'transfer_id': transfer_id,
                    'pow_nonce': pow_nonce,
                    'hashrate_observed': hashrate_observed
                }),
                self.loop
            )
        self.contract_transfer_callback = do_renounce
        asyncio.run_coroutine_threadsafe(self.request_pow_challenge("contract_transfer"), self.loop)

    def show_contract_alert(self, message):
        self.contract_alert_message = message
        self.display.print_alert(message)

    def clear_contract_alert(self):
        self.contract_alert_message = ""
        self.last_contract_alert_key = None

    def handle_contract_violation_notice(self, data):
        violation_type = data.get('violation_type')
        content_hash = data.get('content_hash')
        domain = data.get('domain')
        reason = data.get('reason', 'invalid_contract')
        target = domain or content_hash or "desconhecido"
        message = f"Contrato adulterado: {target}"
        if reason == "missing_contract":
            message = f"Contrato ausente: {target}"
        if domain:
            key = ("domain", domain)
        elif content_hash:
            key = ("content", content_hash)
        else:
            key = ("unknown", target)

        if self.active_contract_violations.get(key) == reason:
            now = time.time()
            if self.last_contract_alert_key == key and now - self.last_contract_alert_time < 10:
                return
            self.last_contract_alert_key = key
            self.last_contract_alert_time = now
        self.active_contract_violations[key] = reason
        self.show_contract_alert("Você está com pendências contratuais. Use 'contracts fix' ou 'contracts pending'.")
        self.display.print_warning(message)

    def handle_contract_violation_response(self, target_type, data):
        reason = data.get('contract_violation_reason', 'invalid_contract')
        target = data.get('domain') if target_type == "domain" else data.get('content_hash')
        message = "Contrato adulterado."
        if reason == "missing_contract":
            message = "Contrato ausente."
        if target:
            message = f"{message} Alvo: {target}"
        if target_type == "domain" and target:
            key = ("domain", target)
        elif target_type == "content" and target:
            key = ("content", target)
        else:
            key = ("unknown", target or "desconhecido")

        if self.active_contract_violations.get(key) == reason:
            now = time.time()
            if self.last_contract_alert_key == key and now - self.last_contract_alert_time < 10:
                return
            self.last_contract_alert_key = key
            self.last_contract_alert_time = now
        self.active_contract_violations[key] = reason
        self.show_contract_alert("Você está com pendências contratuais. Use 'contracts fix' ou 'contracts pending'.")
        self.display.print_warning(message)
        contracts = data.get('contracts', []) or []
        if contracts:
            self.store_contracts(contracts)

    async def process_client_dns_files_sync(self, dns_files):
        domains = [dns_file['domain'] for dns_file in dns_files]
        if not domains:
            return
        await self.sio.emit('request_client_dns_files', {
            'domains': domains
        })

    async def share_missing_dns_files(self, missing_dns):
        for domain in missing_dns:
            await self.send_ddns_to_server(domain)
            await asyncio.sleep(0.1)

    async def process_client_contracts_sync(self, contracts):
        contract_ids = [contract['contract_id'] for contract in contracts]
        if not contract_ids:
            return
        await self.sio.emit('request_client_contracts', {
            'contract_ids': contract_ids,
            'contracts': contracts
        })

    async def share_missing_contracts(self, missing_contracts):
        for contract_id in missing_contracts:
            await self.send_contract_to_server(contract_id)
            await asyncio.sleep(0.1)


    def handle_dns_resolve(self, args, connection_state=None):
        if not self.current_user and not connection_state:
            self.display.print_error("You need to be logged in to resolve DNS")
            return

        if len(args) < 1:
            self.display.print_error("Usage: dns-res <domain>")
            return

        domain = args[0].lower()

        if not self.via_controller:
            self.display.print_section("DNS Resolution")
            self.display.print_info(f"Domain: {domain}")

        self.dns_event.clear()
        self.dns_result = None

        try:
            if connection_state and connection_state.get('connected'):
                self.connected = True
                self.current_server = connection_state.get('current_server')
                self.current_user = connection_state.get('current_user')
                self.sio = connection_state.get('sio')
                self.loop = connection_state.get('loop')

            if not self.connected:
                self.display.print_error("Not connected to server")
                return

            if not self.loop:
                self.display.print_error("Network loop not available")
                return

            future = asyncio.run_coroutine_threadsafe(self._resolve_dns(domain), self.loop)
            future.result(30)
        except Exception as e:
            self.display.print_error(f"DNS resolution error: {e}")
            return

        if not self.dns_event.wait(30):
            self.display.print_error("DNS resolution timeout")
            return

        if self.dns_result and self.dns_result.get('success'):
            content_hash = self.dns_result.get('content_hash')
            username = self.dns_result.get('username')
            verified = self.dns_result.get('verified', False)

            if self.via_controller:
                print(content_hash)
            else:
                self.display.print_success(f"DNS resolved successfully!")
                self.display.print_info(f"Hash: {content_hash}")
                self.display.print_info(f"Owner: {username}")
                self.display.print_info(f"Verified: {'Yes' if verified else 'No'}")
        else:
            if self.via_controller:
                print("DNS resolution failed")
            else:
                self.display.print_error("DNS resolution failed")

    async def _resolve_dns(self, domain):
        if not self.connected:
            self.display.print_error("Not connected to server")
            return

        await self.sio.emit('resolve_dns', {'domain': domain})

    def is_valid_domain(self, domain):
        import re
        pattern = r'^[a-z0-9-]+(\.[a-z0-9-]+)*$'
        return re.match(pattern, domain) is not None

    def handle_search(self, args):
        if not self.current_user:
            self.display.print_error("You need to be logged in to search")
            return

        if len(args) < 1:
            self.display.print_error("Usage: search <term> [--type TYPE] [--sort ORDER]")
            return

        query = args[0]
        content_type = "all"
        sort_by = "reputation"

        i = 1
        while i < len(args):
            if args[i] == '--type' and i+1 < len(args):
                content_type = args[i+1]
                i += 2
            elif args[i] == '--sort' and i+1 < len(args):
                sort_by = args[i+1]
                i += 2
            else:
                self.display.print_error(f"Unknown argument: {args[i]}")
                return

        if not self.via_controller:
            self.display.print_section(f"Search: '{query}'")
            self.display.print_info(f"Type: {content_type}")
            self.display.print_info(f"Sort by: {sort_by}")

        self.search_event.clear()
        self.search_result = None

        try:
            future = asyncio.run_coroutine_threadsafe(self._search_content(query, content_type, sort_by), self.loop)
            future.result(30)
        except Exception as e:
            self.display.print_error(f"Search error: {e}")
            return

        if not self.search_event.wait(30):
            self.display.print_error("Search timeout")
            return

        if self.search_result and 'error' not in self.search_result:
            results = self.search_result

            if not results:
                if self.via_controller:
                    print("No results found")
                else:
                    self.display.print_info("No results found")
                return

            if self.via_controller:
                for result in results:
                    print(f"{result.get('content_hash')}|{result.get('title')}|{result.get('username')}")
            else:
                table_data = []
                for result in results:
                    verified = "✓" if result.get('verified', False) else "⚠"
                    table_data.append([
                        verified,
                        result.get('title', 'No title'),
                        result.get('content_hash', '')[:16] + '...',
                        result.get('username', 'Unknown'),
                        result.get('mime_type', ''),
                        str(result.get('reputation', 100))
                    ])

                self.display.print_table(['✓', 'Title', 'Hash', 'Author', 'Type', 'Reputation'], table_data)
        else:
            if self.via_controller:
                print("Search failed")
            else:
                self.display.print_error("Search failed")

    async def _search_content(self, query, content_type, sort_by):
        if not self.connected:
            self.display.print_error("Not connected to server")
            return

        await self.sio.emit('search_content', {
            'query': query,
            'limit': 50,
            'content_type': content_type if content_type != "all" else "",
            'sort_by': sort_by
        })

    async def _search_contracts(self, search_type, search_value, limit=50, offset=0):
        if not self.connected:
            return
        await self.sio.emit('search_contracts', {
            'search_type': search_type,
            'search_value': search_value,
            'limit': limit,
            'offset': offset
        })

    async def _get_contract_details(self, contract_id):
        if not self.connected:
            return
        await self.sio.emit('get_contract', {'contract_id': contract_id})

    def handle_network(self, args):
        if not self.current_user:
            self.display.print_error("You need to be logged in to view network state")
            return

        if not self.via_controller:
            self.display.print_section("P2P Network State")

        self.network_event.clear()
        self.network_result = None

        try:
            future = asyncio.run_coroutine_threadsafe(self._get_network_state(), self.loop)
            future.result(30)
        except Exception as e:
            self.display.print_error(f"Network state error: {e}")
            return

        if not self.network_event.wait(30):
            self.display.print_error("Network state timeout")
            return

        if self.network_result and 'error' not in self.network_result:
            data = self.network_result

            if self.via_controller:
                print(f"Online nodes: {data.get('online_nodes', 0)}")
                print(f"Total content: {data.get('total_content', 0)}")
                print(f"Registered DNS: {data.get('total_dns', 0)}")
            else:
                self.display.print_info(f"Online nodes: {data.get('online_nodes', 0)}")
                self.display.print_info(f"Total content: {data.get('total_content', 0)}")
                self.display.print_info(f"Registered DNS: {data.get('total_dns', 0)}")

                node_types = data.get('node_types', {})
                if node_types:
                    self.display.print_section("Node Types")
                    for node_type, count in node_types.items():
                        self.display.print_info(f"{node_type}: {count}")

                with sqlite3.connect(self.db_path, timeout=10) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT node_id, address, node_type, reputation, status FROM cli_network_nodes ORDER BY last_seen DESC LIMIT 20')
                    rows = cursor.fetchall()

                    if rows:
                        table_data = []
                        for row in rows:
                            node_id, address, node_type, reputation, status = row
                            table_data.append([
                                node_id[:12] + '...',
                                address,
                                node_type,
                                str(reputation),
                                status
                            ])

                        self.display.print_table(['ID', 'Address', 'Type', 'Reputation', 'Status'], table_data)
        else:
            if self.via_controller:
                print("Failed to get network state")
            else:
                self.display.print_error("Failed to get network state")

    async def _get_network_state(self):
        if not self.connected:
            self.display.print_error("Not connected to server")
            return

        await self.sio.emit('get_network_state', {})

    def handle_stats(self, args):
        if self.via_controller:
            if self.stats_data['session_start'] > 0:
                session_duration = time.time() - self.stats_data['session_start']
                hours = int(session_duration // 3600)
                minutes = int((session_duration % 3600) // 60)
                seconds = int(session_duration % 60)
                session_time = f"{hours}h {minutes}m {seconds}s"
            else:
                session_time = "Not logged in"

            print(f"Session Time: {session_time}")
            print(f"Data Sent: {self.stats_data['data_sent'] / (1024*1024):.2f} MB")
            print(f"Data Received: {self.stats_data['data_received'] / (1024*1024):.2f} MB")
            print(f"Content Downloaded: {self.stats_data['content_downloaded']} files")
            print(f"Content Published: {self.stats_data['content_uploaded']} files")
            print(f"DNS Registered: {self.stats_data['dns_registered']} domains")
            print(f"PoW Solved: {self.stats_data['pow_solved']}")
            print(f"Total PoW Time: {int(self.stats_data['pow_time'])}s")
            print(f"Hashes Calculated: {self.stats_data['hashes_calculated']:,}")
            print(f"Content Reported: {self.stats_data['content_reported']}")
            print(f"Disk Space: {self.used_disk_space / (1024*1024):.2f}MB/{self.disk_quota / (1024*1024):.2f}MB")
            print(f"Reputation: {self.reputation}")
            print(f"User: {self.current_user or 'Not logged in'}")
            print(f"Server: {self.current_server or 'Not connected'}")
        else:
            self.display.print_section("Session Statistics")

            if self.stats_data['session_start'] > 0:
                session_duration = time.time() - self.stats_data['session_start']
                hours = int(session_duration // 3600)
                minutes = int((session_duration % 3600) // 60)
                seconds = int(session_duration % 60)
                session_time = f"{hours}h {minutes}m {seconds}s"
            else:
                session_time = "Not logged in"

            self.display.print_key_value("Session Time", session_time)
            self.display.print_key_value("Data Sent", f"{self.stats_data['data_sent'] / (1024*1024):.2f} MB")
            self.display.print_key_value("Data Received", f"{self.stats_data['data_received'] / (1024*1024):.2f} MB")
            self.display.print_key_value("Content Downloaded", f"{self.stats_data['content_downloaded']} files")
            self.display.print_key_value("Content Published", f"{self.stats_data['content_uploaded']} files")
            self.display.print_key_value("DNS Registered", f"{self.stats_data['dns_registered']} domains")
            self.display.print_key_value("PoW Solved", f"{self.stats_data['pow_solved']}")
            self.display.print_key_value("Total PoW Time", f"{int(self.stats_data['pow_time'])}s")
            self.display.print_key_value("Hashes Calculated", f"{self.stats_data['hashes_calculated']:,}")
            self.display.print_key_value("Content Reported", f"{self.stats_data['content_reported']}")
            self.display.print_key_value("Disk Space", f"{self.used_disk_space / (1024*1024):.2f}MB/{self.disk_quota / (1024*1024):.2f}MB")
            self.display.print_key_value("Reputation", f"{self.reputation}")
            self.display.print_key_value("User", f"{self.current_user or 'Not logged in'}")
            self.display.print_key_value("Server", f"{self.current_server or 'Not connected'}")

    def handle_report(self, args):
        if not self.current_user:
            self.display.print_error("You need to be logged in to report content")
            return

        if len(args) < 2:
            self.display.print_error("Usage: report <content_hash> <reported_user>")
            return

        content_hash = args[0]
        reported_user = args[1]

        if reported_user == self.current_user:
            self.display.print_error("You cannot report your own content")
            return

        if self.reputation < 20:
            self.display.print_error("Your reputation is too low to report content")
            return

        if not self.via_controller:
            self.display.print_section("Content Report")
            self.display.print_info(f"Hash: {content_hash}")
            self.display.print_info(f"Reported user: {reported_user}")
            self.display.print_info(f"Your reputation: {self.reputation}")

        with sqlite3.connect(self.db_path, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute('''
SELECT COUNT(*) FROM cli_reports
WHERE reporter_user = ? AND content_hash = ?
                ''', (self.current_user, content_hash))
            count = cursor.fetchone()[0]
            if count > 0:
                self.display.print_error("You have already reported this content")
                return

        self.pending_report = (content_hash, reported_user)
        self.report_event.clear()
        self.report_result = None

        self.run_async(self.request_pow_challenge("report"))

        if not self.report_event.wait(300):
            self.display.print_error("Report timeout")
            if hasattr(self, 'pending_report'):
                del self.pending_report
            return

        if self.report_result and self.report_result.get('success'):
            if self.via_controller:
                print("Content reported successfully")
            else:
                self.display.print_success("Content reported successfully!")
        else:
            if self.via_controller:
                print("Report failed")
            else:
                self.display.print_error("Report failed")

    async def _report_content(self, content_hash, reported_user, pow_nonce, hashrate_observed):
        if not self.connected:
            return

        try:
            report_id = hashlib.sha256(f"{content_hash}{reported_user}{self.current_user}{time.time()}".encode()).hexdigest()

            with sqlite3.connect(self.db_path, timeout=10) as conn:
                cursor = conn.cursor()
                cursor.execute('''
INSERT INTO cli_reports
(report_id, content_hash, reported_user, reporter_user, timestamp, status, reason)
VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (report_id, content_hash, reported_user, self.current_user, time.time(), 'pending', ''))
                conn.commit()

            await self.sio.emit('report_content', {
                'content_hash': content_hash,
                'reported_user': reported_user,
                'reporter': self.current_user,
                'pow_nonce': pow_nonce,
                'hashrate_observed': hashrate_observed
            })

        except Exception as e:
            self.display.print_error(f"Report sending error: {e}")

    def handle_security(self, args):
        if len(args) < 1:
            self.display.print_error("Usage: security <content_hash>")
            return

        content_hash = args[0]

        with sqlite3.connect(self.db_path, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute('''
SELECT title, description, mime_type, username, signature, public_key, verified
FROM cli_content_cache WHERE content_hash = ?
                ''', (content_hash,))
            row = cursor.fetchone()

            if not row:
                self.display.print_error("Content not found in local cache")
                return

        title, description, mime_type, username, signature, public_key, verified = row

        content_file = os.path.join(self.crypto_dir, "content", f"{content_hash}.dat")
        if not os.path.exists(content_file):
            self.display.print_error("Content file not found")
            return

        with open(content_file, 'rb') as f:
            content = f.read()

        actual_hash = hashlib.sha256(content).hexdigest()
        integrity_ok = actual_hash == content_hash

        if self.via_controller:
            if not integrity_ok:
                print("CONTENT TAMPERED")
            elif verified:
                print("CONTENT VERIFIED")
            else:
                print("CONTENT NOT VERIFIED")

            print(f"Title: {title}")
            print(f"Author: {username}")
            print(f"Hash: {content_hash}")
            print(f"MIME Type: {mime_type}")
            print(f"Integrity: {'OK' if integrity_ok else 'COMPROMISED'}")
            print(f"Valid Signature: {'Yes' if verified else 'No'}")
            print(f"Size: {len(content)} bytes")
        else:
            self.display.print_section("Security Verification")

            if not integrity_ok:
                self.display.print_error("CONTENT TAMPERED")
            elif verified:
                self.display.print_success("CONTENT VERIFIED")
            else:
                self.display.print_warning("CONTENT NOT VERIFIED")

            self.display.print_key_value("Title", title)
            self.display.print_key_value("Author", username)
            self.display.print_key_value("Hash", content_hash)
            self.display.print_key_value("MIME Type", mime_type)
            self.display.print_key_value("Integrity", "OK" if integrity_ok else "COMPROMISED")
            self.display.print_key_value("Valid Signature", "Yes" if verified else "No")
            self.display.print_key_value("Size", f"{len(content)} bytes")

            if public_key:
                self.display.print_section("Author Public Key")
                print(public_key)

    def fetch_contract_details(self, contract_id):
        self.contract_event.clear()
        self.contract_result = None
        self.run_async(self._get_contract_details(contract_id))
        if not self.contract_event.wait(30):
            self.display.print_error("Contract details timeout")
            return None
        if isinstance(self.contract_result, dict) and self.contract_result.get('error'):
            self.display.print_error(f"Contract error: {self.contract_result['error']}")
            return None
        return self.contract_result

    def handle_contracts(self, args):
        if not self.current_user:
            self.display.print_error("You need to be logged in to manage contracts")
            return

        if not args:
            self.display.print_section("Contracts")
            self.display.print_info("contracts search --type <all|hash|domain|user|type> --value <value>")
            self.display.print_info("contracts get <contract_id>")
            self.display.print_info("contracts analyze <contract_id>")
            self.display.print_info("contracts pending")
            self.display.print_info("contracts accept <transfer_id>")
            self.display.print_info("contracts reject <transfer_id>")
            self.display.print_info("contracts renounce <transfer_id>")
            self.display.print_info("contracts fix")
            self.display.print_info("contracts certify <contract_id>")
            self.display.print_info("contracts certify-missing <target> [--type domain|content]")
            self.display.print_info("contracts invalidate <contract_id>")
            self.display.print_info("contracts sync")
            return

        subcommand = args[0].lower()

        if subcommand in ('search', 'list'):
            search_type = 'all'
            search_value = ''
            limit = 50
            i = 1
            while i < len(args):
                if args[i] == '--type' and i + 1 < len(args):
                    search_type = args[i + 1]
                    i += 2
                elif args[i] == '--value' and i + 1 < len(args):
                    search_value = args[i + 1]
                    i += 2
                elif args[i] == '--limit' and i + 1 < len(args):
                    try:
                        limit = int(args[i + 1])
                    except ValueError:
                        self.display.print_error("Invalid limit value")
                        return
                    i += 2
                else:
                    i += 1

            self.contracts_event.clear()
            self.contracts_result = None
            self.run_async(self._search_contracts(search_type, search_value, limit))
            if not self.contracts_event.wait(30):
                self.display.print_error("Contracts search timeout")
                return
            if isinstance(self.contracts_result, dict) and self.contracts_result.get('error'):
                self.display.print_error(f"Contracts search error: {self.contracts_result['error']}")
                return
            contracts = self.contracts_result or []
            if not contracts:
                self.display.print_info("Nenhum contrato encontrado.")
                return
            rows = []
            for contract in contracts:
                rows.append([
                    contract.get('contract_id', '')[:12],
                    contract.get('action_type', ''),
                    contract.get('domain') or contract.get('content_hash', ''),
                    contract.get('username', ''),
                    "OK" if contract.get('integrity_ok', contract.get('verified')) else "FAIL"
                ])
            self.display.print_table(["ID", "Ação", "Alvo", "Usuário", "Status"], rows)
            return

        if subcommand in ('get', 'show'):
            if len(args) < 2:
                self.display.print_error("Usage: contracts get <contract_id>")
                return
            contract_id = args[1]
            contract_info = self.fetch_contract_details(contract_id)
            if not contract_info:
                return
            self.show_contract_analyzer(contract_info, title="Contrato")
            return

        if subcommand == 'analyze':
            if len(args) < 2:
                self.display.print_error("Usage: contracts analyze <contract_id>")
                return
            contract_id = args[1]
            contract_info = self.fetch_contract_details(contract_id)
            if not contract_info:
                return
            self.show_contract_analyzer(contract_info)
            return

        if subcommand == 'pending':
            self.pending_transfers_event.clear()
            self.pending_transfers_result = None
            self.run_async(self.request_pending_transfers())
            if not self.pending_transfers_event.wait(30):
                self.display.print_error("Pending transfers timeout")
                return
            transfers = self.pending_transfers_result or []
            violations = list(self.active_contract_violations.items())
            if not transfers and not violations:
                self.display.print_info("Nenhuma pendência contratual.")
                return
            if violations:
                rows = []
                for (target_type, target), reason in violations:
                    rows.append([target_type, target, reason])
                self.display.print_table(["Tipo", "Alvo", "Motivo"], rows)
            if not transfers:
                return
            rows = []
            for transfer in transfers:
                rows.append([
                    transfer.get('transfer_id', '')[:8],
                    transfer.get('transfer_type', ''),
                    transfer.get('target_user', ''),
                    transfer.get('original_owner', ''),
                    transfer.get('contract_id', '')[:12]
                ])
            self.display.print_table(["ID", "Tipo", "Destino", "Origem", "Contrato"], rows)
            return

        if subcommand in ('accept', 'reject', 'renounce'):
            if len(args) < 2:
                self.display.print_error(f"Usage: contracts {subcommand} <transfer_id>")
                return
            transfer_id = args[1]
            if not self.pending_transfers:
                self.pending_transfers_event.clear()
                self.pending_transfers_result = None
                self.run_async(self.request_pending_transfers())
                self.pending_transfers_event.wait(10)
            pending = next((t for t in self.pending_transfers if t.get('transfer_id') == transfer_id), None)
            if not pending:
                self.display.print_error("Transferência não encontrada na lista de pendências")
                return
            if subcommand == 'accept':
                self.start_transfer_accept(pending)
            elif subcommand == 'reject':
                self.start_transfer_reject(pending)
            else:
                self.start_transfer_renounce(pending)
            return

        if subcommand == 'fix':
            if not self.active_contract_violations and not self.pending_transfers:
                self.display.print_info("Nenhuma pendência contratual.")
                return

            missing = [
                (key, reason)
                for key, reason in self.active_contract_violations.items()
                if reason == "missing_contract"
            ]
            if missing:
                if self.via_controller or self.no_cli:
                    for (target_type, target), _reason in missing:
                        if target_type not in ("domain", "content"):
                            continue
                        self.display.print_info(
                            f"Use: contracts certify-missing {target} --type {target_type}"
                        )
                else:
                    for (target_type, target), _reason in missing:
                        if target_type not in ("domain", "content"):
                            continue
                        confirm = self.display.get_input(
                            f"Certificar contrato ausente para {target_type} {target}? (y/n): "
                        ).strip().lower()
                        if confirm == 'y':
                            self.start_missing_contract_certify(target_type, target)

            other = [
                (key, reason)
                for key, reason in self.active_contract_violations.items()
                if reason != "missing_contract"
            ]
            if other:
                for (target_type, target), reason in other:
                    search_type = "domain" if target_type == "domain" else "hash"
                    if target_type not in ("domain", "content"):
                        self.display.print_warning(
                            f"Violação '{reason}' em {target}. "
                            "Use contracts search para localizar o contrato."
                        )
                        continue
                    self.contracts_event.clear()
                    self.contracts_result = None
                    self.run_async(self._search_contracts(search_type, target, limit=10))
                    if not self.contracts_event.wait(30):
                        self.display.print_warning("Timeout ao buscar contratos.")
                        continue
                    if isinstance(self.contracts_result, dict) and self.contracts_result.get('error'):
                        self.display.print_warning(f"Erro na busca de contratos: {self.contracts_result['error']}")
                        continue
                    contracts = self.contracts_result or []
                    if not contracts:
                        self.display.print_warning(
                            f"Nenhum contrato encontrado para {target_type} {target}. "
                            "Use 'contracts sync' ou tente novamente."
                        )
                        continue
                    contract_id = contracts[0].get('contract_id')
                    if not contract_id:
                        continue
                    contract_info = self.fetch_contract_details(contract_id)
                    if contract_info:
                        self.show_contract_analyzer(contract_info)

            if self.pending_transfers:
                self.display.print_info("Há transferências pendentes. Use 'contracts pending'.")
            return

        if subcommand == 'certify':
            if len(args) < 2:
                self.display.print_error("Usage: contracts certify <contract_id>")
                return
            contract_id = args[1]
            contract_info = self.fetch_contract_details(contract_id)
            if not contract_info:
                return
            self.start_contract_certify(contract_info)
            return

        if subcommand == 'certify-missing':
            if len(args) < 2:
                self.display.print_error("Usage: contracts certify-missing <target> [--type domain|content]")
                return
            target_id = args[1].strip()
            target_type = None
            if '--type' in args:
                idx = args.index('--type')
                if idx + 1 < len(args):
                    target_type = args[idx + 1]
            if not target_type:
                if '.' in target_id and not re.fullmatch(r'[a-fA-F0-9]{32,64}', target_id):
                    target_type = 'domain'
                else:
                    target_type = 'content'
            if target_type == 'content' and len(target_id) < 32:
                self.display.print_error("Hash inválido.")
                return
            self.start_missing_contract_certify(target_type, target_id)
            return

        if subcommand == 'invalidate':
            if len(args) < 2:
                self.display.print_error("Usage: contracts invalidate <contract_id>")
                return
            contract_id = args[1]
            contract_info = self.fetch_contract_details(contract_id)
            if not contract_info:
                return
            self.start_contract_invalidate(contract_info)
            return

        if subcommand == 'sync':
            self.run_async(self.sync_client_contracts())
            self.display.print_success("Contract sync completed")
            return

        self.display.print_error(f"Unknown contracts subcommand: {subcommand}")

    def handle_hps_actions(self, args):
        if not self.current_user:
            self.display.print_error("You need to be logged in to use HPS actions")
            return

        if not args:
            self.display.print_section("HPS Actions")
            self.display.print_info("actions transfer-file <content_hash> <target_user>")
            self.display.print_info("actions transfer-domain <domain> <new_owner>")
            self.display.print_info("actions transfer-api <app_name> <target_user> <file_path>")
            self.display.print_info("actions api-app <app_name> <file_path>")
            return

        subcommand = args[0].lower()

        if subcommand == "transfer-file":
            if len(args) < 3:
                self.display.print_error("Usage: actions transfer-file <content_hash> <target_user>")
                return
            content_hash = args[1].strip()
            target_user = args[2].strip()
            if len(content_hash) < 32 or not target_user:
                self.display.print_error("Hash ou usuário inválido.")
                return
            cached = self.load_cached_content(content_hash)
            if not cached:
                self.display.print_error("Conteúdo não encontrado no cache local. Baixe antes de transferir.")
                return
            title = self.build_hps_transfer_title("file", target_user)
            self.upload_content_bytes(
                title,
                cached.get('description', ''),
                cached.get('mime_type', 'application/octet-stream'),
                cached['content']
            )
            return

        if subcommand == "transfer-domain":
            if len(args) < 3:
                self.display.print_error("Usage: actions transfer-domain <domain> <new_owner>")
                return
            domain = args[1].strip()
            new_owner = args[2].strip()
            if not domain or not new_owner:
                self.display.print_error("Domínio ou novo dono inválido.")
                return
            payload = self.build_domain_transfer_payload(domain, new_owner)
            title = self.build_hps_dns_change_title()
            self.upload_content_bytes(title, "", "text/plain", payload)
            return

        if subcommand == "transfer-api":
            if len(args) < 4:
                self.display.print_error("Usage: actions transfer-api <app_name> <target_user> <file_path>")
                return
            app_name = args[1].strip()
            target_user = args[2].strip()
            file_path = args[3]
            if not app_name or not target_user:
                self.display.print_error("Nome do app ou usuário inválido.")
                return
            if not os.path.exists(file_path):
                self.display.print_error(f"File not found: {file_path}")
                return
            mime_type, _ = mimetypes.guess_type(file_path)
            if not mime_type:
                mime_type = 'application/octet-stream'
            with open(file_path, 'rb') as f:
                content = f.read()
            title = self.build_hps_transfer_title("api_app", target_user, app_name)
            self.upload_content_bytes(title, "", mime_type, content)
            return

        if subcommand == "api-app":
            if len(args) < 3:
                self.display.print_error("Usage: actions api-app <app_name> <file_path>")
                return
            app_name = args[1].strip()
            file_path = args[2]
            if not app_name:
                self.display.print_error("Nome do app inválido.")
                return
            if not os.path.exists(file_path):
                self.display.print_error(f"File not found: {file_path}")
                return
            mime_type, _ = mimetypes.guess_type(file_path)
            if not mime_type:
                mime_type = 'application/octet-stream'
            with open(file_path, 'rb') as f:
                content = f.read()
            title = self.build_hps_api_title(app_name)
            self.upload_content_bytes(title, "", mime_type, content)
            return

        self.display.print_error(f"Unknown actions subcommand: {subcommand}")

    def handle_servers(self, args):
        if self.via_controller:
            if not self.known_servers:
                print("No known servers")
                return

            for i, server in enumerate(self.known_servers, 1):
                status = "Connected" if server == self.current_server else "Available"
                print(f"{i}. {server} [{status}]")
        else:
            self.display.print_section("Known Servers")

            if not self.known_servers:
                self.display.print_info("No known servers")
                return

            table_data = []
            for i, server in enumerate(self.known_servers, 1):
                status = "✓ Connected" if server == self.current_server else "Available"
                table_data.append([str(i), server, status])

            self.display.print_table(['#', 'Address', 'Status'], table_data)

            action = self.display.get_input("\n[A]dd, [R]emove, [C]onnect, [Enter] to return: ").lower()

            if action == 'a':
                new_server = self.display.get_input("New server address: ")
                if new_server and new_server not in self.known_servers:
                    self.known_servers.append(new_server)
                    self.save_known_servers()
                    self.display.print_success(f"Server {new_server} added")

            elif action == 'r':
                try:
                    num = int(self.display.get_input("Server number to remove: "))
                    if 1 <= num <= len(self.known_servers):
                        removed = self.known_servers.pop(num-1)
                        self.save_known_servers()
                        self.display.print_success(f"Server {removed} removed")
                except ValueError:
                    pass

            elif action == 'c':
                try:
                    num = int(self.display.get_input("Server number to connect: "))
                    if 1 <= num <= len(self.known_servers):
                        server = self.known_servers[num-1]
                        self.handle_login([server, self.current_user or "", self.password or ""])
                except ValueError:
                    pass

    def handle_keys(self, args):
        if len(args) < 1:
            if self.via_controller:
                print("Available commands:")
                print("  keys generate  - Generate new keys")
                print("  keys export <path> - Export keys")
                print("  keys import <path> - Import keys")
                print("  keys show      - Show public key")
                return
            else:
                self.display.print_section("Key Management")
                self.display.print_info("Available commands:")
                self.display.print_info("  keys generate  - Generate new keys")
                self.display.print_info("  keys export <path> - Export keys")
                self.display.print_info("  keys import <path> - Import keys")
                self.display.print_info("  keys show      - Show public key")
                return

        subcommand = args[0]

        if subcommand == 'generate':
            if not self.no_cli and not self.via_controller:
                confirm = self.display.get_input("Generate new keys? (y/n): ").lower()
                if confirm != 'y':
                    return

            self.generate_keys()
            if self.via_controller:
                print("New keys generated and saved")
            else:
                self.display.print_success("New keys generated and saved")

        elif subcommand == 'export':
            if len(args) < 2:
                self.display.print_error("Usage: keys export <file_path>")
                return

            file_path = args[1]
            try:
                with open(file_path, "wb") as f:
                    f.write(self.private_key.private_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.PKCS8,
                                encryption_algorithm=serialization.NoEncryption()
                            ))
                if self.via_controller:
                    print(f"Private key exported to: {file_path}")
                else:
                    self.display.print_success(f"Private key exported to: {file_path}")
            except Exception as e:
                self.display.print_error(f"Export failed: {e}")

        elif subcommand == 'import':
            if len(args) < 2:
                self.display.print_error("Usage: keys import <file_path>")
                return

            file_path = args[1]
            try:
                with open(file_path, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
                self.public_key_pem = self.private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                self.save_keys()
                if self.via_controller:
                    print("Keys imported successfully")
                else:
                    self.display.print_success("Keys imported successfully")
            except Exception as e:
                self.display.print_error(f"Import failed: {e}")

        elif subcommand == 'show':
            if self.public_key_pem:
                if self.via_controller:
                    print(self.public_key_pem.decode('utf-8'))
                else:
                    self.display.print_section("Public Key")
                    print(self.public_key_pem.decode('utf-8'))
            else:
                self.display.print_error("No public key available")

        else:
            self.display.print_error(f"Unknown subcommand: {subcommand}")

    def handle_sync(self, args):
        if not self.current_user:
            self.display.print_error("You need to be logged in to sync")
            return

        if not self.via_controller:
            self.display.print_section("Network Sync")

            self.display.print_info("Syncing known servers...")
            self.save_known_servers()

            self.display.print_info("Syncing local files...")
            self.run_async(self.sync_client_files())
            self.display.print_info("Syncing DNS cache...")
            self.run_async(self.sync_client_dns_files())
            self.display.print_info("Syncing contracts...")
            self.run_async(self.sync_client_contracts())

            self.display.print_info("Getting network state...")
            self.run_async(self._get_network_state())

            self.display.print_success("Sync completed")
        else:
            self.save_known_servers()
            self.run_async(self.sync_client_files())
            self.run_async(self.sync_client_dns_files())
            self.run_async(self.sync_client_contracts())
            self.run_async(self._get_network_state())
            print("Sync completed")

    def handle_history(self, args):
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT command, timestamp, success, result FROM cli_history ORDER BY timestamp DESC LIMIT 20')
            rows = cursor.fetchall()

            if not rows:
                if self.via_controller:
                    print("No history available")
                else:
                    self.display.print_info("No history available")
                return

            if self.via_controller:
                for row in rows:
                    command, timestamp, success, result = row
                    time_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
                    status = "SUCCESS" if success else "FAILED"
                    print(f"{time_str} [{status}] {command}")
            else:
                table_data = []
                for row in rows:
                    command, timestamp, success, result = row
                    time_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
                    status = "✓" if success else "✗"
                    table_data.append([time_str, command[:30], status, result[:30] if result else ""])

                self.display.print_table(['Time', 'Command', 'Status', 'Result'], table_data)

    def handle_clear(self, args):
        if not self.no_cli and not self.via_controller:
            self.display.clear_screen()
            self.display.print_logo()
        elif not self.via_controller:
            os.system('cls' if platform.system() == 'Windows' else 'clear')

    def handle_help(self, args):
        if self.via_controller:
            print("Available Commands:")
            print("  login <server> <user> <pass> - Connect to P2P network")
            print("  logout - Disconnect from network")
            print("  upload <file> [options] - Upload file")
            print("  download <hash_or_url> - Download content")
            print("  dns-reg <domain> <hash> - Register DNS domain")
            print("  dns-res <domain> - Resolve DNS domain")
            print("  search <term> [options] - Search content")
            print("  network - View network state")
            print("  stats - View statistics")
            print("  report <hash> <user> - Report content")
            print("  security <hash> - Verify security")
            print("  contracts [subcommand] - Manage contracts and transfers")
            print("  contract [subcommand] - Alias for contracts")
            print("  actions [subcommand] - HPS actions (transfer/api)")
            print("  servers - Manage servers")
            print("  keys [subcommand] - Manage cryptographic keys")
            print("  sync - Sync with network")
            print("  history - View command history")
            print("  clear - Clear screen")
            print("  help - Show this help")
            print("  exit/quit - Exit program")
        else:
            self.display.print_section("Available Commands")

            commands = [
                ("login <server> <user> <pass>", "Connect to P2P network"),
                ("logout", "Disconnect from network"),
                ("upload <file> [options]", "Upload file"),
                ("download <hash_or_url>", "Download content"),
                ("dns-reg <domain> <hash>", "Register DNS domain"),
                ("dns-res <domain>", "Resolve DNS domain"),
                ("search <term> [options]", "Search content"),
                ("network", "View network state"),
                ("stats", "View statistics"),
                ("report <hash> <user>", "Report content"),
                ("security <hash>", "Verify security"),
                ("contracts [subcommand]", "Manage contracts and transfers"),
                ("contract [subcommand]", "Alias for contracts"),
                ("actions [subcommand]", "HPS actions (transfer/api)"),
                ("servers", "Manage servers"),
                ("keys [subcommand]", "Manage cryptographic keys"),
                ("sync", "Sync with network"),
                ("history", "View command history"),
                ("clear", "Clear screen"),
                ("help", "Show this help"),
                ("exit/quit", "Exit program"),
            ]

            for cmd, desc in commands:
                self.display.print_key_value(cmd, desc)

            self.display.print_section("Upload Options")
            self.display.print_info("--title TITLE      Content title")
            self.display.print_info("--desc DESCRIPTION Content description")
            self.display.print_info("--mime MIME_TYPE   MIME type (ex: text/plain, image/jpeg)")

            self.display.print_section("Search Options")
            self.display.print_info("--type TYPE        Content type (all, image, video, document, text)")
            self.display.print_info("--sort ORDER       Sort by (reputation, recent, popular)")

    def handle_exit(self, args):
        self.is_running = False
        if self.connected and self.sio:
            self.run_async(self.sio.disconnect())
        if not self.via_controller:
            self.display.print_info("Exiting HPS CLI...")
        self.save_session_state()
        sys.exit(0)

    def run_async(self, coro, timeout=60):
        if not self.connected:
            self.display.print_error("Not connected to server")
            return None
        if not self.loop:
            self.display.print_error("Network loop not initialized")
            return None
        try:
            future = asyncio.run_coroutine_threadsafe(coro, self.loop)
            return future.result(timeout)
        except Exception as e:
            self.display.print_error(f"Timeout or error in operation: {e}")
            return None

    def shutdown(self):
        self.is_running = False
        if self.sio and self.sio.connected:
            asyncio.run_coroutine_threadsafe(self.sio.disconnect(), self.loop)
        if self.network_thread:
            self.network_thread.join(timeout=5)

    def get_connection_state(self):
        return {
            'connected': self.connected,
            'current_server': self.current_server,
            'current_user': self.current_user,
            'sio': self.sio,
            'loop': self.loop,
            'session_id': self.session_id,
            'username': self.username,
            'reputation': self.reputation
        }

class HPSCommandLine(HPSClientCore):
    def __init__(self, no_cli=False, interactive_mode=False):
        super().__init__(no_cli=no_cli)
        self.interactive_mode = interactive_mode
        self.controller_monitor = ControllerFileMonitor(self, self.display)
        self.setup_command_handlers()

    def setup_command_handlers(self):
        self.command_handlers = {
            'login': self.handle_login,
            'logout': self.handle_logout,
            'upload': self.handle_upload,
            'download': self.handle_download,
            'dns-reg': self.handle_dns_register,
            'dns-res': self.handle_dns_resolve,
            'search': self.handle_search,
            'network': self.handle_network,
            'stats': self.handle_stats,
            'report': self.handle_report,
            'security': self.handle_security,
            'contracts': self.handle_contracts,
            'contract': self.handle_contracts,
            'actions': self.handle_hps_actions,
            'hps-actions': self.handle_hps_actions,
            'servers': self.handle_servers,
            'keys': self.handle_keys,
            'sync': self.handle_sync,
            'history': self.handle_history,
            'clear': self.handle_clear,
            'help': self.handle_help,
            'exit': self.handle_exit,
            'quit': self.handle_exit,
        }

    def save_history(self, command, success, result=""):
        with sqlite3.connect(self.db_path, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO cli_history (command, timestamp, success, result) VALUES (?, ?, ?, ?)',
                         (command, time.time(), 1 if success else 0, result))
            conn.commit()

    def run_interactive(self):
        self.controller_monitor.start_monitoring()

        self.display.clear_screen()
        self.display.print_logo()
        self.display.print_header("Interactive CLI Interface with Controller File")
        self.display.print_info("Type 'help' for available commands")
        self.display.print_info(f"Controller file: {self.controller_monitor.controller_file}")

        if self.current_user:
            self.display.print_status_bar(self.current_user, self.current_server, self.reputation)

        while True:
            try:
                if self.current_user:
                    prompt = f"{self.display.colors['green']}hps://{self.current_user}{self.display.colors['reset']}{self.display.colors['dim']}@{self.display.colors['reset']}{self.display.colors['blue']}{self.current_server}{self.display.colors['reset']} {self.display.colors['yellow']}»{self.display.colors['reset']} "
                else:
                    prompt = f"{self.display.colors['dim']}hps://disconnected{self.display.colors['reset']} {self.display.colors['yellow']}»{self.display.colors['reset']} "

                user_input = self.display.get_input(prompt).strip()

                if not user_input:
                    continue

                parts = user_input.split()
                command = parts[0].lower()
                args = parts[1:]

                if command in ['exit', 'quit']:
                    self.handle_exit(args)
                    break

                if command in self.command_handlers:
                    try:
                        self.command_handlers[command](args)
                        self.save_history(command, True)
                    except Exception as e:
                        self.display.print_error(f"Command error: {e}")
                        self.save_history(command, False, str(e))
                else:
                    self.display.print_error(f"Unknown command: {command}")

                if self.current_user:
                    self.display.print_status_bar(self.current_user, self.current_server, self.reputation)

            except KeyboardInterrupt:
                self.display.print_info("\nUse 'exit' to quit")
            except EOFError:
                break
            except Exception as e:
                self.display.print_error(f"Error: {e}")

        self.controller_monitor.stop_monitoring()

def main():
    parser = argparse.ArgumentParser(description='HPS CLI - Hsyst P2P Browser via Command Line')
    parser.add_argument('--no-cli', action='store_true', help='Non-interactive mode (command execution only)')

    args = parser.parse_args()

    cli = HPSCommandLine(no_cli=args.no_cli, interactive_mode=True)
    cli.run_interactive()

if __name__ == "__main__":
    main()

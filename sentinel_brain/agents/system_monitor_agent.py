"""
System Monitor Agent — Real-time System Monitoring
===================================================
- CPU / RAM / Disk usage
- Running processes
- Network connections & bandwidth
- Open ports (netstat)
- System logs monitor
- Scan resource usage track karo

Author: @who_is_the_black_hat
"""

import logging
import os
import re
import subprocess
import time
import threading
from pathlib import Path

logger = logging.getLogger(__name__)


class SystemMonitorAgent:
    NAME = 'system_monitor_agent'

    def __init__(self):
        self._monitoring = False
        self._thread     = None
        self._stats      = {}
        self._alerts     = []
        self._lock       = threading.Lock()

        # Thresholds
        self.CPU_ALERT    = 90.0   # %
        self.RAM_ALERT    = 85.0   # %
        self.DISK_ALERT   = 90.0   # %

    # ── Snapshot ──────────────────────────────────────────────────────────────

    def snapshot(self) -> dict:
        """Current system state ka full snapshot lo."""
        return {
            'cpu':      self.cpu_usage(),
            'memory':   self.memory_usage(),
            'disk':     self.disk_usage(),
            'network':  self.network_stats(),
            'processes': self.top_processes(10),
            'connections': self.open_connections(),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        }

    # ── CPU ───────────────────────────────────────────────────────────────────

    def cpu_usage(self) -> dict:
        try:
            import psutil
            cpu = psutil.cpu_percent(interval=0.5)
            cores = psutil.cpu_count()
            freq  = psutil.cpu_freq()
            return {
                'percent': cpu,
                'cores':   cores,
                'freq_mhz': round(freq.current, 0) if freq else 0,
                'high': cpu > self.CPU_ALERT,
            }
        except ImportError:
            r = subprocess.run(
                "top -bn1 | grep 'Cpu(s)' | awk '{print $2}'",
                shell=True, capture_output=True, text=True
            )
            try:
                pct = float(r.stdout.strip().replace('%', '').replace(',', '.'))
            except Exception:
                pct = 0.0
            return {'percent': pct, 'high': pct > self.CPU_ALERT}

    # ── Memory ────────────────────────────────────────────────────────────────

    def memory_usage(self) -> dict:
        try:
            import psutil
            m = psutil.virtual_memory()
            return {
                'total_gb':  round(m.total / 1e9, 1),
                'used_gb':   round(m.used / 1e9, 1),
                'free_gb':   round(m.available / 1e9, 1),
                'percent':   m.percent,
                'high':      m.percent > self.RAM_ALERT,
            }
        except ImportError:
            r = subprocess.run('free -m', shell=True, capture_output=True, text=True)
            for line in r.stdout.splitlines():
                if line.startswith('Mem:'):
                    parts = line.split()
                    total = int(parts[1])
                    used  = int(parts[2])
                    pct   = round(used / total * 100, 1) if total else 0
                    return {
                        'total_gb': round(total / 1024, 1),
                        'used_gb':  round(used / 1024, 1),
                        'percent':  pct,
                        'high':     pct > self.RAM_ALERT,
                    }
            return {}

    # ── Disk ──────────────────────────────────────────────────────────────────

    def disk_usage(self, path: str = '/') -> dict:
        try:
            import psutil
            d = psutil.disk_usage(path)
            return {
                'total_gb': round(d.total / 1e9, 1),
                'used_gb':  round(d.used / 1e9, 1),
                'free_gb':  round(d.free / 1e9, 1),
                'percent':  d.percent,
                'high':     d.percent > self.DISK_ALERT,
            }
        except ImportError:
            r = subprocess.run(f'df -h {path}', shell=True, capture_output=True, text=True)
            lines = r.stdout.splitlines()
            if len(lines) >= 2:
                parts = lines[1].split()
                pct = int(parts[4].replace('%', '')) if len(parts) >= 5 else 0
                return {
                    'total_gb': parts[1], 'used_gb': parts[2],
                    'free_gb':  parts[3], 'percent': pct,
                    'high':     pct > self.DISK_ALERT,
                }
            return {}

    # ── Network ───────────────────────────────────────────────────────────────

    def network_stats(self) -> dict:
        try:
            import psutil
            net = psutil.net_io_counters()
            return {
                'bytes_sent_mb': round(net.bytes_sent / 1e6, 1),
                'bytes_recv_mb': round(net.bytes_recv / 1e6, 1),
                'packets_sent':  net.packets_sent,
                'packets_recv':  net.packets_recv,
            }
        except ImportError:
            r = subprocess.run(
                "cat /proc/net/dev | grep -v lo | tail -1",
                shell=True, capture_output=True, text=True
            )
            return {'raw': r.stdout.strip()[:100]}

    def open_connections(self, filter_established: bool = True) -> list:
        """Active network connections lo."""
        r = subprocess.run(
            'ss -tnp 2>/dev/null | head -30',
            shell=True, capture_output=True, text=True
        )
        connections = []
        for line in r.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                connections.append({
                    'state':   parts[0],
                    'local':   parts[3],
                    'remote':  parts[4],
                    'process': parts[5] if len(parts) > 5 else '',
                })
        return connections[:20]

    # ── Processes ─────────────────────────────────────────────────────────────

    def top_processes(self, n: int = 10) -> list:
        """Top N processes by CPU usage."""
        try:
            import psutil
            procs = []
            for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
                try:
                    procs.append(p.info)
                except Exception:
                    pass
            procs.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
            return procs[:n]
        except ImportError:
            r = subprocess.run(
                "ps aux --sort=-%cpu | head -11",
                shell=True, capture_output=True, text=True
            )
            procs = []
            for line in r.stdout.splitlines()[1:]:
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    procs.append({
                        'pid':            int(parts[1]),
                        'name':           parts[10][:40],
                        'cpu_percent':    float(parts[2]),
                        'memory_percent': float(parts[3]),
                    })
            return procs

    def find_process(self, name: str) -> list:
        """Process name se dhundo."""
        r = subprocess.run(
            f'pgrep -a {name} 2>/dev/null',
            shell=True, capture_output=True, text=True
        )
        procs = []
        for line in r.stdout.splitlines():
            parts = line.split(None, 1)
            if len(parts) >= 2:
                procs.append({'pid': int(parts[0]), 'cmd': parts[1][:80]})
        return procs

    def kill_process(self, pid: int, force: bool = False) -> bool:
        sig = '-9' if force else '-15'
        r = subprocess.run(f'kill {sig} {pid} 2>/dev/null', shell=True)
        return r.returncode == 0

    # ── Scan Resource Tracking ────────────────────────────────────────────────

    def track_scan(self, scan_name: str, duration: int = 60) -> dict:
        """Scan ke dauran resource usage track karo."""
        samples = []
        end_time = time.time() + duration

        while time.time() < end_time:
            samples.append({
                'time':   time.time(),
                'cpu':    self.cpu_usage().get('percent', 0),
                'ram':    self.memory_usage().get('percent', 0),
            })
            time.sleep(5)

        if not samples:
            return {}

        cpu_vals = [s['cpu'] for s in samples]
        ram_vals = [s['ram'] for s in samples]

        return {
            'scan':     scan_name,
            'duration': duration,
            'cpu_avg':  round(sum(cpu_vals) / len(cpu_vals), 1),
            'cpu_max':  max(cpu_vals),
            'ram_avg':  round(sum(ram_vals) / len(ram_vals), 1),
            'ram_max':  max(ram_vals),
            'samples':  len(samples),
        }

    # ── Continuous Monitoring ─────────────────────────────────────────────────

    def start_monitoring(self, interval: int = 30):
        """Background mein continuously monitor karo."""
        if self._monitoring:
            return
        self._monitoring = True
        self._thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True,
            name='sentinel-sysmon'
        )
        self._thread.start()
        logger.info(f"[SystemMonitor] Started — interval={interval}s")

    def stop_monitoring(self):
        self._monitoring = False

    def _monitor_loop(self, interval: int):
        while self._monitoring:
            snap = self.snapshot()
            with self._lock:
                self._stats = snap

            # Alert check
            if snap['cpu'].get('high'):
                self._add_alert('HIGH_CPU', f"CPU {snap['cpu']['percent']}%")
            if snap['memory'].get('high'):
                self._add_alert('HIGH_RAM', f"RAM {snap['memory']['percent']}%")
            if snap['disk'].get('high'):
                self._add_alert('HIGH_DISK', f"Disk {snap['disk']['percent']}%")

            time.sleep(interval)

    def _add_alert(self, alert_type: str, detail: str):
        with self._lock:
            self._alerts.append({
                'type':   alert_type,
                'detail': detail,
                'time':   time.strftime('%H:%M:%S'),
            })
            self._alerts = self._alerts[-20:]  # Last 20 only

    def get_stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def get_alerts(self) -> list:
        with self._lock:
            return list(self._alerts)

    # ── System Info ───────────────────────────────────────────────────────────

    def system_info(self) -> dict:
        info = {}
        r = subprocess.run('uname -a', shell=True, capture_output=True, text=True)
        info['kernel'] = r.stdout.strip()

        r = subprocess.run('hostname', shell=True, capture_output=True, text=True)
        info['hostname'] = r.stdout.strip()

        r = subprocess.run('whoami', shell=True, capture_output=True, text=True)
        info['user'] = r.stdout.strip()

        r = subprocess.run('uptime -p', shell=True, capture_output=True, text=True)
        info['uptime'] = r.stdout.strip()

        return info

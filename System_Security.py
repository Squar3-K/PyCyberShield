import psutil
import os
import platform
import subprocess
import hashlib
import time
from pathlib import Path

# Enhanced whitelist of known safe processes by OS
WINDOWS_SAFE_PROCESSES = {
    'System', 'Registry', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
    'services.exe', 'lsass.exe', 'svchost.exe', 'explorer.exe', 'dwm.exe',
    'RuntimeBroker.exe', 'SearchUI.exe', 'ShellExperienceHost.exe', 'Taskmgr.exe',
    'MsMpEng.exe', 'audiodg.exe', 'conhost.exe', 'dllhost.exe', 'fontdrvhost.exe'
}

LINUX_SAFE_PROCESSES = {
    'init', 'kthreadd', 'systemd', 'bash', 'sh', 'python3', 'python', 'ssh', 'sshd',
    'NetworkManager', 'dbus', 'cron', 'rsyslog', 'udev', 'getty', 'login',
    'sudo', 'su', 'ps', 'top', 'htop', 'vim', 'nano', 'firefox', 'chrome',
    'gnome-shell', 'Xorg', 'pulseaudio', 'systemd-', 'kworker/', 'ksoftirqd/',
    'migration/', 'rcu_', 'watchdog/', 'systemd-logind', 'systemd-networkd',
    'systemd-resolved', 'systemd-timesyncd', 'accounts-daemon', 'polkitd'
}

# Suspicious indicators
SUSPICIOUS_INDICATORS = {
    'high_cpu_threshold': 85.0,  # Increased threshold
    'high_memory_threshold': 80.0,  # Memory usage threshold (%)
    'suspicious_names': [
        'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe',
        'regsvr32.exe', 'rundll32.exe', 'certutil.exe', 'bitsadmin.exe',
        'nc.exe', 'netcat', 'ncat', 'telnet.exe', 'ftp.exe'
    ],
    'suspicious_paths': [
        '/tmp/', '/var/tmp/', 'C:\\Windows\\Temp\\', 'C:\\Temp\\',
        'C:\\Users\\Public\\', '%APPDATA%', '%TEMP%'
    ]
}

def get_safe_processes():
    """Get appropriate safe process list based on OS."""
    if platform.system().lower() == 'windows':
        return WINDOWS_SAFE_PROCESSES
    else:
        return LINUX_SAFE_PROCESSES

def list_processes():
    """List all running processes with detailed information."""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_info', 
                                   'create_time', 'ppid', 'username', 'cmdline']):
        try:
            proc_info = proc.info
            # Calculate memory percentage
            if proc_info['memory_info']:
                total_memory = psutil.virtual_memory().total
                memory_percent = (proc_info['memory_info'].rss / total_memory) * 100
                proc_info['memory_percent'] = memory_percent
            else:
                proc_info['memory_percent'] = 0
            
            # Add runtime duration
            if proc_info['create_time']:
                runtime_seconds = time.time() - proc_info['create_time']
                proc_info['runtime_hours'] = runtime_seconds / 3600
            else:
                proc_info['runtime_hours'] = 0
                
            processes.append(proc_info)
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
    return processes

def is_process_suspicious(proc):
    """Enhanced logic to determine if a process is suspicious."""
    safe_processes = get_safe_processes()
    suspicion_score = 0
    reasons = []
    
    # Check if process name is in safe list
    proc_name = proc['name']
    if proc_name in safe_processes:
        # Even safe processes can be suspicious under certain conditions
        pass
    else:
        # Check for kernel/system processes that start with known prefixes
        safe_prefixes = ['systemd', 'kworker', 'ksoftirqd', 'migration', 'rcu_', 'watchdog']
        if not any(proc_name.startswith(prefix) for prefix in safe_prefixes):
            suspicion_score += 2
    
    # High CPU usage (but not for short bursts)
    cpu_percent = proc.get('cpu_percent', 0)
    if cpu_percent > SUSPICIOUS_INDICATORS['high_cpu_threshold']:
        if proc.get('runtime_hours', 0) > 0.1:  # Running for more than 6 minutes
            suspicion_score += 3
            reasons.append(f"High CPU usage: {cpu_percent:.1f}%")
    
    # High memory usage
    memory_percent = proc.get('memory_percent', 0)
    if memory_percent > SUSPICIOUS_INDICATORS['high_memory_threshold']:
        suspicion_score += 2
        reasons.append(f"High memory usage: {memory_percent:.1f}%")
    
    # Suspicious executable names
    if proc_name.lower() in [name.lower() for name in SUSPICIOUS_INDICATORS['suspicious_names']]:
        suspicion_score += 4
        reasons.append(f"Suspicious executable: {proc_name}")
    
    # Suspicious paths
    exe_path = proc.get('exe', '')
    if exe_path:
        for sus_path in SUSPICIOUS_INDICATORS['suspicious_paths']:
            if sus_path.lower() in exe_path.lower():
                suspicion_score += 3
                reasons.append(f"Suspicious path: {exe_path}")
                break
    else:
        # No executable path could indicate process hiding
        if proc_name not in safe_processes:
            suspicion_score += 1
            reasons.append("No executable path")
    
    # Check for unusual parent-child relationships
    if proc.get('ppid') == 1 and proc_name not in safe_processes:
        # Process with init as parent (could be orphaned or suspicious)
        if proc.get('runtime_hours', 0) < 1:  # Recently started
            suspicion_score += 1
            reasons.append("Unusual parent process")
    
    # Command line analysis for scripting engines
    cmdline = proc.get('cmdline', [])
    if cmdline and len(cmdline) > 1:
        cmdline_str = ' '.join(cmdline).lower()
        suspicious_cmdline_patterns = [
            'powershell.exe -enc', 'cmd.exe /c', 'wscript.exe', 'cscript.exe',
            'base64', 'invoke-expression', 'downloadstring', 'webclient'
        ]
        for pattern in suspicious_cmdline_patterns:
            if pattern in cmdline_str:
                suspicion_score += 3
                reasons.append(f"Suspicious command line: {pattern}")
                break
    
    # Return suspicious if score is above threshold
    is_suspicious = suspicion_score >= 3
    
    if is_suspicious:
        proc['suspicion_score'] = suspicion_score
        proc['suspicion_reasons'] = reasons
    
    return is_suspicious

def flag_suspicious_processes(processes):
    """Flag processes as suspicious based on enhanced criteria."""
    suspicious = []
    for proc in processes:
        if is_process_suspicious(proc):
            suspicious.append(proc)
    
    # Sort by suspicion score (highest first)
    suspicious.sort(key=lambda x: x.get('suspicion_score', 0), reverse=True)
    return suspicious

def check_security_services():
    """Check status of security services."""
    os_type = platform.system()
    services_status = {}
    
    if os_type == 'Windows':
        # Check Windows Firewall
        try:
            output = subprocess.check_output(['netsh', 'advfirewall', 'show', 'allprofiles'], 
                                           text=True, stderr=subprocess.DEVNULL)
            services_status['firewall'] = 'Active' if 'State                                 ON' in output else 'Inactive'
        except (subprocess.CalledProcessError, FileNotFoundError):
            services_status['firewall'] = 'Unknown'
        
        # Check Windows Defender
        try:
            output = subprocess.check_output(['powershell', '-Command', 
                                           'Get-MpComputerStatus | Select-Object -Property AntivirusEnabled'], 
                                           text=True, stderr=subprocess.DEVNULL)
            services_status['antivirus'] = 'Active' if 'True' in output else 'Inactive'
        except (subprocess.CalledProcessError, FileNotFoundError):
            services_status['antivirus'] = 'Unknown'
            
    elif os_type == 'Linux':
        # Check UFW firewall
        try:
            output = subprocess.check_output(['ufw', 'status'], text=True, stderr=subprocess.DEVNULL)
            services_status['ufw'] = 'Active' if 'Status: active' in output else 'Inactive'
        except (subprocess.CalledProcessError, FileNotFoundError):
            services_status['ufw'] = 'Not installed'
        
        # Check iptables
        try:
            output = subprocess.check_output(['iptables', '-L'], text=True, stderr=subprocess.DEVNULL)
            rule_count = len([line for line in output.split('\n') if line.strip() and not line.startswith('Chain')])
            services_status['iptables'] = f'Active ({rule_count} rules)' if rule_count > 3 else 'Minimal rules'
        except (subprocess.CalledProcessError, FileNotFoundError):
            services_status['iptables'] = 'Not accessible'
        
        # Check for common antivirus
        av_processes = ['clamd', 'freshclam', 'clamav', 'avast', 'sophos']
        running_av = []
        for proc in psutil.process_iter(['name']):
            try:
                if any(av in proc.info['name'].lower() for av in av_processes):
                    running_av.append(proc.info['name'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        services_status['antivirus'] = f'Running: {", ".join(running_av)}' if running_av else 'None detected'
    
    return services_status

def generate_process_summary(processes, suspicious):
    """Generate a summary of process analysis."""
    total_processes = len(processes)
    suspicious_count = len(suspicious)
    
    # CPU and memory statistics
    cpu_usage = [p.get('cpu_percent', 0) for p in processes if p.get('cpu_percent') is not None]
    memory_usage = [p.get('memory_percent', 0) for p in processes if p.get('memory_percent') is not None]
    
    summary = {
        'total_processes': total_processes,
        'suspicious_processes': suspicious_count,
        'risk_percentage': (suspicious_count / total_processes * 100) if total_processes > 0 else 0,
        'avg_cpu_usage': sum(cpu_usage) / len(cpu_usage) if cpu_usage else 0,
        'avg_memory_usage': sum(memory_usage) / len(memory_usage) if memory_usage else 0,
        'high_cpu_processes': len([p for p in processes if p.get('cpu_percent', 0) > 50]),
        'high_memory_processes': len([p for p in processes if p.get('memory_percent', 0) > 50])
    }
    
    return summary

def create_test_suspicious_process():
    """Create a simulated suspicious process for testing (demonstration only)."""
    # This would simulate a suspicious process for testing
    # In a real implementation, this might involve creating test scenarios
    test_process = {
        'pid': 99999,
        'name': 'suspicious_test.exe',
        'exe': 'C:\\Temp\\suspicious_test.exe',
        'cpu_percent': 95.0,
        'memory_percent': 75.0,
        'create_time': time.time() - 3600,  # 1 hour ago
        'runtime_hours': 1.0,
        'ppid': 1,
        'username': 'SYSTEM',
        'cmdline': ['C:\\Temp\\suspicious_test.exe', '-hidden', '-encrypt'],
        'suspicion_score': 8,
        'suspicion_reasons': ['High CPU usage: 95.0%', 'Suspicious path: C:\\Temp\\suspicious_test.exe', 'Suspicious command line: -hidden']
    }
    return test_process

def run_system_security(include_test=False):
    """Main function to run system security analysis."""
    print(f"Running enhanced security check on {platform.system()}")
    
    processes = list_processes()
    suspicious = flag_suspicious_processes(processes)
    services = check_security_services()
    summary = generate_process_summary(processes, suspicious)
    
    # Add test suspicious process for demonstration if requested
    if include_test and len(suspicious) < 5:
        test_process = create_test_suspicious_process()
        suspicious.insert(0, test_process)  # Add at the beginning
        summary['test_process_added'] = True
    
    result = {
        'processes': processes,
        'suspicious': suspicious,
        'services': services,
        'summary': summary,
        'analysis_timestamp': time.time()
    }
    
    return result

if __name__ == "__main__":
    result = run_system_security(include_test=True)  # Include test for demonstration
    
    print(f"Total Processes: {result['summary']['total_processes']}")
    print(f"Suspicious Processes: {result['summary']['suspicious_processes']}")
    print(f"Risk Percentage: {result['summary']['risk_percentage']:.2f}%")
    print(f"Average CPU Usage: {result['summary']['avg_cpu_usage']:.2f}%")
    print(f"Average Memory Usage: {result['summary']['avg_memory_usage']:.2f}%")
    
    print("\nTop 5 Most Suspicious Processes:")
    for i, proc in enumerate(result['suspicious'][:5], 1):
        print(f"{i}. {proc['name']} (PID: {proc.get('pid', 'N/A')})")
        print(f"   Score: {proc.get('suspicion_score', 0)}")
        print(f"   Reasons: {', '.join(proc.get('suspicion_reasons', []))}")
        print(f"   CPU: {proc.get('cpu_percent', 0):.1f}%, Memory: {proc.get('memory_percent', 0):.1f}%")
        print()
    
    print(f"Security Services Status: {result['services']}")
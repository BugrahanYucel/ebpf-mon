#!/usr/bin/env python3
"""
Instrumented Test Harness for eBPF Monitoring Tool
Generates controlled workload and ground truth for validation.
"""

import os
import sys
import json
import socket
import time
import subprocess
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any
import struct


class GroundTruthTracker:
    """Tracks all operations to generate ground truth matching eBPF output format"""
    
    def __init__(self):
        # Use nested dicts with tuples as keys to track unique events and frequencies
        self.network_events = defaultdict(lambda: {'freq': 0, 'data': None})
        self.fs_events = defaultdict(lambda: {'freq': 0, 'data': None})
        self.process_events = defaultdict(lambda: {'freq': 0, 'data': None})
        self.cgroup_id = self._get_cgroup_id()
        print(f"[Ground Truth] Using cgroup ID (inode): {self.cgroup_id}")
    
    def _get_cgroup_id(self) -> int:
        """Get current process cgroup ID (inode)"""
        try:
            with open(f'/proc/self/cgroup', 'r') as f:
                # Parse cgroup v2 format: 0::/docker/xxxxx or similar
                lines = f.readlines()
                if lines:
                    # Get relative cgroup path
                    cgroup_rel_path = lines[0].strip().split(':')[-1]
                    # Convert to full path
                    cgroup_full_path = f'/sys/fs/cgroup{cgroup_rel_path}'
                    # Get inode (same as eBPF does)
                    stat_info = os.stat(cgroup_full_path)
                    return stat_info.st_ino
        except Exception as e:
            # Fallback: try to get inode of /sys/fs/cgroup
            try:
                stat_info = os.stat('/sys/fs/cgroup')
                return stat_info.st_ino
            except:
                pass
        return 686846  # Default/example value
    
    def _get_file_info(self, filepath: str) -> Dict[str, Any]:
        """Get inode and owner_uid for a file"""
        try:
            # Resolve symlinks to get real path (matches eBPF behavior)
            real_path = os.path.realpath(filepath)
            stat_info = os.stat(real_path)
            return {
                'inode': stat_info.st_ino,
                'owner_uid': stat_info.st_uid,
                'real_path': real_path
            }
        except OSError:
            return {'inode': 0, 'owner_uid': 0, 'real_path': filepath}
    
    def _ip_to_u32(self, ip_str: str) -> int:
        """Convert IP string to u32 (little-endian byte order to match kernel)"""
        try:
            # Parse IP address
            parts = ip_str.split('.')
            if len(parts) != 4:
                return 0
            # Pack in network byte order (big-endian), then interpret as little-endian
            # Actually, looking at the serialize_ip function, it uses direct bit shifting
            # ip & 0xFF is first octet, so it's already in the right order
            return (int(parts[0]) | 
                    (int(parts[1]) << 8) | 
                    (int(parts[2]) << 16) | 
                    (int(parts[3]) << 24))
        except:
            return 0
    
    def track_network_event(self, dst_ip: str, dst_port: int, direction: str):
        """
        Track a network event
        direction: 'outgoing' (1) or 'incoming' (0)
        Identity: (dst_ip, dst_port, direction)
        """
        dst_ip_u32 = self._ip_to_u32(dst_ip)
        direction_val = 1 if direction == 'outgoing' else 0
        
        # Create unique key matching eBPF NetworkIdentity hash
        key = (dst_ip_u32, dst_port, direction_val)
        
        self.network_events[key]['freq'] += 1
        if self.network_events[key]['data'] is None:
            self.network_events[key]['data'] = {
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'direction': direction,
            }
    
    def track_fs_event(self, path: str, operation: str):
        """
        Track a filesystem event
        operation: 'read' (0) or 'write' (1)
        Identity: (inode, r_w, owner_uid)
        """
        file_info = self._get_file_info(path)
        r_w_val = 1 if operation == 'write' else 0
        
        # Use real path (resolved symlinks) to match eBPF behavior
        real_path = file_info.get('real_path', path)
        
        # Create unique key matching eBPF FsIdentity hash
        key = (file_info['inode'], r_w_val, file_info['owner_uid'])
        
        self.fs_events[key]['freq'] += 1
        if self.fs_events[key]['data'] is None:
            self.fs_events[key]['data'] = {
                'path': real_path,  # Use resolved path
                'inode': file_info['inode'],
                'owner_uid': file_info['owner_uid'],
                'r_w': operation,
            }
    
    def track_process_event(self, exec_path: str, ps_type: str, pid: int):
        """
        Track a process event
        ps_type: 'execve' (0) or 'fork' (1)
        Identity: (inode, ps_type, cgroup) - NO pid
        """
        file_info = self._get_file_info(exec_path)
        ps_type_val = 0 if ps_type == 'execve' else 1
        
        # Use real path (resolved symlinks) to match eBPF behavior
        real_exec_path = file_info.get('real_path', exec_path)
        
        # Create unique key matching eBPF ProcessIdentity hash (NO pid!)
        key = (file_info['inode'], ps_type_val, self.cgroup_id)
        
        self.process_events[key]['freq'] += 1
        if self.process_events[key]['data'] is None:
            self.process_events[key]['data'] = {
                'exec_path': real_exec_path,  # Use resolved path
                'inode': file_info['inode'],
                'ps_type': ps_type,
                'pid': pid,
                'cgroup': self.cgroup_id,
            }
    
    def export_json(self, filename: str = 'ground_truth.json'):
        """Export ground truth in the exact format of eBPF tool output"""
        
        # Convert to list format with frequencies
        network_list = []
        for key, val in self.network_events.items():
            data = val['data'].copy()
            data['freq'] = val['freq']
            network_list.append(data)
        
        fs_list = []
        for key, val in self.fs_events.items():
            data = val['data'].copy()
            data['freq'] = val['freq']
            fs_list.append(data)
        
        process_list = []
        for key, val in self.process_events.items():
            data = val['data'].copy()
            data['freq'] = val['freq']
            process_list.append(data)
        
        # Sort by frequency (descending) to match eBPF output
        network_list.sort(key=lambda x: x['freq'], reverse=True)
        fs_list.sort(key=lambda x: x['freq'], reverse=True)
        process_list.sort(key=lambda x: x['freq'], reverse=True)
        
        output = {
            'cgroup': str(self.cgroup_id),
            'network': network_list,
            'fs': fs_list,
            'process': process_list
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n{'='*60}")
        print(f"Ground Truth exported to: {filename}")
        print(f"{'='*60}")
        print(f"Total unique network events: {len(network_list)}")
        print(f"Total unique fs events: {len(fs_list)}")
        print(f"Total unique process events: {len(process_list)}")
        print(f"Total network operations: {sum(x['freq'] for x in network_list)}")
        print(f"Total fs operations: {sum(x['freq'] for x in fs_list)}")
        print(f"Total process operations: {sum(x['freq'] for x in process_list)}")
        print(f"{'='*60}\n")
        
        return output


class TestWorkload:
    """Execute controlled workload with tracking"""
    
    def __init__(self, tracker: GroundTruthTracker):
        self.tracker = tracker
        self.test_dir = Path('/tmp/ebpf_test')
        self.test_dir.mkdir(exist_ok=True)
    
    def network_tests(self):
        """Controlled network operations"""
        print("\n[+] Running Network Tests...")
        
        # Test 1: Multiple connections to same destination (should deduplicate)
        print("  - Testing connection deduplication (5x to 1.1.1.1:443)")
        for i in range(5):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect(('1.1.1.1', 443))
                self.tracker.track_network_event('1.1.1.1', 443, 'outgoing')
                sock.close()
                time.sleep(0.1)
            except Exception as e:
                # Track even if connection fails (eBPF tracks at syscall level)
                self.tracker.track_network_event('1.1.1.1', 443, 'outgoing')
        
        # Test 2: Different ports to same IP
        print("  - Testing different destination ports")
        for port in [443, 80, 8080]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect(('8.8.8.8', port))
                self.tracker.track_network_event('8.8.8.8', port, 'outgoing')
                sock.close()
            except:
                self.tracker.track_network_event('8.8.8.8', port, 'outgoing')
        
        # Test 3: UDP connections (DNS-like)
        print("  - Testing UDP connections (DNS to 1.1.1.1:53)")
        for i in range(3):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                sock.sendto(b'test', ('1.1.1.1', 53))
                self.tracker.track_network_event('1.1.1.1', 53, 'outgoing')
                sock.close()
            except:
                self.tracker.track_network_event('1.1.1.1', 53, 'outgoing')
        
        # Test 4: Different IPs
        print("  - Testing different destination IPs")
        for ip in ['93.184.216.34', '142.250.185.46']:  # example.com, google.com
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip, 443))
                self.tracker.track_network_event(ip, 443, 'outgoing')
                sock.close()
            except:
                self.tracker.track_network_event(ip, 443, 'outgoing')
        
        print(f"  ✓ Network tests complete")
    
    def fs_tests(self):
        """Controlled filesystem operations"""
        print("\n[+] Running Filesystem Tests...")
        
        # Test 1: Multiple reads of same file (should deduplicate)
        print("  - Testing read deduplication (5x reads of same file)")
        test_file = self.test_dir / 'test_read.txt'
        test_file.write_text('test content')
        for i in range(5):
            with open(test_file, 'r') as f:
                _ = f.read()
            self.tracker.track_fs_event(str(test_file), 'read')
        
        # Test 2: Multiple writes to same file (should deduplicate)
        print("  - Testing write deduplication (5x writes to same file)")
        test_file_write = self.test_dir / 'test_write.txt'
        for i in range(5):
            with open(test_file_write, 'w') as f:
                f.write(f'content {i}')
            self.tracker.track_fs_event(str(test_file_write), 'write')
        
        # Test 3: Read and write to same file (different events due to r_w)
        print("  - Testing read + write to same file")
        test_rw = self.test_dir / 'test_rw.txt'
        test_rw.write_text('initial')
        with open(test_rw, 'r') as f:
            _ = f.read()
        self.tracker.track_fs_event(str(test_rw), 'read')
        with open(test_rw, 'w') as f:
            f.write('modified')
        self.tracker.track_fs_event(str(test_rw), 'write')
        
        # Test 4: Multiple different files
        print("  - Testing operations on different files")
        for i in range(3):
            fpath = self.test_dir / f'file_{i}.txt'
            fpath.write_text(f'data {i}')
            self.tracker.track_fs_event(str(fpath), 'write')
            with open(fpath, 'r') as f:
                _ = f.read()
            self.tracker.track_fs_event(str(fpath), 'read')
        
        # Test 5: System files (common patterns)
        print("  - Testing system file reads")
        system_files = ['/etc/hosts', '/etc/resolv.conf', '/proc/self/status']
        for fpath in system_files:
            try:
                with open(fpath, 'r') as f:
                    _ = f.read()
                self.tracker.track_fs_event(fpath, 'read')
            except:
                pass
        
        print(f"  ✓ Filesystem tests complete")
    
    def process_tests(self):
        """Controlled process operations"""
        print("\n[+] Running Process Tests...")
        
        # Test 1: Multiple execve of same binary (should deduplicate by inode+cgroup)
        print("  - Testing execve deduplication (3x echo)")
        for i in range(3):
            result = subprocess.run(['echo', f'test {i}'], 
                                  capture_output=True, text=True)
            # Find actual binary path (subprocess resolves it)
            import shutil
            echo_path = shutil.which('echo') or '/usr/bin/echo'
            self.tracker.track_process_event(echo_path, 'execve', result.returncode)
        
        # Test 2: Different binaries
        print("  - Testing different binaries")
        binaries = ['ls', 'cat', 'pwd']
        for binary in binaries:
            try:
                result = subprocess.run([binary], capture_output=True, text=True, 
                                      timeout=1)
                import shutil
                binary_path = shutil.which(binary) or f'/usr/bin/{binary}'
                self.tracker.track_process_event(binary_path, 'execve', result.returncode)
            except Exception as e:
                import shutil
                binary_path = shutil.which(binary) or f'/usr/bin/{binary}'
                self.tracker.track_process_event(binary_path, 'execve', 0)
        
        # Test 3: Fork operations
        # NOTE: Python subprocess.run() causes Python itself to fork, not sh
        # So we track the Python interpreter as the forking process
        print("  - Testing fork events (Python interpreter forks)")
        import sys
        python_path = sys.executable  # e.g., /usr/local/bin/python3.9
        
        # Each subprocess.run() causes Python to fork
        for i in range(2):
            result = subprocess.run(['sh', '-c', 'exit 0'], 
                                  capture_output=True)
            # Track Python as the forking process (what actually happens)
            self.tracker.track_process_event(python_path, 'fork', os.getpid())
        
        print(f"  ✓ Process tests complete")
    
    def cleanup(self):
        """Clean up test files"""
        import shutil
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)


def main():
    """Main test execution"""
    print("="*60)
    print("eBPF Monitoring Tool - Test Harness")
    print("="*60)
    print(f"PID: {os.getpid()}")
    print(f"UID: {os.getuid()}")
    
    tracker = GroundTruthTracker()
    workload = TestWorkload(tracker)
    
    try:
        # Run all tests
        workload.network_tests()
        workload.fs_tests()
        workload.process_tests()
        
        # Export ground truth
        output_file = sys.argv[1] if len(sys.argv) > 1 else 'ground_truth.json'
        tracker.export_json(output_file)
        
        print("\n[✓] Test workload complete!")
        print(f"[!] Now run your eBPF tool and compare outputs")
        
    finally:
        workload.cleanup()


if __name__ == '__main__':
    main()








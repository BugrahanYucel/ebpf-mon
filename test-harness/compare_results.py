#!/usr/bin/env python3
"""
Compare ground truth with eBPF tool output to validate completeness and accuracy
"""

import json
import sys
from typing import Dict, List, Set, Tuple
from collections import defaultdict


class EventComparator:
    """Compare ground truth events with eBPF captured events"""
    
    def __init__(self, ground_truth_file: str, ebpf_output_file: str):
        with open(ground_truth_file, 'r') as f:
            self.ground_truth = json.load(f)
        
        with open(ebpf_output_file, 'r') as f:
            self.ebpf_output = json.load(f)
    
    def _normalize_network_event(self, event: Dict) -> Tuple:
        """Create normalized key for network event (matching eBPF NetworkIdentity)"""
        # Key: (dst_ip, dst_port, direction)
        return (event['dst_ip'], event['dst_port'], event['direction'])
    
    def _normalize_fs_event(self, event: Dict) -> Tuple:
        """Create normalized key for fs event (matching eBPF FsIdentity)"""
        # Key: (inode, r_w, owner_uid)
        return (event['inode'], event['r_w'], event['owner_uid'])
    
    def _normalize_process_event(self, event: Dict) -> Tuple:
        """Create normalized key for process event (matching eBPF ProcessIdentity)"""
        # Key: (inode, ps_type, cgroup) - NO pid!
        return (event['inode'], event['ps_type'], event['cgroup'])
    
    def compare_network_events(self):
        """Compare network events"""
        print("\n" + "="*70)
        print("NETWORK EVENTS COMPARISON")
        print("="*70)
        
        gt_events = {self._normalize_network_event(e): e for e in self.ground_truth['network']}
        ebpf_events = {self._normalize_network_event(e): e for e in self.ebpf_output['network']}
        
        gt_keys = set(gt_events.keys())
        ebpf_keys = set(ebpf_events.keys())
        
        # Analysis
        matched = gt_keys & ebpf_keys
        missed = gt_keys - ebpf_keys
        extra = ebpf_keys - gt_keys
        
        print(f"\n📊 Summary:")
        print(f"  Ground Truth: {len(gt_keys)} unique events")
        print(f"  eBPF Captured: {len(ebpf_keys)} unique events")
        print(f"  Matched: {len(matched)} ✓")
        print(f"  Missed: {len(missed)} ✗")
        print(f"  Extra (not in ground truth): {len(extra)} ⚠")
        
        if matched:
            print(f"\n✓ Matched Events ({len(matched)}):")
            for key in sorted(matched):
                gt_event = gt_events[key]
                ebpf_event = ebpf_events[key]
                freq_match = "✓" if gt_event['freq'] == ebpf_event['freq'] else "✗"
                print(f"  {freq_match} {gt_event['dst_ip']}:{gt_event['dst_port']} "
                      f"({gt_event['direction']}) - GT freq: {gt_event['freq']}, "
                      f"eBPF freq: {ebpf_event['freq']}")
        
        if missed:
            print(f"\n✗ Missed Events ({len(missed)}):")
            for key in sorted(missed):
                event = gt_events[key]
                print(f"  - {event['dst_ip']}:{event['dst_port']} "
                      f"({event['direction']}) - freq: {event['freq']}")
        
        if extra:
            print(f"\n⚠ Extra Events ({len(extra)}) - Captured by eBPF but not in ground truth:")
            for key in sorted(extra):
                event = ebpf_events[key]
                print(f"  + {event['dst_ip']}:{event['dst_port']} "
                      f"({event['direction']}) - freq: {event['freq']}")
        
        return {
            'total_gt': len(gt_keys),
            'total_ebpf': len(ebpf_keys),
            'matched': len(matched),
            'missed': len(missed),
            'extra': len(extra),
            'accuracy': len(matched) / len(gt_keys) * 100 if gt_keys else 0
        }
    
    def compare_fs_events(self):
        """Compare filesystem events"""
        print("\n" + "="*70)
        print("FILESYSTEM EVENTS COMPARISON")
        print("="*70)
        
        gt_events = {self._normalize_fs_event(e): e for e in self.ground_truth['fs']}
        ebpf_events = {self._normalize_fs_event(e): e for e in self.ebpf_output['fs']}
        
        gt_keys = set(gt_events.keys())
        ebpf_keys = set(ebpf_events.keys())
        
        matched = gt_keys & ebpf_keys
        missed = gt_keys - ebpf_keys
        extra = ebpf_keys - gt_keys
        
        print(f"\n📊 Summary:")
        print(f"  Ground Truth: {len(gt_keys)} unique events")
        print(f"  eBPF Captured: {len(ebpf_keys)} unique events")
        print(f"  Matched: {len(matched)} ✓")
        print(f"  Missed: {len(missed)} ✗")
        print(f"  Extra (not in ground truth): {len(extra)} ⚠")
        
        if matched:
            print(f"\n✓ Matched Events ({len(matched)}):")
            for key in sorted(matched, key=lambda k: gt_events[k]['freq'], reverse=True)[:10]:
                gt_event = gt_events[key]
                ebpf_event = ebpf_events[key]
                freq_match = "✓" if gt_event['freq'] == ebpf_event['freq'] else "✗"
                print(f"  {freq_match} {gt_event['path']} ({gt_event['r_w']}) "
                      f"- GT freq: {gt_event['freq']}, eBPF freq: {ebpf_event['freq']}")
            if len(matched) > 10:
                print(f"  ... and {len(matched) - 10} more")
        
        if missed:
            print(f"\n✗ Missed Events ({len(missed)}):")
            for key in sorted(missed, key=lambda k: gt_events[k]['freq'], reverse=True)[:10]:
                event = gt_events[key]
                print(f"  - {event['path']} ({event['r_w']}) "
                      f"- inode: {event['inode']}, freq: {event['freq']}")
            if len(missed) > 10:
                print(f"  ... and {len(missed) - 10} more")
        
        if extra:
            print(f"\n⚠ Extra Events ({len(extra)}) - Showing top 10:")
            extra_sorted = sorted(extra, key=lambda k: ebpf_events[k]['freq'], reverse=True)[:10]
            for key in extra_sorted:
                event = ebpf_events[key]
                print(f"  + {event['path']} ({event['r_w']}) "
                      f"- inode: {event['inode']}, freq: {event['freq']}")
            if len(extra) > 10:
                print(f"  ... and {len(extra) - 10} more")
        
        return {
            'total_gt': len(gt_keys),
            'total_ebpf': len(ebpf_keys),
            'matched': len(matched),
            'missed': len(missed),
            'extra': len(extra),
            'accuracy': len(matched) / len(gt_keys) * 100 if gt_keys else 0
        }
    
    def compare_process_events(self):
        """Compare process events"""
        print("\n" + "="*70)
        print("PROCESS EVENTS COMPARISON")
        print("="*70)
        
        gt_events = {self._normalize_process_event(e): e for e in self.ground_truth['process']}
        ebpf_events = {self._normalize_process_event(e): e for e in self.ebpf_output['process']}
        
        gt_keys = set(gt_events.keys())
        ebpf_keys = set(ebpf_events.keys())
        
        matched = gt_keys & ebpf_keys
        missed = gt_keys - ebpf_keys
        extra = ebpf_keys - gt_keys
        
        print(f"\n📊 Summary:")
        print(f"  Ground Truth: {len(gt_keys)} unique events")
        print(f"  eBPF Captured: {len(ebpf_keys)} unique events")
        print(f"  Matched: {len(matched)} ✓")
        print(f"  Missed: {len(missed)} ✗")
        print(f"  Extra (not in ground truth): {len(extra)} ⚠")
        
        if matched:
            print(f"\n✓ Matched Events ({len(matched)}):")
            for key in sorted(matched):
                gt_event = gt_events[key]
                ebpf_event = ebpf_events[key]
                freq_match = "✓" if gt_event['freq'] == ebpf_event['freq'] else "✗"
                print(f"  {freq_match} {gt_event['exec_path']} ({gt_event['ps_type']}) "
                      f"- GT freq: {gt_event['freq']}, eBPF freq: {ebpf_event['freq']}")
        
        if missed:
            print(f"\n✗ Missed Events ({len(missed)}):")
            for key in sorted(missed):
                event = gt_events[key]
                print(f"  - {event['exec_path']} ({event['ps_type']}) "
                      f"- inode: {event['inode']}, freq: {event['freq']}")
        
        if extra:
            print(f"\n⚠ Extra Events ({len(extra)}):")
            for key in sorted(extra)[:20]:
                event = ebpf_events[key]
                print(f"  + {event['exec_path']} ({event['ps_type']}) "
                      f"- inode: {event['inode']}, freq: {event['freq']}")
            if len(extra) > 20:
                print(f"  ... and {len(extra) - 20} more")
        
        return {
            'total_gt': len(gt_keys),
            'total_ebpf': len(ebpf_keys),
            'matched': len(matched),
            'missed': len(missed),
            'extra': len(extra),
            'accuracy': len(matched) / len(gt_keys) * 100 if gt_keys else 0
        }
    
    def generate_report(self):
        """Generate comprehensive comparison report"""
        print("\n" + "="*70)
        print("eBPF MONITORING TOOL VALIDATION REPORT")
        print("="*70)
        
        net_stats = self.compare_network_events()
        fs_stats = self.compare_fs_events()
        proc_stats = self.compare_process_events()
        
        print("\n" + "="*70)
        print("OVERALL VALIDATION SUMMARY")
        print("="*70)
        
        total_gt = net_stats['total_gt'] + fs_stats['total_gt'] + proc_stats['total_gt']
        total_matched = net_stats['matched'] + fs_stats['matched'] + proc_stats['matched']
        total_missed = net_stats['missed'] + fs_stats['missed'] + proc_stats['missed']
        total_extra = net_stats['extra'] + fs_stats['extra'] + proc_stats['extra']
        
        overall_accuracy = (total_matched / total_gt * 100) if total_gt > 0 else 0
        
        print(f"\n📈 Overall Statistics:")
        print(f"  Total Ground Truth Events: {total_gt}")
        print(f"  Total Matched: {total_matched} ({total_matched/total_gt*100:.1f}%)")
        print(f"  Total Missed: {total_missed} ({total_missed/total_gt*100:.1f}%)")
        print(f"  Total Extra: {total_extra}")
        print(f"\n  Overall Accuracy: {overall_accuracy:.2f}%")
        
        print(f"\n📊 Per-Category Accuracy:")
        print(f"  Network:  {net_stats['accuracy']:.1f}%")
        print(f"  Filesystem: {fs_stats['accuracy']:.1f}%")
        print(f"  Process:  {proc_stats['accuracy']:.1f}%")
        
        # Verdict
        print(f"\n{'='*70}")
        if overall_accuracy >= 95:
            print("✅ EXCELLENT: Tool captures >95% of ground truth events")
        elif overall_accuracy >= 80:
            print("✓ GOOD: Tool captures >80% of ground truth events")
        elif overall_accuracy >= 60:
            print("⚠ FAIR: Tool captures >60% of ground truth events - review missed events")
        else:
            print("✗ NEEDS IMPROVEMENT: Tool captures <60% of ground truth events")
        print("="*70)
        
        # Notes about extra events
        if total_extra > 0:
            print(f"\nℹ Note: {total_extra} extra events were captured by eBPF.")
            print("  This is normal - the tool captures system background activity.")
            print("  Focus on ensuring ground truth events are NOT in the 'missed' category.")
        
        return {
            'network': net_stats,
            'fs': fs_stats,
            'process': proc_stats,
            'overall_accuracy': overall_accuracy
        }


def main():
    if len(sys.argv) != 3:
        print("Usage: python compare_results.py <ground_truth.json> <ebpf_output.json>")
        print("\nExample:")
        print("  python compare_results.py ground_truth.json events.json")
        sys.exit(1)
    
    ground_truth_file = sys.argv[1]
    ebpf_output_file = sys.argv[2]
    
    try:
        comparator = EventComparator(ground_truth_file, ebpf_output_file)
        comparator.generate_report()
    except FileNotFoundError as e:
        print(f"Error: File not found - {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()








#!/usr/bin/env python3
"""
Test script for shellcode detection capabilities
Demonstrates the ShellcodeDetector module with sample payloads
"""

from shellcode_detector import ShellcodeDetector, ShellcodeType, Architecture
import binascii


def test_signature_detection():
    """Test signature-based detection"""
    print("\n" + "="*70)
    print("TEST 1: Signature-Based Shellcode Detection")
    print("="*70)
    
    detector = ShellcodeDetector()
    
    # Sample payloads (safe for testing - no execution)
    test_payloads = {
        'x86_syscall': b'\xcd\x80',  # int 0x80
        'x64_syscall': b'\x0f\x05',  # syscall
        'nop_sled': b'\x90' * 16,     # 16 NOPs
        'stack_pivot': b'\x5c\xc3',   # pop rsp; ret
        'function_prologue': b'\x55\x89\xe5',  # push ebp; mov ebp, esp
    }
    
    for name, payload in test_payloads.items():
        detections = detector.detect_shellcode(payload)
        print(f"\n{name}:")
        print(f"  Payload (hex): {payload.hex()}")
        print(f"  Detections: {len(detections)}")
        if detections:
            for det in detections[:3]:  # Show first 3
                print(f"    - {det['description']} [{det['threat_level']}]")


def test_nop_sled_detection():
    """Test NOP sled pattern detection"""
    print("\n" + "="*70)
    print("TEST 2: NOP Sled Detection")
    print("="*70)
    
    detector = ShellcodeDetector()
    
    # Create memory region with NOP sled
    memory = b'\x00' * 100 + b'\x90' * 32 + b'\x55\x89\xe5' + b'\x00' * 100
    
    detections = detector.detect_shellcode(memory)
    nop_detections = [d for d in detections if d['type'] == 'nop_sled']
    
    print(f"Memory size: {len(memory)} bytes")
    print(f"NOP sled detections: {len(nop_detections)}")
    
    if nop_detections:
        for det in nop_detections:
            print(f"  Offset: {hex(det['offset'])}")
            print(f"  Size: {det['size']} bytes")
            print(f"  Description: {det['description']}")


def test_architecture_detection():
    """Test architecture detection"""
    print("\n" + "="*70)
    print("TEST 3: Architecture Detection")
    print("="*70)
    
    detector = ShellcodeDetector()
    
    test_cases = {
        'x86': b'\xcd\x80' + b'\x55\x89\xe5',  # int 0x80 + prologue
        'x64': b'\x0f\x05' + b'\x48\x89\xe5',  # syscall + x64 prologue
        'mixed': b'\xcd\x80\x0f\x05',  # Both
    }
    
    for arch_name, payload in test_cases.items():
        detected_arch = detector._detect_architecture(payload)
        print(f"\n{arch_name}:")
        print(f"  Payload (hex): {payload.hex()}")
        print(f"  Detected architecture: {detected_arch.value}")


def test_entropy_detection():
    """Test entropy analysis"""
    print("\n" + "="*70)
    print("TEST 4: Entropy Analysis (Encrypted Shellcode Detection)")
    print("="*70)
    
    detector = ShellcodeDetector()
    
    # Low entropy (normal data)
    low_entropy_data = b'A' * 64
    
    # High entropy (random/encrypted)
    import os
    high_entropy_data = os.urandom(64)
    
    low_ent = detector._calculate_entropy(low_entropy_data)
    high_ent = detector._calculate_entropy(high_entropy_data)
    
    print(f"\nLow entropy data (AAAA...): {low_ent:.2f}")
    print(f"High entropy data (random): {high_ent:.2f}")
    print(f"\nEntropy threshold for suspicious: 7.0")
    print(f"Low entropy marked suspicious: {low_ent > 7.0}")
    print(f"High entropy marked suspicious: {high_ent > 7.0}")


def test_shellcode_classification():
    """Test shellcode type classification"""
    print("\n" + "="*70)
    print("TEST 5: Shellcode Classification")
    print("="*70)
    
    detector = ShellcodeDetector()
    
    # Create sample payload with execution function indicator
    payload = b'CreateProcessA' + b'\x90' * 50 + b'\xcd\x80'
    
    classification = detector.classify_shellcode(payload)
    
    print(f"\nPayload analysis:")
    print(f"  Type: {classification['type']}")
    print(f"  Confidence: {classification['confidence']}%")
    print(f"  Architecture: {classification['architecture']}")
    print(f"  Size: {classification['size']} bytes")
    print(f"  Entropy: {classification['entropy']:.2f}")
    print(f"  Detections found: {classification['detections_count']}")


def test_candidate_extraction():
    """Test shellcode candidate extraction"""
    print("\n" + "="*70)
    print("TEST 6: Shellcode Candidate Extraction")
    print("="*70)
    
    detector = ShellcodeDetector()
    
    # Create memory region with NOP sled followed by code
    memory = b'\x00' * 100
    memory += b'\x90' * 32  # NOP sled
    memory += b'\x55\x89\xe5' + b'\x83\xec\x20' + b'\xc3'  # Code
    memory += b'\x00' * 100
    
    candidates = detector.extract_shellcode_candidates(memory)
    
    print(f"\nMemory size: {len(memory)} bytes")
    print(f"Shellcode candidates extracted: {len(candidates)}")
    
    for i, candidate in enumerate(candidates, 1):
        print(f"\n  Candidate {i}:")
        print(f"    Source: {candidate['source']}")
        print(f"    Offset: {hex(candidate['offset'])}")
        print(f"    Size: {candidate['size']} bytes")
        print(f"    Entropy: {candidate['entropy']:.2f}")


def test_report_generation():
    """Test report generation"""
    print("\n" + "="*70)
    print("TEST 7: Report Generation")
    print("="*70)
    
    detector = ShellcodeDetector()
    
    payload = b'\xcd\x80' + b'\x90' * 16 + b'\x55\x89\xe5'
    analysis = detector.analyze_shellcode_region(payload, base_addr=0x1000)
    
    report = detector.generate_report(analysis)
    print(report)


def run_all_tests():
    """Run all tests"""
    print("\n" + "#"*70)
    print("# SHELLCODE DETECTOR TEST SUITE")
    print("#"*70)
    
    try:
        test_signature_detection()
        test_nop_sled_detection()
        test_architecture_detection()
        test_entropy_detection()
        test_shellcode_classification()
        test_candidate_extraction()
        test_report_generation()
        
        print("\n" + "#"*70)
        print("# ALL TESTS COMPLETED SUCCESSFULLY")
        print("#"*70 + "\n")
        
    except Exception as e:
        print(f"\n[ERROR] Test failed: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    run_all_tests()

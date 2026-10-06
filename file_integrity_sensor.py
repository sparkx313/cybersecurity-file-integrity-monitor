import os
import hashlib
import json
import sys

def calculate_sha256(filepath):
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None

def create_baseline(directory):
    baseline = {}
    print(f"📌 Creating Baseline Checksums for: {directory}")
    for root, _, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            checksum = calculate_sha256(full_path)
            if checksum:
                baseline[full_path] = checksum
    return baseline

def verify_integrity(directory, baseline):
    print(f"\n🔍 Auditing System Integrity against Baseline...")
    current_files = {}
    alerts = []

    for root, _, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            checksum = calculate_sha256(full_path)
            if checksum:
                current_files[full_path] = checksum

    # Check for modified or removed files
    for path, old_hash in baseline.items():
        if path not in current_files:
            alerts.append(f"❌ [DELETED FILE] {path}")
        elif current_files[path] != old_hash:
            alerts.append(f"⚠️  [MODIFIED / TAMPERED] {path}")

    # Check for new files
    for path in current_files:
        if path not in baseline:
            alerts.append(f"🚨 [UNAUTHORIZED ADDITION] {path}")

    print("=" * 60)
    print("🛡️ Integrity Audit Results")
    print("=" * 60)
    if not alerts:
        print("✅ System Status: Clean. All checksums match baseline perfectly.")
    else:
        for alert in alerts:
            print(alert)
    print("=" * 60)

def main():
    target_dir = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    baseline = create_baseline(target_dir)
    print(f"✓ Baseline created with {len(baseline)} file hashes.")
    verify_integrity(target_dir, baseline)

if __name__ == "__main__":
    main()

import os
import sys
import zipfile
import tempfile
import shutil
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import json
import logging
import hashlib
import math

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Define categories based on file paths
CATEGORIES = {
    "Frameworks": [".framework", ".xcframework"],
    "Resources": [".bundle", "Assets.car", ".nib", ".png", ".pdf", ".otf"],
    "Swift Libraries": ["libswift"],
    "Code Signature": ["_CodeSignature"],
    "Executable": ["Runner"]
}

# Function to extract IPA
def extract_ipa(ipa_path, extract_dir):
    logging.info(f"Extracting {ipa_path}...")
    with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)
    logging.info(f"Finished extracting {ipa_path}")

# Function to calculate entropy (Fixed)
def calculate_entropy(data):
    if not data:
        return 0
    byte_counts = defaultdict(int)
    for byte in data:
        byte_counts[byte] += 1
    total_bytes = len(data)
    entropy = 0
    for count in byte_counts.values():
        p = count / total_bytes
        entropy -= p * math.log2(p) if p > 0 else 0  # Corrected entropy calculation
    return entropy

# Function to list files with sizes and hashes
def get_file_list(root_dir):
    file_data = {}
    for root, _, files in os.walk(root_dir):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, root_dir)
            file_size = os.path.getsize(file_path)
            with open(file_path, 'rb') as f:
                content = f.read()
                file_hash = hashlib.md5(content).hexdigest()
                entropy = calculate_entropy(content)  # Fixed entropy function
            file_data[relative_path] = {"size": file_size, "hash": file_hash, "entropy": entropy}
    return file_data

# Function to categorize files
def categorize_files(file_list):
    categorized = defaultdict(int)
    for file, data in file_list.items():
        size = data["size"]
        for category, keywords in CATEGORIES.items():
            if any(keyword in file for keyword in keywords):
                categorized[category] += size
                break
        else:
            categorized["Other"] += size
    return categorized

# Function to compare file lists
def compare_files(before_files, after_files):
    added_files = {f: d for f, d in after_files.items() if f not in before_files}
    removed_files = {f: d for f, d in before_files.items() if f not in after_files}
    modified_files = {
        f: after_files[f]["size"] - before_files[f]["size"]
        for f in before_files if f in after_files and after_files[f]["size"] != before_files[f]["size"]
    }
    return added_files, removed_files, modified_files

# Convert bytes to MB
def format_size(size):
    return f"{size / (1024 * 1024):.2f} MB ({size} bytes)"

# Get compressed size of IPA
def get_compressed_size(ipa_path):
    return os.path.getsize(ipa_path)

# Main analysis function
def analyze_ipa(old_ipa, new_ipa, output_dir=None):
    if not os.path.isfile(old_ipa) or not os.path.isfile(new_ipa):
        logging.error("One or both IPA files are missing.")
        sys.exit(1)

    old_compressed = get_compressed_size(old_ipa)
    new_compressed = get_compressed_size(new_ipa)

    old_dir = tempfile.mkdtemp()
    new_dir = tempfile.mkdtemp()

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            executor.submit(extract_ipa, old_ipa, old_dir)
            executor.submit(extract_ipa, new_ipa, new_dir).result()

        logging.info("Parsing files...")
        before_files = get_file_list(old_dir)
        after_files = get_file_list(new_dir)

        added_files, removed_files, modified_files = compare_files(before_files, after_files)
        added_total = sum(d["size"] for d in added_files.values())
        removed_total = sum(d["size"] for d in removed_files.values())
        modified_total = sum(modified_files.values())
        before_total = sum(d["size"] for d in before_files.values())
        after_total = sum(d["size"] for d in after_files.values())
        net_change = after_total - before_total

        # Print Summary
        print("\n********** SIZE ANALYSIS SUMMARY **********")
        print(f"Compressed Before: {format_size(old_compressed)}")
        print(f"Compressed After: {format_size(new_compressed)}")
        print(f"Uncompressed Before: {format_size(before_total)}")
        print(f"Uncompressed After: {format_size(after_total)}")
        print(f"Uncompressed Net Change: {format_size(net_change)}")

        # Export JSON report
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            report = {
                "compressed": {"before": old_compressed, "after": new_compressed},
                "uncompressed": {"before": before_total, "after": after_total},
                "added": {f: d["size"] for f, d in added_files.items()},
                "removed": {f: d["size"] for f, d in removed_files.items()},
                "modified": modified_files
            }
            with open(os.path.join(output_dir, "report.json"), "w") as f:
                json.dump(report, f, indent=2)
            logging.info(f"Report saved to {output_dir}/report.json")

    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        raise
    finally:
        shutil.rmtree(old_dir)
        shutil.rmtree(new_dir)

if __name__ == "__main__":
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: python compare_ipa.py <old_ipa_path> <new_ipa_path> [output_dir]")
        sys.exit(1)

    old_ipa = sys.argv[1]
    new_ipa = sys.argv[2]
    output_dir = sys.argv[3] if len(sys.argv) == 4 else None
    analyze_ipa(old_ipa, new_ipa, output_dir)

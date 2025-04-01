import os
import sys
import zipfile
import tempfile
import shutil
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor
import json
import logging
import hashlib
import re
from datetime import datetime

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
    try:
        with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        logging.info(f"Finished extracting {ipa_path}")
    except zipfile.BadZipFile:
        logging.error(f"Invalid IPA file: {ipa_path}")
        raise

# Function to list files with sizes, hashes, and metadata
def get_file_list(root_dir):
    file_data = {}
    file_names = defaultdict(list)
    for root, _, files in os.walk(root_dir):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, root_dir)
            file_size = os.path.getsize(file_path)
            with open(file_path, 'rb') as f:
                content = f.read()
                file_hash = hashlib.md5(content).hexdigest()
            file_data[relative_path] = {"size": file_size, "hash": file_hash}
            file_names[file].append(relative_path)
    return file_data, file_names

# Function to categorize files
def categorize_files(file_list):
    categorized = defaultdict(int)
    for file, data in file_list.items():
        size = data["size"] if isinstance(data, dict) else data
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

# Function to find duplicate files with size impact
def find_duplicates(file_names, file_data):
    duplicates = {}
    for name, paths in file_names.items():
        if len(paths) > 1:
            sizes = [file_data[path]["size"] for path in paths]
            hashes = [file_data[path]["hash"] for path in paths]
            if len(set(hashes)) == 1:  # True duplicates (same content)
                duplicates[name] = {"paths": paths, "size": sizes[0], "count": len(paths)}
    return duplicates

# Convert bytes to MB with precise formatting
def format_size(size):
    mb_size = size / (1024 * 1024)  # Exact conversion: 1 MB = 1024 * 1024 bytes
    return f"{mb_size:.2f} MB ({size} bytes)"

# Get compressed size of IPA with debug logging
def get_compressed_size(ipa_path):
    try:
        size = os.path.getsize(ipa_path)
        logging.info(f"Raw size of {ipa_path}: {size} bytes")
        return size
    except FileNotFoundError:
        logging.error(f"IPA file not found: {ipa_path}")
        raise

# Enhanced architecture detection
def detect_architecture(file_path):
    if "ios-arm64_x86_64-simulator" in file_path.lower():
        return "ios-arm64_x86_64-simulator"
    elif "ios-arm64" in file_path.lower() and "simulator" not in file_path.lower():
        return "ios-arm64"
    return "Other"

# Main analysis function
def analyze_ipa(old_ipa, new_ipa, output_dir=None):
    if not os.path.isfile(old_ipa) or not os.path.isfile(new_ipa):
        logging.error("One or both IPA files are missing.")
        sys.exit(1)

    # Get compressed sizes
    old_compressed = get_compressed_size(old_ipa)
    new_compressed = get_compressed_size(new_ipa)

    # Temporary directories
    old_dir = tempfile.mkdtemp()
    new_dir = tempfile.mkdtemp()

    try:
        # Parallel extraction
        with ThreadPoolExecutor(max_workers=2) as executor:
            executor.submit(extract_ipa, old_ipa, old_dir)
            executor.submit(extract_ipa, new_ipa, new_dir).result()

        logging.info("Parsing files...")
        before_files, _ = get_file_list(old_dir)
        after_files, after_file_names = get_file_list(new_dir)

        added_files, removed_files, modified_files = compare_files(before_files, after_files)
        duplicate_files = find_duplicates(after_file_names, after_files)

        # Calculate totals
        before_total = sum(d["size"] for d in before_files.values())
        after_total = sum(d["size"] for d in after_files.values())
        added_total = sum(d["size"] for d in added_files.values())
        removed_total = sum(d["size"] for d in removed_files.values())
        modified_total = sum(modified_files.values())
        net_change = after_total - before_total

        # Categorize and analyze architectures
        added_categories = categorize_files(added_files)
        modified_categories = categorize_files({f: {"size": s} for f, s in modified_files.items()})
        simulator_binaries = {f: d["size"] for f, d in after_files.items() if "ios-arm64_x86_64-simulator" in f.lower()}
        arm64_binaries = {f: d["size"] for f, d in after_files.items() if "ios-arm64" in f.lower() and "simulator" not in f.lower()}

        # Print basic summary
        print("\n********** SIZE ANALYSIS SUMMARY **********")
        print(f"Compressed Before: {format_size(old_compressed)}")
        print(f"Compressed After: {format_size(new_compressed)}")
        print(f"Compressed Net Change: {format_size(new_compressed - old_compressed)}")
        print(f"Uncompressed Before: {format_size(before_total)}")
        print(f"Uncompressed After: {format_size(after_total)}")
        print(f"Uncompressed Added: {format_size(added_total)}")
        print(f"Uncompressed Removed: {format_size(removed_total)}")
        print(f"Uncompressed Modified: {format_size(modified_total)}")
        print(f"Uncompressed Net Change: {format_size(net_change)}\n")

        # Detailed Size Contributors Analysis
        print("********** ANALYZING SIZE CONTRIBUTORS **********")
        
        # 1. Breakdown of Increase
        print("\n1. Breakdown of Increase")
        print(f"Total Uncompressed Increase: {format_size(net_change)}")
        if added_total > 0:
            print("  Contributors to Increase:")
            total_added = sum(added_categories.values())
            for cat, size in sorted(added_categories.items(), key=lambda x: x[1], reverse=True):
                percentage = (size / total_added) * 100 if total_added > 0 else 0
                print(f"    - {cat}: {format_size(size)} ({percentage:.1f}% of added size)")
            print("  Top 5 Largest Added Files:")
            for file, data in sorted(added_files.items(), key=lambda x: x[1]["size"], reverse=True)[:5]:
                percentage = (data["size"] / added_total) * 100 if added_total > 0 else 0
                arch = detect_architecture(file)
                print(f"    - {format_size(data['size'])} - {file} ({percentage:.1f}% of added size, Arch: {arch})")
        else:
            print("  No increase detected from added files.")

        # 2. Architecture Analysis
        print("\n2. Architecture Analysis")
        total_sim_size = sum(simulator_binaries.values())
        total_arm64_size = sum(arm64_binaries.values())
        print(f"  Total Simulator Binary Size (ios-arm64_x86_64-simulator): {format_size(total_sim_size)}")
        print(f"  Total Device Binary Size (ios-arm64): {format_size(total_arm64_size)}")
        if simulator_binaries:
            percentage_of_total = (total_sim_size / after_total) * 100 if after_total > 0 else 0
            percentage_of_increase = (total_sim_size / net_change) * 100 if net_change > 0 else 0
            print(f"    - Simulator Impact: {percentage_of_total:.1f}% of total uncompressed size, {percentage_of_increase:.1f}% of increase")
            print("    Largest Simulator Binaries:")
            for file, size in sorted(simulator_binaries.items(), key=lambda x: x[1], reverse=True)[:3]:
                print(f"      - {format_size(size)} - {file}")
            print("    Optimization Recommendation:")
            print("      - Remove simulator slices using: 'flutter build ipa --release --export-options-plist=ios/ExportOptions.plist' with 'thin' set to 'arm64'.")
            print(f"      - Potential Savings: Up to {format_size(total_sim_size)} uncompressed.")
        if arm64_binaries:
            print("    Largest Device Binaries:")
            for file, size in sorted(arm64_binaries.items(), key=lambda x: x[1], reverse=True)[:3]:
                print(f"      - {format_size(size)} - {file}")

        # 3. Compression Impact
        print("\n3. Compression Impact")
        print(f"  Compressed Size Increase: {format_size(new_compressed - old_compressed)}")
        print(f"  Uncompressed Size Increase: {format_size(net_change)}")
        before_ratio = (old_compressed / before_total) * 100 if before_total > 0 else 0
        after_ratio = (new_compressed / after_total) * 100 if after_total > 0 else 0
        print(f"  Compression Ratio Before: {before_ratio:.1f}% (Compressed: {format_size(old_compressed)} / Uncompressed: {format_size(before_total)})")
        print(f"  Compression Ratio After: {after_ratio:.1f}% (Compressed: {format_size(new_compressed)} / Uncompressed: {format_size(after_total)})")
        if net_change > 0:
            effective_compression = ((new_compressed - old_compressed) / net_change) * 100
            print(f"  Effective Compression of Increase: {effective_compression:.1f}%")
            print("  Insights:")
            print("    - Lower ratios indicate better compression (e.g., binaries compress well, resources less so).")
            if effective_compression < 50:
                print("    - High binary content likely dominates the increase (compresses efficiently).")
            else:
                print("    - Resource-heavy increase (e.g., images, PDFs) may not compress as well.")
            print("  Recommendation:")
            print("    - Optimize resources (e.g., PNGs with 'pngcrush', PDFs with 'gs -sDEVICE=pdfwrite') to improve compression.")

        # Additional sections
        print("\nAdded by Category:")
        for cat, size in sorted(added_categories.items(), key=lambda x: x[1], reverse=True):
            print(f"  {cat}: {format_size(size)}")

        print("\nModified by Category:")
        for cat, size in sorted(modified_categories.items(), key=lambda x: x[1], reverse=True):
            print(f"  {cat}: {format_size(size)}")

        if duplicate_files:
            print("\nDuplicate Files Detected:")
            total_dupe_size = sum(d["size"] * (d["count"] - 1) for d in duplicate_files.values())
            print(f"  Total Redundant Size: {format_size(total_dupe_size)}")
            for file, info in sorted(duplicate_files.items(), key=lambda x: x[1]["size"], reverse=True):
                print(f"  {file} (Size: {format_size(info['size'])} x {info['count']} instances):")
                for path in info["paths"]:
                    print(f"    - {path}")

        print("\nTop 10 Largest Added Files by Architecture:")
        sorted_added = sorted(added_files.items(), key=lambda x: x[1]["size"], reverse=True)[:10]
        for file, data in sorted_added:
            arch = detect_architecture(file)
            print(f"  {format_size(data['size'])} - {file} (Arch: {arch})")

        # Export report if output_dir is provided
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            report = {
                "compressed": {"before": old_compressed, "after": new_compressed},
                "uncompressed": {"before": before_total, "after": after_total},
                "added": {f: d["size"] for f, d in added_files.items()},
                "removed": {f: d["size"] for f, d in removed_files.items()},
                "modified": modified_files,
                "categories": {"added": added_categories, "modified": modified_categories},
                "architectures": {
                    "simulator": simulator_binaries,
                    "arm64": arm64_binaries
                },
                "duplicates": duplicate_files,
                "analysis": {
                    "breakdown_of_increase": dict(added_categories),
                    "simulator_impact": total_sim_size,
                    "arm64_impact": total_arm64_size,
                    "compression": {
                        "before_ratio": before_ratio,
                        "after_ratio": after_ratio,
                        "effective_compression": effective_compression if net_change > 0 else 0
                    }
                }
            }
            report_path = os.path.join(output_dir, "report.json")
            with open(report_path, "w") as f:
                json.dump(report, f, indent=2)
            logging.info(f"Report saved to {report_path}")

    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        raise
    finally:
        shutil.rmtree(old_dir, ignore_errors=True)
        shutil.rmtree(new_dir, ignore_errors=True)

# Enhanced file list extraction for IPA contents
def extract_file_list(ipa_path, output_file):
    try:
        with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
            file_info_list = zip_ref.infolist()
        
        with open(output_file, 'w') as f:
            f.write(f"{'Index':>6}  {'MB':>10}  {'Bytes':>10}  {'Date':>10} {'Time':>5}   {'Name'}\n")
            f.write(f"{'-' * 6}  {'-' * 10}  {'-' * 10}  {'-' * 10} {'-' * 5}   {'-' * 50}\n")
            for index, file_info in enumerate(file_info_list, start=1):
                size = file_info.file_size
                size_mb = format_size_mb(size)
                date = datetime(*file_info.date_time).strftime('%m-%d-%Y')
                time = datetime(*file_info.date_time).strftime('%H:%M')
                file_name = file_info.filename
                f.write(f"{index:>6}  {size_mb:>10}  {size:>10}  {date} {time}   {file_name}\n")
    except Exception as e:
        logging.error(f"Failed to extract file list from {ipa_path}: {str(e)}")
        raise

def format_size_mb(size_in_bytes):
    return f"{size_in_bytes / (1024 * 1024):.2f} MB"

def clean_file(input_file, output_file):
    try:
        with open(input_file, 'r') as f:
            lines = f.readlines()
        
        with open(output_file, 'w') as f:
            for line in lines:
                if re.match(r'^[ ]*[0-9]+[ ]+[0-9]{2}-[0-9]{2}-[0-9]{4}', line):
                    f.write(line)
    except Exception as e:
        logging.error(f"Failed to clean file {input_file}: {str(e)}")
        raise

def process_ipa_files(old_ipa, new_ipa):
    try:
        extract_file_list(old_ipa, "before.txt")
        extract_file_list(new_ipa, "after.txt")
        
        clean_file("before.txt", "before_clean.txt")
        clean_file("after.txt", "after_clean.txt")
    except Exception as e:
        logging.error(f"Error processing IPA files: {str(e)}")
        raise

if __name__ == "__main__":
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: python compare_ipa.py <old_ipa_path> <new_ipa_path> [output_dir]")
        old_ipa = input("Enter path to before IPA: ").strip()
        new_ipa = input("Enter path to after IPA: ").strip()
        output_dir = input("Enter output directory (leave empty for default): ").strip() or None
    else:
        old_ipa = sys.argv[1]
        new_ipa = sys.argv[2]
        output_dir = sys.argv[3] if len(sys.argv) == 4 else None

    # Validate inputs
    if not old_ipa or not new_ipa:
        logging.error("IPA paths cannot be empty.")
        sys.exit(1)

    process_ipa_files(old_ipa, new_ipa)
    analyze_ipa(old_ipa, new_ipa, output_dir)

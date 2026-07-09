import os
import subprocess
import struct
import zlib
import verify_zipcrypto

def create_test_zip(zip_path, files_dict, password):
    print(f"Creating encrypted ZIP archive: {zip_path} using zip CLI...")
    temp_files = []
    for name, content in files_dict.items():
        dir_name = os.path.dirname(name)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name, exist_ok=True)
            temp_files.append(dir_name)
        with open(name, "w") as f:
            f.write(content)
        temp_files.append(name)
    
    file_list = list(files_dict.keys())
    cmd = ["zip", "-P", password, zip_path] + file_list
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
    
    # Clean up files from disk
    for path in sorted(temp_files, key=len, reverse=True):
        if os.path.isdir(path):
            try:
                os.rmdir(path)
            except:
                pass
        else:
            if os.path.exists(path):
                os.remove(path)
    print("ZIP archive created successfully.\n")

def test_file_extraction(zip_path, password, expected_files):
    extracted_files = {}
    print(f"Running sequential decryption test on {zip_path}...")
    
    with open(zip_path, "rb") as f:
        file_count = 0
        while True:
            offset = f.tell()
            sig = f.read(4)
            if not sig or sig == b"\x50\x4B\x01\x02" or sig == b"\x50\x4B\x05\x06":
                print(f"Reached CDFH or EOCD at offset {offset}. Done scanning local files.")
                break
                
            if sig != b"\x50\x4B\x03\x04":
                print(f"FAIL: Unexpected signature {sig} at offset {offset}")
                assert False, f"Unexpected signature {sig}"
                
            header_data = f.read(26)
            version, gp_flag, comp_method, mod_time, mod_date, crc32, comp_size, uncomp_size, name_len, extra_len = struct.unpack(
                "<HHHHHIIIHH", header_data
            )
            
            file_name = f.read(name_len).decode('utf-8')
            extra = f.read(extra_len)
            
            print(f"\n[File {file_count + 1}] Processing: {file_name}")
            print(f"  gp_flag: {gp_flag}, comp_method: {comp_method}")
            print(f"  comp_size: {comp_size}, uncomp_size: {uncomp_size}")
            
            # Read encrypted payload
            encrypted_payload = f.read(comp_size)
            
            # Decrypt
            assert gp_flag & 1, "Test error: Expected files to be encrypted."
            header, decrypted_payload = verify_zipcrypto.decrypt_data(encrypted_payload, password)
            
            # Verify password check byte
            print(f"  Decrypted check byte: {hex(header[11])}")
            if gp_flag & 8:
                expected_check = (mod_time >> 8) & 0xff
            else:
                expected_check = (crc32 >> 24) & 0xff
            print(f"  Expected check byte: {hex(expected_check)}")
            
            assert header[11] == expected_check, f"Password check failed for {file_name}!"
            print("  Password verification: PASSED")
            
            # Decompress
            if comp_method == 8:
                decompressed = zlib.decompress(decrypted_payload, -zlib.MAX_WBITS)
            elif comp_method == 0:
                decompressed = decrypted_payload
            else:
                raise ValueError(f"Unsupported compression method {comp_method}")
                
            content_str = decompressed.decode('utf-8')
            extracted_files[file_name] = content_str
            print(f"  Decompressed Content: '{content_str}'")
            
            # Skip Data Descriptor if present
            if gp_flag & 8:
                dd_sig = f.read(4)
                if dd_sig == b"\x50\x4B\x07\x08":
                    # Signature present, skip remaining 12 bytes of data descriptor
                    f.read(12)
                else:
                    # Signatureless, go back and skip the entire 12-byte descriptor
                    f.seek(-4, 1)
                    f.read(12)
            
            file_count += 1
            
    # Verify contents
    print("\nVerifying extracted file contents...")
    for name, expected_content in expected_files.items():
        assert name in extracted_files, f"Missing file: {name}"
        assert extracted_files[name] == expected_content, f"Content mismatch for {name}"
        print(f"  - {name}: MATCHED")

def run_tests():
    # Test 1: Existing Windows 11 zip file (uses Data Descriptor, single file)
    print("=== TEST 1: Original Windows 11 ZIP ===")
    test_file_extraction(
        "115-D-02190-00046.1.zip",
        "00000046",
        {"test.txt": "Hello Windows 11 ZipCrypto! This is a test file.\n"}
    )
    print("TEST 1 PASSED!\n")
    
    # Test 2: Generated Multi-File ZIP (multi-file)
    print("=== TEST 2: Multi-File ZipCrypto ===")
    zip_path = "115-D-02190-00046.2.zip"
    password = "00000046"
    test_files = {
        "file1.txt": "Hello from file 1! This is some test content.",
        "file2.txt": "Hello from file 2! Testing multiple files in sequence.",
        "nested/file3.txt": "Hello from nested file 3! Inside a subdirectory."
    }
    
    create_test_zip(zip_path, test_files, password)
    try:
        test_file_extraction(zip_path, password, test_files)
        print("TEST 2 PASSED!\n")
    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)
            
    print("===================================================")
    print(" ALL TESTS PASSED SUCCESSFULLY!")
    print(" Sequential parsing and Data Descriptor skipping work.")
    print("===================================================")

if __name__ == "__main__":
    run_tests()

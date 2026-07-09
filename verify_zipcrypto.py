import struct
import zlib

# Standard CRC32 table
crc_table = []
for i in range(256):
    entry = i
    for j in range(8):
        if entry & 1:
            entry = (entry >> 1) ^ 0xedb88320
        else:
            entry = entry >> 1
    crc_table.append(entry)

def crc32_update(crc, b):
    return (crc >> 8) ^ crc_table[(crc ^ b) & 0xff]

# ZipCrypto Keys
keys = [305419896, 591751049, 878082192]

def update_keys(b):
    global keys
    keys[0] = crc32_update(keys[0], b)
    keys[1] = ((keys[1] + (keys[0] & 0xff)) * 134775813 + 1) & 0xffffffff
    keys[2] = crc32_update(keys[2], (keys[1] >> 24) & 0xff)

def decrypt_byte():
    temp = (keys[2] | 2) & 0xffff
    return ((temp * (temp ^ 1)) >> 8) & 0xff

def decrypt_data(data, password):
    global keys
    # Reset keys
    keys = [305419896, 591751049, 878082192]
    
    # Initialize with password
    for c in password.encode('utf-8'):
        update_keys(c)
        
    # Decrypt 12-byte header
    header = bytearray()
    for b in data[:12]:
        pb = b ^ decrypt_byte()
        update_keys(pb)
        header.append(pb)
        
    # Decrypt payload
    payload = bytearray()
    for b in data[12:]:
        pb = b ^ decrypt_byte()
        update_keys(pb)
        payload.append(pb)
        
    return header, payload

# Read zip file sequentially
def main():
    zip_path = "115-D-02190-00046.1.zip"
    password = "000" + "00046"  # "00000046"
    
    with open(zip_path, "rb") as f:
        while True:
            sig = f.read(4)
            if not sig or sig == b"\x50\x4B\x01\x02" or sig == b"\x50\x4B\x05\x06":
                # Reached CDFH or EOCD, or EOF
                break
                
            if sig != b"\x50\x4B\x03\x04":
                print(f"Error: Unknown signature {sig} at offset {f.tell()-4}")
                break
                
            header_data = f.read(26)
            version, gp_flag, comp_method, mod_time, mod_date, crc32, comp_size, uncomp_size, name_len, extra_len = struct.unpack(
                "<HHHHHIIIHH", header_data
            )
            
            file_name = f.read(name_len).decode('utf-8')
            extra = f.read(extra_len)
            
            print(f"\nFile Name: {file_name}")
            print(f"Compressed Size: {comp_size}")
            print(f"Uncompressed Size: {uncomp_size}")
            print(f"GP Flag: {gp_flag}")
            print(f"CRC32: {hex(crc32)}")
            print(f"Is Encrypted: {bool(gp_flag & 1)}")
            
            # Read encrypted payload
            encrypted_payload = f.read(comp_size)
            
            # Decrypt
            if gp_flag & 1:
                header, decrypted_payload = decrypt_data(encrypted_payload, password)
                
                print(f"Decrypted header 12th byte: {hex(header[11])}")
                if gp_flag & 8:
                    expected_check = (mod_time >> 8) & 0xff
                else:
                    expected_check = (crc32 >> 24) & 0xff
                print(f"Expected check byte: {hex(expected_check)}")
                
                if header[11] == expected_check:
                    print("Password check PASSED!")
                else:
                    print("Password check FAILED!")
            else:
                decrypted_payload = encrypted_payload
                print("File is not encrypted.")
                
            # Decompress if compression method is 8 (Deflated) or 0 (Stored)
            if comp_method == 8:
                # For raw deflate, we can use zlib.decompress with wbits = -zlib.MAX_WBITS
                decompressed = zlib.decompress(decrypted_payload, -zlib.MAX_WBITS)
            elif comp_method == 0:
                decompressed = decrypted_payload
            else:
                print(f"Unsupported compression method: {comp_method}")
                return
                
            print(f"Decompressed Output: {decompressed.decode('utf-8')}")
            
            # Skip Data Descriptor if present
            if gp_flag & 8:
                dd_sig = f.read(4)
                if dd_sig == b"\x50\x4B\x07\x08":
                    # Signature present, skip remaining 12 bytes of data descriptor
                    f.read(12)
                else:
                    # Signatureless, we already read 4 bytes (CRC32), skip remaining 8 bytes
                    # Since we read 4 bytes, we need to seek back or adjust
                    f.seek(-4, 1) # Go back 4 bytes
                    f.read(12) # Read the entire 12-byte descriptor (CRC32, CompSize, UncompSize)

if __name__ == "__main__":
    main()

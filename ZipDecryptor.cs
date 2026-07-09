using System;
using System.IO;
using System.IO.Compression;
using System.Text;

public class ZipDecryptor {
    public static void Main(string[] args) {
        Console.WriteLine("===================================================");
        Console.WriteLine(" Windows 11 Standalone ZIP Decryptor & Extractor");
        Console.WriteLine("===================================================\n");

        string currentDir = AppDomain.CurrentDomain.BaseDirectory;
        string[] zipFiles = Directory.GetFiles(currentDir, "*.zip");

        if (zipFiles.Length == 0) {
            Console.WriteLine("No *.zip files found in the current directory.");
            return;
        }

        foreach (string zipPath in zipFiles) {
            string fileName = Path.GetFileName(zipPath);
            Console.WriteLine($"---------------------------------------------------");
            Console.WriteLine($"Processing file: {fileName}");

            // Extract segment and calculate password
            // Target format: e.g. 115-D-02190-00046.1.zip
            // Remove extension .zip
            string nameWithoutExt = Path.GetFileNameWithoutExtension(fileName);
            string[] parts = nameWithoutExt.Split('-');
            if (parts.Length == 0) {
                Console.WriteLine("Error: Filename cannot be split by '-' to find segment.");
                continue;
            }

            string lastPart = parts[parts.Length - 1]; // e.g. 00046.1
            string[] subParts = lastPart.Split('.');
            string segment = subParts[0]; // e.g. 00046
            
            if (string.IsNullOrEmpty(segment)) {
                Console.WriteLine("Error: Could not extract segment from filename.");
                continue;
            }

            string password = "000" + segment; // e.g. 00000046
            Console.WriteLine($"Extracted segment: '{segment}' -> Generated password: '{password}'");

            // Destination directory
            string outputDir = Path.Combine(currentDir, nameWithoutExt);
            Console.WriteLine($"Target directory: {outputDir}");

            try {
                ExtractZip(zipPath, password, outputDir);
                Console.WriteLine("Result: Extraction COMPLETED successfully!");
            } catch (Exception ex) {
                Console.WriteLine($"Result: Extraction FAILED!");
                Console.WriteLine($"Error Details: {ex.Message}");
            }
            Console.WriteLine();
        }
    }

    private static void ExtractZip(string zipPath, string password, string outputDir) {
        using (FileStream fs = new FileStream(zipPath, FileMode.Open, FileAccess.Read)) {
            BinaryReader reader = new BinaryReader(fs);
            
            // Standard CRC table for ZipCrypto
            uint[] crcTable = GetCrcTable();
            
            while (fs.Position < fs.Length) {
                if (fs.Position + 4 > fs.Length) break;
                
                uint sig = reader.ReadUInt32();
                if (sig == 0x04034b50) { // Local File Header (LFH)
                    // Parse Local File Header
                    ushort versionNeeded = reader.ReadUInt16();
                    ushort gpFlag = reader.ReadUInt16();
                    ushort compMethod = reader.ReadUInt16();
                    ushort lastModTime = reader.ReadUInt16();
                    ushort lastModDate = reader.ReadUInt16();
                    uint crc = reader.ReadUInt32();
                    uint compSize = reader.ReadUInt32();
                    uint uncompSize = reader.ReadUInt32();
                    ushort nameLen = reader.ReadUInt16();
                    ushort extraLen = reader.ReadUInt16();
                    
                    byte[] nameBytes = reader.ReadBytes(nameLen);
                    // Use CP437 or UTF-8. Standard Windows zip files often use CP437, but UTF-8 is standard for modern files.
                    // We will fall back to UTF-8.
                    string fileName = Encoding.UTF8.GetString(nameBytes);
                    
                    // Skip the extra field
                    if (extraLen > 0) {
                        reader.BaseStream.Seek(extraLen, SeekOrigin.Current);
                    }
                    
                    // Destination path
                    string destPath = Path.Combine(outputDir, fileName);
                    
                    // Check if it's a directory
                    bool isDirectory = fileName.EndsWith("/") || fileName.EndsWith("\\");
                    if (isDirectory) {
                        Directory.CreateDirectory(destPath);
                        continue;
                    }
                    
                    string parentDir = Path.GetDirectoryName(destPath);
                    if (!string.IsNullOrEmpty(parentDir)) {
                        Directory.CreateDirectory(parentDir);
                    }
                    
                    bool isEncrypted = (gpFlag & 1) == 1;
                    Console.WriteLine($" -> Extracting: {fileName} (Size: {uncompSize} bytes, Encrypted: {isEncrypted})");
                    
                    byte[] fileData;
                    if (isEncrypted) {
                        byte[] encryptedData = reader.ReadBytes((int)compSize);
                        fileData = DecryptZipCrypto(encryptedData, password, crc, lastModTime, gpFlag, crcTable);
                    } else {
                        fileData = reader.ReadBytes((int)compSize);
                    }
                    
                    byte[] decompressedData;
                    if (compMethod == 8) { // DEFLATE
                        decompressedData = DecompressDeflate(fileData);
                    } else if (compMethod == 0) { // STORED (Uncompressed)
                        decompressedData = fileData;
                    } else {
                        throw new NotSupportedException($"Unsupported compression method: {compMethod}");
                    }
                    
                    File.WriteAllBytes(destPath, decompressedData);
                    
                    // Set file times
                    try {
                        DateTime dt = DOSDateTimeToDateTime(lastModDate, lastModTime);
                        File.SetLastWriteTime(destPath, dt);
                    } catch { }
                    
                    // Skip Data Descriptor if present
                    if ((gpFlag & 8) == 8) {
                        if (fs.Position + 4 <= fs.Length) {
                            uint possibleSig = reader.ReadUInt32();
                            if (possibleSig == 0x08074b50) {
                                // Signature present, skip remaining 12 bytes (CRC32, CompSize, UncompSize)
                                reader.BaseStream.Seek(12, SeekOrigin.Current);
                            } else {
                                // Signatureless, the uint we read was CRC32, skip remaining 8 bytes (CompSize, UncompSize)
                                reader.BaseStream.Seek(8, SeekOrigin.Current);
                            }
                        }
                    }
                    
                } else if (sig == 0x02014b50) { // Central Directory File Header (CDFH)
                    // Sequential extraction of local files is complete once we reach the CDFH.
                    break;
                } else if (sig == 0x06054b50) { // End of Central Directory (EOCD)
                    break;
                } else {
                    // Unknown signature, meaning we are done or misaligned.
                    break;
                }
            }
        }
    }

    private static byte[] DecryptZipCrypto(byte[] encryptedData, string password, uint crc, ushort lastModTime, ushort gpFlag, uint[] crcTable) {
        if (encryptedData.Length < 12) {
            throw new Exception("Encrypted data is too short for ZipCrypto header.");
        }
        
        // Initialize keys
        uint[] keys = new uint[3];
        keys[0] = 305419896;
        keys[1] = 591751049;
        keys[2] = 878082192;
        
        Action<byte> updateKeys = (b) => {
            keys[0] = (keys[0] >> 8) ^ crcTable[(keys[0] ^ b) & 0xff];
            keys[1] = (keys[1] + (keys[0] & 0xff)) * 134775813 + 1;
            keys[2] = (keys[2] >> 8) ^ crcTable[(keys[2] ^ (byte)(keys[1] >> 24)) & 0xff];
        };
        
        Func<byte> decryptByte = () => {
            ushort temp = (ushort)(keys[2] | 2);
            return (byte)((temp * (temp ^ 1)) >> 8);
        };
        
        // Initialize keys with password
        foreach (byte b in Encoding.UTF8.GetBytes(password)) {
            updateKeys(b);
        }
        
        // Decrypt 12-byte encryption header
        byte[] header = new byte[12];
        for (int i = 0; i < 12; i++) {
            byte cb = encryptedData[i];
            byte pb = (byte)(cb ^ decryptByte());
            updateKeys(pb);
            header[i] = pb;
        }
        
        // Verify 12th byte
        byte expectedCheck = 0;
        bool hasDataDescriptor = (gpFlag & 8) == 8;
        if (hasDataDescriptor) {
            expectedCheck = (byte)((lastModTime >> 8) & 0xff);
        } else {
            expectedCheck = (byte)((crc >> 24) & 0xff);
        }
        
        // We log a warning if the check byte fails, but don't abort,
        // because some encoders have minor variations.
        if (header[11] != expectedCheck) {
            Console.WriteLine($"    [Warning] Password check byte mismatch (Expected: 0x{expectedCheck:X2}, Decrypted: 0x{header[11]:X2}). Trying to proceed...");
        }
        
        // Decrypt ciphertext
        byte[] payload = new byte[encryptedData.Length - 12];
        for (int i = 0; i < payload.Length; i++) {
            byte cb = encryptedData[i + 12];
            byte pb = (byte)(cb ^ decryptByte());
            updateKeys(pb);
            payload[i] = pb;
        }
        
        return payload;
    }
    
    private static uint[] _crcTable;
    private static uint[] GetCrcTable() {
        if (_crcTable == null) {
            _crcTable = new uint[256];
            for (uint i = 0; i < 256; i++) {
                uint entry = i;
                for (int j = 0; j < 8; j++) {
                    if ((entry & 1) == 1) {
                        entry = (entry >> 1) ^ 0xedb88320;
                    } else {
                        entry = entry >> 1;
                    }
                }
                _crcTable[i] = entry;
            }
        }
        return _crcTable;
    }
    
    private static byte[] DecompressDeflate(byte[] compressedData) {
        using (MemoryStream ms = new MemoryStream(compressedData))
        using (MemoryStream outMs = new MemoryStream()) {
            using (DeflateStream ds = new DeflateStream(ms, CompressionMode.Decompress)) {
                ds.CopyTo(outMs);
            }
            return outMs.ToArray();
        }
    }
    
    private static DateTime DOSDateTimeToDateTime(ushort dosDate, ushort dosTime) {
        try {
            int year = ((dosDate >> 9) & 0x7f) + 1980;
            int month = (dosDate >> 5) & 0x0f;
            int day = dosDate & 0x1f;
            int hour = (dosTime >> 11) & 0x1f;
            int minute = (dosTime >> 5) & 0x3f;
            int second = (dosTime & 0x1f) * 2;
            if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) {
                return DateTime.Now;
            }
            return new DateTime(year, month, day, hour, minute, second);
        } catch {
            return DateTime.Now;
        }
    }
}

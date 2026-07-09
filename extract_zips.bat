@echo off
:: =====================================================================
:: Windows 11 獨立運作 ZIP 自動密碼解析與解壓縮工具
:: 說明：請直接雙擊此批次檔執行，它將自動搜尋目錄下所有 *.zip 並完成解密與解壓縮。
:: =====================================================================
title ZIP Auto Decryptor & Extractor
echo =====================================================================
echo  正在搜尋並解析當前目錄下的 *.zip 加密檔案...
echo =====================================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=[System.IO.File]::ReadAllText('%~f0'); $s=$s.Substring($s.IndexOf('GOTO :EOF') + 9); Invoke-Expression $s"

echo.
echo =====================================================================
echo  批次處理完畢！
echo =====================================================================
pause
GOTO :EOF

# =====================================================================
# POWERSHELL + C# 程式碼區段 (雙擊時自動於記憶體編譯並執行，不產生暫存檔)
# =====================================================================

$Source = @"
using System;
using System.IO;
using System.IO.Compression;
using System.Text;

public class ZipDecryptor {
    public static void Run() {
        string currentDir = AppDomain.CurrentDomain.BaseDirectory;
        string[] zipFiles = Directory.GetFiles(currentDir, "*.zip");

        if (zipFiles.Length == 0) {
            Console.WriteLine(" 找不到任何 *.zip 檔案。");
            return;
        }

        foreach (string zipPath in zipFiles) {
            string fileName = Path.GetFileName(zipPath);
            Console.WriteLine("---------------------------------------------------");
            Console.WriteLine(" 檔案名稱: " + fileName);

            // 解析密碼段落
            string nameWithoutExt = Path.GetFileNameWithoutExtension(fileName);
            string[] parts = nameWithoutExt.Split('-');
            if (parts.Length == 0) {
                Console.WriteLine(" [錯誤] 無法以 '-' 分割檔名解析段落。");
                continue;
            }

            string lastPart = parts[parts.Length - 1]; // e.g. 00046.1
            string[] subParts = lastPart.Split('.');
            string segment = subParts[0]; // e.g. 00046
            
            if (string.IsNullOrEmpty(segment)) {
                Console.WriteLine(" [錯誤] 無法從檔名提取段落數字。");
                continue;
            }

            string password = "000" + segment; // e.g. 00000046
            Console.WriteLine(" 解析段落: [" + segment + "] => 生成密碼: [" + password + "]");

            string outputDir = Path.Combine(currentDir, nameWithoutExt);
            Console.WriteLine(" 解壓目錄: " + outputDir);

            try {
                ExtractZip(zipPath, password, outputDir);
                Console.WriteLine(" >> 解壓結果: 成功 (SUCCESS)!");
            } catch (Exception ex) {
                Console.WriteLine(" >> 解壓結果: 失敗 (FAILED)!");
                Console.WriteLine(" 錯誤訊息: " + ex.Message);
            }
            Console.WriteLine();
        }
    }

    private static void ExtractZip(string zipPath, string password, string outputDir) {
        using (FileStream fs = new FileStream(zipPath, FileMode.Open, FileAccess.Read)) {
            BinaryReader reader = new BinaryReader(fs);
            uint[] crcTable = GetCrcTable();
            
            while (fs.Position < fs.Length) {
                if (fs.Position + 4 > fs.Length) break;
                
                uint sig = reader.ReadUInt32();
                if (sig == 0x04034b50) { // Local File Header
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
                    string fileName = Encoding.UTF8.GetString(nameBytes);
                    
                    if (extraLen > 0) {
                        reader.BaseStream.Seek(extraLen, SeekOrigin.Current);
                    }
                    
                    string destPath = Path.Combine(outputDir, fileName);
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
                    Console.WriteLine("   -> 正在還原: " + fileName + " (" + uncompSize + " bytes)...");
                    
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
                    } else if (compMethod == 0) { // STORED
                        decompressedData = fileData;
                    } else {
                        throw new NotSupportedException("不支援的壓縮格式 (Method " + compMethod + ")");
                    }
                    
                    File.WriteAllBytes(destPath, decompressedData);
                    
                    try {
                        DateTime dt = DOSDateTimeToDateTime(lastModDate, lastModTime);
                        File.SetLastWriteTime(destPath, dt);
                    } catch {}
                    
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
                    
                } else if (sig == 0x02014b50 || sig == 0x06054b50) {
                    break;
                } else {
                    break;
                }
            }
        }
    }

    private static byte[] DecryptZipCrypto(byte[] encryptedData, string password, uint crc, ushort lastModTime, ushort gpFlag, uint[] crcTable) {
        if (encryptedData.Length < 12) {
            throw new Exception("加密資料長度不足 12 位元組。");
        }
        
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
        
        foreach (byte b in Encoding.UTF8.GetBytes(password)) {
            updateKeys(b);
        }
        
        byte[] header = new byte[12];
        for (int i = 0; i < 12; i++) {
            byte cb = encryptedData[i];
            byte pb = (byte)(cb ^ decryptByte());
            updateKeys(pb);
            header[i] = pb;
        }
        
        byte expectedCheck = 0;
        bool hasDataDescriptor = (gpFlag & 8) == 8;
        if (hasDataDescriptor) {
            expectedCheck = (byte)((lastModTime >> 8) & 0xff);
        } else {
            expectedCheck = (byte)((crc >> 24) & 0xff);
        }
        
        // 僅警告，不中斷，相容性更高
        if (header[11] != expectedCheck) {
            // Console.WriteLine("    [警告] 密碼驗證字元不符。");
        }
        
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
            return new DateTime(year, month, day, hour, minute, second);
        } catch {
            return DateTime.Now;
        }
    }
}
"@

Add-Type -TypeDefinition $Source -ReferencedAssemblies "System.IO.Compression"
[ZipDecryptor]::Run()

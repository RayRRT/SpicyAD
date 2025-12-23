using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Security.Principal;

namespace SpicyAD.BloodHound
{
    /// <summary>
    /// Collects session information from computers using NetSessionEnum and NetWkstaUserEnum
    /// </summary>
    public class SessionCollector
    {
        private readonly List<BloodHoundComputer> _computers;
        private readonly int _threads;
        private readonly string _domainSid;
        private readonly string _domainName;
        private readonly Dictionary<string, string> _sidCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private int _successCount;
        private int _failCount;

        #region P/Invoke Definitions

        [DllImport("netapi32.dll", SetLastError = true)]
        private static extern int NetSessionEnum(
            [MarshalAs(UnmanagedType.LPWStr)] string serverName,
            [MarshalAs(UnmanagedType.LPWStr)] string uncClientName,
            [MarshalAs(UnmanagedType.LPWStr)] string userName,
            int level,
            out IntPtr bufPtr,
            int prefMaxLen,
            out int entriesRead,
            out int totalEntries,
            ref int resumeHandle);

        [DllImport("netapi32.dll", SetLastError = true)]
        private static extern int NetWkstaUserEnum(
            [MarshalAs(UnmanagedType.LPWStr)] string serverName,
            int level,
            out IntPtr bufPtr,
            int prefMaxLen,
            out int entriesRead,
            out int totalEntries,
            ref int resumeHandle);

        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SESSION_INFO_10
        {
            public string sesi10_cname;
            public string sesi10_username;
            public uint sesi10_time;
            public uint sesi10_idle_time;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WKSTA_USER_INFO_1
        {
            public string wkui1_username;
            public string wkui1_logon_domain;
            public string wkui1_oth_domains;
            public string wkui1_logon_server;
        }

        private const int MAX_PREFERRED_LENGTH = -1;
        private const int NERR_Success = 0;
        private const int ERROR_MORE_DATA = 234;
        private const int ERROR_ACCESS_DENIED = 5;

        #endregion

        public SessionCollector(List<BloodHoundComputer> computers, int threads, string domainSid, string domainName)
        {
            _computers = computers;
            _threads = Math.Max(1, Math.Min(threads, 50)); // Cap at 50 threads
            _domainSid = domainSid;
            _domainName = domainName?.ToUpper();
        }

        /// <summary>
        /// Collect sessions from all computers
        /// </summary>
        public void CollectSessions()
        {
            Console.WriteLine($"[*] Enumerating sessions on {_computers.Count} computers ({_threads} threads)...");

            var options = new ParallelOptions { MaxDegreeOfParallelism = _threads };

            Parallel.ForEach(_computers, options, computer =>
            {
                try
                {
                    CollectComputerSessions(computer);
                }
                catch (Exception ex)
                {
                    OutputHelper.Verbose($"[!] Error on {computer.Properties.Name}: {ex.Message}");
                    Interlocked.Increment(ref _failCount);
                }
            });

            Console.WriteLine($"    [+] Sessions collected from {_successCount} computers ({_failCount} failed)");
        }

        /// <summary>
        /// Collect sessions from a single computer
        /// </summary>
        private void CollectComputerSessions(BloodHoundComputer computer)
        {
            string hostname = computer.Properties.Name?.Split('.')[0];
            if (string.IsNullOrEmpty(hostname))
                return;

            // Skip if computer is not reachable (quick port check)
            if (!IsPortOpen(hostname, 445, 500))
            {
                computer.Sessions.Collected = false;
                computer.Sessions.FailureReason = "Port 445 not reachable";
                return;
            }

            // Try NetSessionEnum first (network sessions)
            var sessions = GetNetSessions(hostname);

            if (sessions != null)
            {
                computer.Sessions.Results = sessions;
                computer.Sessions.Collected = true;
                Interlocked.Increment(ref _successCount);
            }
            else
            {
                computer.Sessions.Collected = false;
                computer.Sessions.FailureReason = "Access denied or RPC error";
            }

            // Try NetWkstaUserEnum for privileged sessions (requires admin)
            var privilegedSessions = GetWkstaSessions(hostname);
            if (privilegedSessions != null)
            {
                computer.PrivilegedSessions.Results = privilegedSessions;
                computer.PrivilegedSessions.Collected = true;
            }
        }

        /// <summary>
        /// Get network sessions using NetSessionEnum
        /// </summary>
        private List<SessionInfo> GetNetSessions(string hostname)
        {
            var sessions = new List<SessionInfo>();
            IntPtr bufPtr = IntPtr.Zero;
            int resumeHandle = 0;

            try
            {
                int result = NetSessionEnum(
                    $"\\\\{hostname}",
                    null,
                    null,
                    10, // SESSION_INFO_10
                    out bufPtr,
                    MAX_PREFERRED_LENGTH,
                    out int entriesRead,
                    out int totalEntries,
                    ref resumeHandle);

                if (result != NERR_Success && result != ERROR_MORE_DATA)
                {
                    return null;
                }

                IntPtr iter = bufPtr;
                int structSize = Marshal.SizeOf(typeof(SESSION_INFO_10));

                for (int i = 0; i < entriesRead; i++)
                {
                    var sessionInfo = Marshal.PtrToStructure<SESSION_INFO_10>(iter);
                    iter = IntPtr.Add(iter, structSize);

                    if (!string.IsNullOrEmpty(sessionInfo.sesi10_username))
                    {
                        // Skip computer accounts and anonymous
                        if (sessionInfo.sesi10_username.EndsWith("$") ||
                            sessionInfo.sesi10_username.Equals("ANONYMOUS LOGON", StringComparison.OrdinalIgnoreCase))
                            continue;

                        string userSid = ResolveUserToSid(sessionInfo.sesi10_username);
                        if (!string.IsNullOrEmpty(userSid))
                        {
                            sessions.Add(new SessionInfo
                            {
                                UserSID = userSid,
                                ComputerSID = hostname
                            });
                        }
                    }
                }

                return sessions;
            }
            catch
            {
                return null;
            }
            finally
            {
                if (bufPtr != IntPtr.Zero)
                    NetApiBufferFree(bufPtr);
            }
        }

        /// <summary>
        /// Get logged on users using NetWkstaUserEnum (requires admin)
        /// </summary>
        private List<SessionInfo> GetWkstaSessions(string hostname)
        {
            var sessions = new List<SessionInfo>();
            IntPtr bufPtr = IntPtr.Zero;
            int resumeHandle = 0;

            try
            {
                int result = NetWkstaUserEnum(
                    $"\\\\{hostname}",
                    1, // WKSTA_USER_INFO_1
                    out bufPtr,
                    MAX_PREFERRED_LENGTH,
                    out int entriesRead,
                    out int totalEntries,
                    ref resumeHandle);

                if (result != NERR_Success && result != ERROR_MORE_DATA)
                {
                    return null;
                }

                IntPtr iter = bufPtr;
                int structSize = Marshal.SizeOf(typeof(WKSTA_USER_INFO_1));

                for (int i = 0; i < entriesRead; i++)
                {
                    var wkstaInfo = Marshal.PtrToStructure<WKSTA_USER_INFO_1>(iter);
                    iter = IntPtr.Add(iter, structSize);

                    if (!string.IsNullOrEmpty(wkstaInfo.wkui1_username))
                    {
                        // Skip computer accounts
                        if (wkstaInfo.wkui1_username.EndsWith("$"))
                            continue;

                        string userSid = ResolveUserToSid(wkstaInfo.wkui1_username, wkstaInfo.wkui1_logon_domain);
                        if (!string.IsNullOrEmpty(userSid))
                        {
                            sessions.Add(new SessionInfo
                            {
                                UserSID = userSid,
                                ComputerSID = hostname
                            });
                        }
                    }
                }

                return sessions;
            }
            catch
            {
                return null;
            }
            finally
            {
                if (bufPtr != IntPtr.Zero)
                    NetApiBufferFree(bufPtr);
            }
        }

        /// <summary>
        /// Resolve username to SID
        /// </summary>
        private string ResolveUserToSid(string username, string domain = null)
        {
            if (string.IsNullOrEmpty(username))
                return null;

            // Build full name
            string fullName = !string.IsNullOrEmpty(domain) ? $"{domain}\\{username}" : username;

            // Check cache
            if (_sidCache.TryGetValue(fullName, out string cachedSid))
                return cachedSid;

            try
            {
                var account = new NTAccount(fullName);
                var sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
                string sidString = sid.ToString();

                // Cache it
                _sidCache[fullName] = sidString;
                return sidString;
            }
            catch
            {
                // Try with domain prefix if not present
                if (!fullName.Contains("\\") && !string.IsNullOrEmpty(_domainName))
                {
                    try
                    {
                        var account = new NTAccount(_domainName, username);
                        var sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
                        string sidString = sid.ToString();

                        _sidCache[fullName] = sidString;
                        return sidString;
                    }
                    catch
                    {
                        return null;
                    }
                }
                return null;
            }
        }

        /// <summary>
        /// Quick check if port is open
        /// </summary>
        private bool IsPortOpen(string hostname, int port, int timeoutMs)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var result = client.BeginConnect(hostname, port, null, null);
                    bool success = result.AsyncWaitHandle.WaitOne(timeoutMs);
                    if (success)
                    {
                        client.EndConnect(result);
                        return true;
                    }
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }
    }
}

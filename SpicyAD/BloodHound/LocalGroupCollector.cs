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
    /// Collects local group membership from computers using NetLocalGroupGetMembers
    /// </summary>
    public class LocalGroupCollector
    {
        private readonly List<BloodHoundComputer> _computers;
        private readonly int _threads;
        private readonly string _domainSid;
        private readonly string _domainName;
        private readonly Dictionary<string, PrincipalType> _sidTypeCache = new Dictionary<string, PrincipalType>();
        private int _successCount;
        private int _failCount;

        // Group names to enumerate
        private static readonly string[] TargetGroups = new[]
        {
            "Administrators",
            "Remote Desktop Users",
            "Distributed COM Users",
            "Remote Management Users"
        };

        #region P/Invoke Definitions

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int NetLocalGroupGetMembers(
            string servername,
            string localgroupname,
            int level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref IntPtr resumehandle);

        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);

        // LOCALGROUP_MEMBERS_INFO_2 structure
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct LOCALGROUP_MEMBERS_INFO_2
        {
            public IntPtr lgrmi2_sid;
            public int lgrmi2_sidusage;
            public string lgrmi2_domainandname;
        }

        // SID_NAME_USE enum
        private enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup = 2,
            SidTypeDomain = 3,
            SidTypeAlias = 4,
            SidTypeWellKnownGroup = 5,
            SidTypeDeletedAccount = 6,
            SidTypeInvalid = 7,
            SidTypeUnknown = 8,
            SidTypeComputer = 9
        }

        private const int MAX_PREFERRED_LENGTH = -1;
        private const int NERR_Success = 0;
        private const int ERROR_MORE_DATA = 234;
        private const int ERROR_ACCESS_DENIED = 5;
        private const int ERROR_BAD_NETPATH = 53;
        private const int ERROR_NETWORK_UNREACHABLE = 1231;
        private const int RPC_S_SERVER_UNAVAILABLE = 1722;

        #endregion

        public LocalGroupCollector(List<BloodHoundComputer> computers, int threads, string domainSid, string domainName)
        {
            _computers = computers;
            _threads = Math.Max(1, Math.Min(threads, 50));
            _domainSid = domainSid;
            _domainName = domainName?.ToUpper();
        }

        /// <summary>
        /// Collect local group membership from all computers
        /// </summary>
        public void CollectLocalGroups()
        {
            Console.WriteLine($"[*] Enumerating local groups on {_computers.Count} computers ({_threads} threads)...");

            var options = new ParallelOptions { MaxDegreeOfParallelism = _threads };

            Parallel.ForEach(_computers, options, computer =>
            {
                try
                {
                    CollectComputerLocalGroups(computer);
                }
                catch (Exception ex)
                {
                    OutputHelper.Verbose($"[!] Error on {computer.Properties.Name}: {ex.Message}");
                    Interlocked.Increment(ref _failCount);
                }
            });

            Console.WriteLine($"    [+] Local groups collected from {_successCount} computers ({_failCount} failed)");
        }

        /// <summary>
        /// Collect local groups from a single computer
        /// </summary>
        private void CollectComputerLocalGroups(BloodHoundComputer computer)
        {
            string hostname = GetHostname(computer);
            if (string.IsNullOrEmpty(hostname))
                return;

            // Quick port check
            if (!IsPortOpen(hostname, 445, 500))
            {
                SetCollectionFailed(computer, "Port 445 not reachable");
                return;
            }

            bool anySuccess = false;

            // Enumerate Administrators
            var admins = GetLocalGroupMembers(hostname, "Administrators");
            if (admins != null)
            {
                computer.LocalAdmins.Results = admins;
                computer.LocalAdmins.Collected = true;
                anySuccess = true;
            }
            else
            {
                computer.LocalAdmins.Collected = false;
                computer.LocalAdmins.FailureReason = "Access denied or RPC error";
            }

            // Enumerate Remote Desktop Users
            var rdpUsers = GetLocalGroupMembers(hostname, "Remote Desktop Users");
            if (rdpUsers != null)
            {
                computer.RemoteDesktopUsers.Results = rdpUsers;
                computer.RemoteDesktopUsers.Collected = true;
                anySuccess = true;
            }
            else
            {
                computer.RemoteDesktopUsers.Collected = false;
                computer.RemoteDesktopUsers.FailureReason = "Access denied or RPC error";
            }

            // Enumerate DCOM Users
            var dcomUsers = GetLocalGroupMembers(hostname, "Distributed COM Users");
            if (dcomUsers != null)
            {
                computer.DcomUsers.Results = dcomUsers;
                computer.DcomUsers.Collected = true;
                anySuccess = true;
            }
            else
            {
                computer.DcomUsers.Collected = false;
                computer.DcomUsers.FailureReason = "Access denied or RPC error";
            }

            // Enumerate Remote Management Users (PSRemote)
            var psRemoteUsers = GetLocalGroupMembers(hostname, "Remote Management Users");
            if (psRemoteUsers != null)
            {
                computer.PSRemoteUsers.Results = psRemoteUsers;
                computer.PSRemoteUsers.Collected = true;
                anySuccess = true;
            }
            else
            {
                computer.PSRemoteUsers.Collected = false;
                computer.PSRemoteUsers.FailureReason = "Access denied or RPC error";
            }

            if (anySuccess)
            {
                Interlocked.Increment(ref _successCount);
            }
            else
            {
                Interlocked.Increment(ref _failCount);
            }
        }

        /// <summary>
        /// Get members of a local group using NetLocalGroupGetMembers
        /// </summary>
        private List<LocalGroupMember> GetLocalGroupMembers(string hostname, string groupName)
        {
            var members = new List<LocalGroupMember>();
            IntPtr bufPtr = IntPtr.Zero;
            IntPtr resumeHandle = IntPtr.Zero;

            try
            {
                int result = NetLocalGroupGetMembers(
                    $"\\\\{hostname}",
                    groupName,
                    2, // LOCALGROUP_MEMBERS_INFO_2
                    out bufPtr,
                    MAX_PREFERRED_LENGTH,
                    out int entriesRead,
                    out int totalEntries,
                    ref resumeHandle);

                // Handle common errors
                if (result == ERROR_ACCESS_DENIED)
                {
                    OutputHelper.Verbose($"    Access denied to {groupName} on {hostname}");
                    return null;
                }

                if (result != NERR_Success && result != ERROR_MORE_DATA)
                {
                    OutputHelper.Verbose($"    Error {result} enumerating {groupName} on {hostname}");
                    return null;
                }

                if (entriesRead == 0)
                {
                    return members; // Empty group is valid
                }

                IntPtr iter = bufPtr;
                int structSize = Marshal.SizeOf(typeof(LOCALGROUP_MEMBERS_INFO_2));

                for (int i = 0; i < entriesRead; i++)
                {
                    var memberInfo = Marshal.PtrToStructure<LOCALGROUP_MEMBERS_INFO_2>(iter);
                    iter = IntPtr.Add(iter, structSize);

                    // Get SID string
                    string sidString = null;
                    if (memberInfo.lgrmi2_sid != IntPtr.Zero)
                    {
                        try
                        {
                            var sid = new SecurityIdentifier(memberInfo.lgrmi2_sid);
                            sidString = sid.ToString();
                        }
                        catch
                        {
                            continue;
                        }
                    }

                    if (string.IsNullOrEmpty(sidString))
                        continue;

                    // Skip local accounts (not domain accounts)
                    if (!sidString.StartsWith("S-1-5-21-") && !sidString.StartsWith("S-1-5-32-"))
                        continue;

                    // Determine type from SID_NAME_USE
                    PrincipalType memberType = GetPrincipalTypeFromSidUsage(
                        (SID_NAME_USE)memberInfo.lgrmi2_sidusage,
                        sidString,
                        memberInfo.lgrmi2_domainandname);

                    members.Add(new LocalGroupMember
                    {
                        ObjectIdentifier = sidString,
                        ObjectType = memberType.ToString()
                    });
                }

                return members;
            }
            catch (Exception ex)
            {
                OutputHelper.Verbose($"    Exception enumerating {groupName} on {hostname}: {ex.Message}");
                return null;
            }
            finally
            {
                if (bufPtr != IntPtr.Zero)
                    NetApiBufferFree(bufPtr);
            }
        }

        /// <summary>
        /// Determine principal type from SID_NAME_USE
        /// </summary>
        private PrincipalType GetPrincipalTypeFromSidUsage(SID_NAME_USE sidUsage, string sid, string domainAndName)
        {
            // Check cache first
            if (_sidTypeCache.TryGetValue(sid, out PrincipalType cachedType))
                return cachedType;

            PrincipalType result;

            switch (sidUsage)
            {
                case SID_NAME_USE.SidTypeUser:
                    result = PrincipalType.User;
                    break;

                case SID_NAME_USE.SidTypeGroup:
                case SID_NAME_USE.SidTypeAlias:
                case SID_NAME_USE.SidTypeWellKnownGroup:
                    result = PrincipalType.Group;
                    break;

                case SID_NAME_USE.SidTypeComputer:
                    result = PrincipalType.Computer;
                    break;

                default:
                    // Try to determine from name (ends with $)
                    if (!string.IsNullOrEmpty(domainAndName) && domainAndName.TrimEnd().EndsWith("$"))
                        result = PrincipalType.Computer;
                    else
                        result = DetermineTypeFromSid(sid);
                    break;
            }

            // Cache it
            _sidTypeCache[sid] = result;
            return result;
        }

        /// <summary>
        /// Determine type from SID RID
        /// </summary>
        private PrincipalType DetermineTypeFromSid(string sid)
        {
            // Built-in groups (S-1-5-32-XXX)
            if (sid.StartsWith("S-1-5-32-"))
                return PrincipalType.Group;

            // Domain SIDs - check RID
            if (sid.StartsWith("S-1-5-21-"))
            {
                string[] parts = sid.Split('-');
                if (parts.Length >= 8)
                {
                    if (int.TryParse(parts[parts.Length - 1], out int rid))
                    {
                        // Well-known group RIDs
                        if (rid == 512 || rid == 513 || rid == 514 || rid == 515 ||
                            rid == 516 || rid == 517 || rid == 518 || rid == 519 ||
                            rid == 520 || rid == 521 || rid == 522 || rid == 525 ||
                            rid == 526 || rid == 527 || rid == 553)
                        {
                            return PrincipalType.Group;
                        }

                        // Well-known user RIDs
                        if (rid == 500 || rid == 501 || rid == 502 || rid == 503)
                        {
                            return PrincipalType.User;
                        }
                    }
                }
            }

            // Default to User for unknown
            return PrincipalType.User;
        }

        /// <summary>
        /// Get hostname from computer object
        /// </summary>
        private string GetHostname(BloodHoundComputer computer)
        {
            // Try DNS name first
            string name = computer.Properties.Name;
            if (!string.IsNullOrEmpty(name))
            {
                // Remove domain suffix if present
                int dotIndex = name.IndexOf('.');
                if (dotIndex > 0)
                    return name.Substring(0, dotIndex);
                return name;
            }

            // Fallback to SAM account name
            string sam = computer.Properties.SamAccountName;
            if (!string.IsNullOrEmpty(sam))
                return sam.TrimEnd('$');

            return null;
        }

        /// <summary>
        /// Set all collections as failed
        /// </summary>
        private void SetCollectionFailed(BloodHoundComputer computer, string reason)
        {
            computer.LocalAdmins.Collected = false;
            computer.LocalAdmins.FailureReason = reason;

            computer.RemoteDesktopUsers.Collected = false;
            computer.RemoteDesktopUsers.FailureReason = reason;

            computer.DcomUsers.Collected = false;
            computer.DcomUsers.FailureReason = reason;

            computer.PSRemoteUsers.Collected = false;
            computer.PSRemoteUsers.FailureReason = reason;

            Interlocked.Increment(ref _failCount);
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

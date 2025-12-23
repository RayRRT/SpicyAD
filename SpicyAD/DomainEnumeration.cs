using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.AccountManagement;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.ComponentModel;

namespace SpicyAD
{
    public static class DomainEnumeration
    {
        public static void GetDomainInfo()
        {
            Console.WriteLine("[*] Enumerating Domain Information...\n");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(objectClass=domain)";
                searcher.PropertiesToLoad.Add("distinguishedName");
                searcher.PropertiesToLoad.Add("whenCreated");
                searcher.PropertiesToLoad.Add("ms-DS-MachineAccountQuota");
                searcher.PropertiesToLoad.Add("msDS-Behavior-Version");
                searcher.PropertiesToLoad.Add("name");

                SearchResult result = searcher.FindOne();
                if (result != null)
                {
                    Console.WriteLine($"[+] Domain Name: {AuthContext.DomainName}");

                    if (result.Properties.Contains("distinguishedName"))
                        OutputHelper.Verbose($"[+] Distinguished Name: {result.Properties["distinguishedName"][0]}");

                    if (result.Properties.Contains("whenCreated"))
                        OutputHelper.Verbose($"[+] Created: {result.Properties["whenCreated"][0]}");

                    if (result.Properties.Contains("msDS-Behavior-Version"))
                    {
                        int funcLevel = (int)result.Properties["msDS-Behavior-Version"][0];
                        string levelName = GetFunctionalLevelName(funcLevel);
                        OutputHelper.Verbose($"[+] Domain Functional Level: {levelName}");
                    }

                    if (result.Properties.Contains("ms-DS-MachineAccountQuota"))
                    {
                        Console.WriteLine($"[+] Machine Account Quota: {result.Properties["ms-DS-MachineAccountQuota"][0]}");
                    }
                }

                // Get forest info from RootDSE
                try
                {
                    DirectoryEntry rootDse = AuthContext.GetRootDSE();
                    if (rootDse.Properties.Contains("rootDomainNamingContext"))
                    {
                        string forestDN = rootDse.Properties["rootDomainNamingContext"][0].ToString();
                        OutputHelper.Verbose($"[+] Forest Root: {ConvertDNToDomain(forestDN)}");
                    }
                }
                catch { }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        private static string GetFunctionalLevelName(int level)
        {
            switch (level)
            {
                case 0: return "Windows 2000";
                case 1: return "Windows Server 2003 Interim";
                case 2: return "Windows Server 2003";
                case 3: return "Windows Server 2008";
                case 4: return "Windows Server 2008 R2";
                case 5: return "Windows Server 2012";
                case 6: return "Windows Server 2012 R2";
                case 7: return "Windows Server 2016";
                default: return $"Unknown ({level})";
            }
        }

        private static string ConvertDNToDomain(string dn)
        {
            if (string.IsNullOrEmpty(dn)) return null;
            var parts = dn.Split(',')
                .Where(p => p.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                .Select(p => p.Substring(3));
            return string.Join(".", parts);
        }

        
        /// Get DC hostname from LDAP or use DC IP as fallback
        
        private static string GetDCHostname()
        {
            // If DC IP is specified and we're not domain-joined, use IP directly for SMB
            // This is more reliable when DNS resolution might not work
            if (!string.IsNullOrEmpty(AuthContext.DcIp) && !AuthContext.IsDomainJoined)
            {
                return AuthContext.DcIp;
            }

            // If DC IP is specified but we're domain-joined, try to get hostname via LDAP
            if (!string.IsNullOrEmpty(AuthContext.DcIp))
            {
                try
                {
                    DirectoryEntry de = AuthContext.GetDirectoryEntry();
                    DirectorySearcher searcher = new DirectorySearcher(de);
                    searcher.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";
                    searcher.PropertiesToLoad.Add("dNSHostName");

                    SearchResult result = searcher.FindOne();
                    if (result != null && result.Properties.Contains("dNSHostName"))
                    {
                        return result.Properties["dNSHostName"][0].ToString();
                    }
                }
                catch { }

                // Fallback to DC IP
                return AuthContext.DcIp;
            }

            // Try domain name
            return AuthContext.DomainName;
        }

        public static void EnumerateDomainControllers()
        {
            Console.WriteLine("[*] Enumerating Domain Controllers...\n");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";
                searcher.PropertiesToLoad.Add("name");
                searcher.PropertiesToLoad.Add("dNSHostName");
                searcher.PropertiesToLoad.Add("operatingSystem");
                searcher.PropertiesToLoad.Add("operatingSystemVersion");

                SearchResultCollection results = searcher.FindAll();
                Console.WriteLine($"[+] Found {results.Count} Domain Controller(s):\n");

                foreach (SearchResult result in results)
                {
                    string name = result.Properties.Contains("name") ? result.Properties["name"][0].ToString() : "Unknown";
                    string dnsName = result.Properties.Contains("dNSHostName") ? result.Properties["dNSHostName"][0].ToString() : "";
                    string os = result.Properties.Contains("operatingSystem") ? result.Properties["operatingSystem"][0].ToString() : "";
                    string osVer = result.Properties.Contains("operatingSystemVersion") ? result.Properties["operatingSystemVersion"][0].ToString() : "";

                    // Try to resolve IP
                    string ip = "";
                    try
                    {
                        if (!string.IsNullOrEmpty(dnsName))
                        {
                            // Use DC as DNS server if specified
                            if (!string.IsNullOrEmpty(AuthContext.DnsServer))
                            {
                                ip = ResolveDnsWithServer(dnsName, AuthContext.DnsServer);
                            }
                            else
                            {
                                var addresses = Dns.GetHostAddresses(dnsName);
                                if (addresses.Length > 0)
                                    ip = addresses[0].ToString();
                            }
                        }
                    }
                    catch { }

                    Console.WriteLine($"    [DC] Name: {name}");
                    if (!string.IsNullOrEmpty(dnsName))
                        Console.WriteLine($"         DNS: {dnsName}");
                    if (!string.IsNullOrEmpty(ip))
                        Console.WriteLine($"         IP: {ip}");
                    if (!string.IsNullOrEmpty(os))
                        OutputHelper.Verbose($"         OS: {os} {osVer}");
                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        private static string ResolveDnsWithServer(string hostname, string dnsServer)
        {
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "nslookup",
                    Arguments = $"{hostname} {dnsServer}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var process = System.Diagnostics.Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit(3000);

                    var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    bool foundName = false;
                    foreach (var line in lines)
                    {
                        if (line.Contains(hostname))
                            foundName = true;
                        if (foundName && line.StartsWith("Address:"))
                        {
                            string ip = line.Replace("Address:", "").Trim();
                            if (!ip.Contains(":"))
                                return ip;
                        }
                    }
                }
            }
            catch { }
            return "";
        }

        public static void EnumerateDomainTrusts()
        {
            Console.WriteLine("[*] Enumerating Domain Trusts...\n");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);

                // Search for trustedDomain objects
                searcher.Filter = "(objectClass=trustedDomain)";
                searcher.PropertiesToLoad.Add("name");
                searcher.PropertiesToLoad.Add("trustDirection");
                searcher.PropertiesToLoad.Add("trustType");
                searcher.PropertiesToLoad.Add("trustAttributes");
                searcher.PropertiesToLoad.Add("flatName");
                searcher.PageSize = 1000;

                SearchResultCollection results = searcher.FindAll();

                if (results.Count == 0)
                {
                    Console.WriteLine("[*] No domain trusts found.");
                    return;
                }

                Console.WriteLine($"[+] Found {results.Count} Trust(s):\n");

                foreach (SearchResult result in results)
                {
                    string targetName = result.Properties.Contains("name") ?
                        result.Properties["name"][0].ToString() : "Unknown";
                    string flatName = result.Properties.Contains("flatName") ?
                        result.Properties["flatName"][0].ToString() : "";

                    // Trust direction: 0=Disabled, 1=Inbound, 2=Outbound, 3=Bidirectional
                    string direction = "Unknown";
                    if (result.Properties.Contains("trustDirection"))
                    {
                        int dir = (int)result.Properties["trustDirection"][0];
                        direction = dir switch
                        {
                            0 => "Disabled",
                            1 => "Inbound",
                            2 => "Outbound",
                            3 => "Bidirectional",
                            _ => $"Unknown ({dir})"
                        };
                    }

                    // Trust type: 1=Downlevel, 2=Uplevel, 3=MIT, 4=DCE
                    string trustType = "Unknown";
                    if (result.Properties.Contains("trustType"))
                    {
                        int type = (int)result.Properties["trustType"][0];
                        trustType = type switch
                        {
                            1 => "Downlevel (Windows NT)",
                            2 => "Uplevel (Active Directory)",
                            3 => "MIT (Kerberos)",
                            4 => "DCE",
                            _ => $"Unknown ({type})"
                        };
                    }

                    Console.WriteLine($"    [Trust] Target: {targetName}");
                    if (!string.IsNullOrEmpty(flatName))
                        OutputHelper.Verbose($"            NetBIOS: {flatName}");
                    OutputHelper.Verbose($"            Source: {AuthContext.DomainName}");
                    Console.WriteLine($"            Direction: {direction}");
                    OutputHelper.Verbose($"            Type: {trustType}");

                    // Check trust attributes for SID filtering
                    if (result.Properties.Contains("trustAttributes"))
                    {
                        int attrs = (int)result.Properties["trustAttributes"][0];
                        if ((attrs & 0x4) != 0) // TRUST_ATTRIBUTE_QUARANTINED_DOMAIN
                        {
                            OutputHelper.Verbose("            [!] SID Filtering Enabled");
                        }
                        if ((attrs & 0x8) != 0) // TRUST_ATTRIBUTE_FOREST_TRANSITIVE
                        {
                            OutputHelper.Verbose("            [+] Forest Trust");
                        }
                    }
                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        public static void EnumerateUsers()
        {
            Console.WriteLine("[*] Enumerating Domain Users...\n");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(&(objectClass=user)(objectCategory=person))";
                searcher.PropertiesToLoad.Add("samAccountName");
                searcher.PageSize = 1000;

                SearchResultCollection results = searcher.FindAll();

                Console.WriteLine($"[+] Found {results.Count} users:\n");

                // Simple output: just sAMAccountName
                foreach (SearchResult result in results)
                {
                    string samAccountName = result.Properties["samAccountName"].Count > 0 ?
                        result.Properties["samAccountName"][0].ToString() : "N/A";
                    Console.WriteLine(samAccountName);
                }

                Console.WriteLine($"\n[+] Total: {results.Count} users");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        public static void EnumerateComputers(bool resolveIPs = true)
        {
            Console.WriteLine("[*] Enumerating Domain Computers...\n");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(objectClass=computer)";
                searcher.PropertiesToLoad.Add("samAccountName");
                searcher.PropertiesToLoad.Add("dNSHostName");
                searcher.PropertiesToLoad.Add("operatingSystem");
                searcher.PropertiesToLoad.Add("operatingSystemVersion");
                searcher.PropertiesToLoad.Add("lastLogonTimestamp");
                searcher.PageSize = 1000;

                SearchResultCollection results = searcher.FindAll();

                Console.WriteLine($"[+] Found {results.Count} computers:\n");

                // Table header
                Console.WriteLine("    {0,-25} {1,-18} {2,-30} {3}", "HOSTNAME", "IP ADDRESS", "OPERATING SYSTEM", "LAST LOGON");
                Console.WriteLine("    {0,-25} {1,-18} {2,-30} {3}", new string('-', 25), new string('-', 18), new string('-', 30), new string('-', 12));

                int count = 0;
                int onlineCount = 0;
                foreach (SearchResult result in results)
                {
                    count++;
                    string samAccountName = result.Properties["samAccountName"].Count > 0 ?
                        result.Properties["samAccountName"][0].ToString().TrimEnd('$') : "N/A";
                    string dnsName = result.Properties["dNSHostName"].Count > 0 ?
                        result.Properties["dNSHostName"][0].ToString() : "";
                    string os = result.Properties["operatingSystem"].Count > 0 ?
                        result.Properties["operatingSystem"][0].ToString() : "N/A";

                    // Shorten OS name
                    if (os.Length > 28)
                        os = os.Substring(0, 28) + "..";

                    // Get last logon
                    string lastLogon = "N/A";
                    if (result.Properties["lastLogonTimestamp"].Count > 0)
                    {
                        try
                        {
                            long lastLogonValue = (long)result.Properties["lastLogonTimestamp"][0];
                            if (lastLogonValue > 0)
                            {
                                DateTime lastLogonDate = DateTime.FromFileTimeUtc(lastLogonValue);
                                TimeSpan timeSince = DateTime.UtcNow - lastLogonDate;
                                if (timeSince.TotalDays < 1)
                                    lastLogon = "Today";
                                else if (timeSince.TotalDays < 7)
                                    lastLogon = $"{(int)timeSince.TotalDays}d ago";
                                else if (timeSince.TotalDays < 30)
                                    lastLogon = $"{(int)(timeSince.TotalDays / 7)}w ago";
                                else
                                    lastLogon = $"{(int)(timeSince.TotalDays / 30)}mo ago";
                            }
                        }
                        catch { }
                    }

                    // Resolve IP
                    string ipAddress = "";
                    if (resolveIPs && !string.IsNullOrEmpty(dnsName))
                    {
                        ipAddress = ResolveHostIP(dnsName);
                        if (!string.IsNullOrEmpty(ipAddress) && ipAddress != "[Offline]")
                            onlineCount++;
                    }

                    Console.WriteLine("    {0,-25} {1,-18} {2,-30} {3}", samAccountName, ipAddress, os, lastLogon);

                    // Show additional details in verbose mode
                    if (OutputHelper.IsVerbose && !string.IsNullOrEmpty(dnsName))
                    {
                        OutputHelper.Verbose($"         FQDN: {dnsName}");
                        if (result.Properties["operatingSystemVersion"].Count > 0)
                            OutputHelper.Verbose($"         OS Version: {result.Properties["operatingSystemVersion"][0]}");
                    }
                }

                Console.WriteLine();
                Console.WriteLine($"[+] Total: {count} computers");
                if (resolveIPs)
                    Console.WriteLine($"[+] Resolvable: {onlineCount} computers");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        
        /// Resolve hostname to IP address (uses DC as DNS if configured)
        private static string ResolveHostIP(string hostname)
        {
            try
            {
                // Use DC as DNS server if configured
                if (!string.IsNullOrEmpty(AuthContext.DnsServer))
                {
                    string resolved = ResolveDnsWithServer(hostname, AuthContext.DnsServer);
                    if (!string.IsNullOrEmpty(resolved))
                        return resolved;
                }

                // Fallback to system DNS
                IPHostEntry hostEntry = Dns.GetHostEntry(hostname);
                // Prefer IPv4
                foreach (var ip in hostEntry.AddressList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                        return ip.ToString();
                }
                // Fallback to first IP
                if (hostEntry.AddressList.Length > 0)
                    return hostEntry.AddressList[0].ToString();
            }
            catch
            {
                return "[Offline]";
            }
            return "";
        }

        
        /// Get list of computers with their hostnames/IPs for share enumeration
        /// Returns IP addresses when DNS resolution works, otherwise FQDN
        public static List<string> GetComputerHostnames()
        {
            var hostnames = new List<string>();

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(objectClass=computer)";
                searcher.PropertiesToLoad.Add("dNSHostName");
                searcher.PageSize = 1000;

                SearchResultCollection results = searcher.FindAll();

                foreach (SearchResult result in results)
                {
                    if (result.Properties["dNSHostName"].Count > 0)
                    {
                        string dnsName = result.Properties["dNSHostName"][0].ToString();
                        if (!string.IsNullOrEmpty(dnsName))
                        {
                            // If we have a custom DNS server (not domain-joined), resolve to IP
                            if (!string.IsNullOrEmpty(AuthContext.DnsServer))
                            {
                                string ip = ResolveDnsWithServer(dnsName, AuthContext.DnsServer);
                                if (!string.IsNullOrEmpty(ip))
                                {
                                    hostnames.Add(ip);
                                    continue;
                                }
                            }
                            hostnames.Add(dnsName);
                        }
                    }
                }
            }
            catch { }

            return hostnames;
        }

        public static void EnumerateShares()
        {
            Console.WriteLine("[*] Enumerating Domain Shares (SYSVOL/NETLOGON)...\n");

            try
            {
                // Get DC hostname from LDAP or use DC IP
                string dcTarget = GetDCHostname();
                if (string.IsNullOrEmpty(dcTarget))
                {
                    Console.WriteLine("[!] Could not determine DC hostname.");
                    return;
                }

                // Establish authenticated SMB session if using alternate credentials
                if (!EstablishSmbConnection(dcTarget, out string smbError))
                {
                    Console.WriteLine($"[!] Could not establish SMB session to DC: {smbError}");
                    Console.WriteLine("[!] Share enumeration may fail without proper authentication.");
                }

                string[] sharePaths = new string[]
                {
                    $"\\\\{dcTarget}\\SYSVOL",
                    $"\\\\{dcTarget}\\NETLOGON"
                };

                try
                {
                    foreach (string sharePath in sharePaths)
                    {
                        Console.WriteLine($"[*] Enumerating: {sharePath}");

                        try
                        {
                            // Try to list directory contents directly instead of Directory.Exists
                            // This gives better error messages for access denied vs not found
                            string[] entries = Directory.GetDirectories(sharePath);

                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"[+] Share accessible!");
                            Console.ResetColor();

                            // List files
                            string[] files = Directory.GetFiles(sharePath, "*.*", SearchOption.AllDirectories);
                            OutputHelper.Verbose($"[+] Found {files.Length} files:");

                            if (OutputHelper.IsVerbose)
                            {
                                foreach (string file in files.Take(50))
                                {
                                    FileInfo fi = new FileInfo(file);
                                    Console.WriteLine($"    {file} ({fi.Length} bytes)");
                                }

                                if (files.Length > 50)
                                    Console.WriteLine($"    ... and {files.Length - 50} more files");
                            }

                            // Look for interesting files
                            var interestingFiles = files.Where(f =>
                                f.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) ||
                                f.EndsWith(".ini", StringComparison.OrdinalIgnoreCase) ||
                                f.EndsWith(".bat", StringComparison.OrdinalIgnoreCase) ||
                                f.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase) ||
                                f.EndsWith(".vbs", StringComparison.OrdinalIgnoreCase) ||
                                f.IndexOf("password", StringComparison.OrdinalIgnoreCase) >= 0
                            ).ToList();

                            if (interestingFiles.Count > 0)
                            {
                                Console.WriteLine($"\n[!] Found {interestingFiles.Count} potentially interesting files:");
                                foreach (string file in interestingFiles)
                                {
                                    Console.WriteLine($"    [!] {file}");
                                }
                            }
                        }
                        catch (UnauthorizedAccessException)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"[!] ACCESS DENIED - User does not have read permissions");
                            Console.ResetColor();
                        }
                        catch (DirectoryNotFoundException)
                        {
                            Console.WriteLine($"[!] Share does not exist");
                        }
                        catch (IOException ex)
                        {
                            // Network errors
                            Console.WriteLine($"[!] Network error: {ex.Message}");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[!] Error accessing {sharePath}: {ex.Message}");
                        }

                        Console.WriteLine();
                    }
                }
                finally
                {
                    // Clean up SMB connection
                    CloseSmbConnection(dcTarget);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        // P/Invoke for NetShareEnum
        [DllImport("Netapi32.dll", SetLastError = true)]
        private static extern int NetShareEnum(
            string serverName,
            int level,
            out IntPtr bufPtr,
            int prefMaxLen,
            out int entriesRead,
            out int totalEntries,
            ref int resumeHandle);

        [DllImport("Netapi32.dll", SetLastError = true)]
        private static extern int NetApiBufferFree(IntPtr buffer);

        // WNetAddConnection2 for authenticated SMB connections
        [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
        private static extern int WNetAddConnection2(ref NETRESOURCE netResource, string password, string username, int flags);

        [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
        private static extern int WNetCancelConnection2(string name, int flags, bool force);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct NETRESOURCE
        {
            public int dwScope;
            public int dwType;
            public int dwDisplayType;
            public int dwUsage;
            public string lpLocalName;
            public string lpRemoteName;
            public string lpComment;
            public string lpProvider;
        }

        private const int RESOURCETYPE_DISK = 1;
        private const int CONNECT_TEMPORARY = 0x00000004;

        
        /// Establish authenticated SMB connection to remote host
        /// Required when running from non-domain-joined machine with alternate credentials
        
        private static bool EstablishSmbConnection(string host, out string error)
        {
            error = null;

            // Only needed when using alternate credentials from non-domain-joined machine
            if (!AuthContext.UseAlternateCredentials)
            {
                return true; // No need, using current Windows context
            }

            string uncPath = $@"\\{host}\IPC$";

            // First, try to cancel any existing connection (ignore errors)
            WNetCancelConnection2(uncPath, 0, true);

            // Try multiple username formats since SMB can be picky
            // 1. UPN format: user@domain.com (most reliable for cross-domain)
            // 2. NetBIOS format: DOMAIN\user
            // 3. Domain FQDN format: domain.com\user
            var usernameFormats = new List<string>();

            // UPN format first (most reliable)
            if (!string.IsNullOrEmpty(AuthContext.DomainName))
            {
                usernameFormats.Add($"{AuthContext.Username}@{AuthContext.DomainName}");
            }

            // NetBIOS format (extract first part of domain)
            if (!string.IsNullOrEmpty(AuthContext.CredentialDomain))
            {
                string netbiosDomain = AuthContext.CredentialDomain.Split('.')[0].ToUpper();
                usernameFormats.Add($"{netbiosDomain}\\{AuthContext.Username}");
            }

            // FQDN format
            if (!string.IsNullOrEmpty(AuthContext.CredentialDomain))
            {
                usernameFormats.Add($"{AuthContext.CredentialDomain}\\{AuthContext.Username}");
            }

            // Just username as fallback
            usernameFormats.Add(AuthContext.Username);

            var netResource = new NETRESOURCE
            {
                dwType = RESOURCETYPE_DISK,
                lpRemoteName = uncPath,
                lpLocalName = null,
                lpProvider = null
            };

            int lastResult = 0;
            foreach (string username in usernameFormats)
            {
                OutputHelper.Verbose($"    [*] Trying SMB auth: {username}");

                int result = WNetAddConnection2(ref netResource, AuthContext.Password, username, CONNECT_TEMPORARY);

                if (result == 0)
                {
                    OutputHelper.Verbose($"    [+] SMB session established to {host} as {username}");
                    return true;
                }

                // If error 1219 (session exists), we can still try to use it
                if (result == 1219)
                {
                    OutputHelper.Verbose($"    [*] Using existing SMB session to {host}");
                    return true;
                }

                lastResult = result;

                // Cancel before trying next format
                WNetCancelConnection2(uncPath, 0, true);
            }

            // Common error codes for the last attempt
            error = lastResult switch
            {
                5 => "Access Denied",
                53 => "Network path not found",
                67 => "Network name not found",
                86 => "Invalid password",
                1219 => "Multiple connections not allowed (session exists)",
                1326 => "Logon failure (bad credentials)",
                1311 => "No logon servers available",
                2202 => "Bad username",
                _ => $"Error code {lastResult}"
            };

            OutputHelper.Verbose($"    [!] SMB connection failed to {host}: {error}");
            return false;
        }

        
        /// Close SMB connection to remote host
        
        private static void CloseSmbConnection(string host)
        {
            if (!AuthContext.UseAlternateCredentials)
                return;

            string uncPath = $@"\\{host}\IPC$";
            WNetCancelConnection2(uncPath, 0, false);
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SHARE_INFO_1
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string shi1_netname;
            public uint shi1_type;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string shi1_remark;
        }

        // Share types
        private const uint STYPE_DISKTREE = 0x0;
        private const uint STYPE_PRINTQ = 0x1;
        private const uint STYPE_DEVICE = 0x2;
        private const uint STYPE_IPC = 0x3;
        private const uint STYPE_SPECIAL = 0x80000000;

        
        /// Enumerate shares on all domain computers
        public static void EnumerateAllShares(string targetHost = null)
        {
            Console.WriteLine("[*] Enumerating Network Shares...\n");

            List<string> hosts = new List<string>();

            if (!string.IsNullOrEmpty(targetHost))
            {
                // Single target
                hosts.Add(targetHost);
            }
            else
            {
                // Get all computers from domain
                Console.WriteLine("[*] Getting list of domain computers...");
                hosts = GetComputerHostnames();
                Console.WriteLine($"[+] Found {hosts.Count} computers\n");
            }

            int accessibleHosts = 0;
            int totalShares = 0;
            var accessibleShares = new List<Tuple<string, string, string>>(); // host, share, remark

            int current = 0;
            int skipped = 0;
            foreach (string host in hosts)
            {
                current++;
                Console.Write($"\r[*] Scanning {current}/{hosts.Count}: {host.PadRight(30)}");

                // Resolve hostname to IP if needed (from non-domain machine)
                string resolvedHost = host;
                if (!string.IsNullOrEmpty(AuthContext.DnsServer) && !System.Net.IPAddress.TryParse(host, out _))
                {
                    string resolved = ResolveDnsWithServer(host, AuthContext.DnsServer);
                    if (string.IsNullOrEmpty(resolved))
                    {
                        skipped++;
                        continue; // Skip hosts that can't be resolved
                    }
                    resolvedHost = resolved;
                }

                try
                {
                    var shares = GetHostShares(resolvedHost);

                    if (shares.Count > 0)
                    {
                        accessibleHosts++;
                        totalShares += shares.Count;

                        Console.Write("\r" + new string(' ', 60) + "\r"); // Clear line
                        Console.WriteLine($"[+] {host}");
                        foreach (var share in shares)
                        {
                            string shareType = GetShareTypeName(share.Item2);
                            string remark = !string.IsNullOrEmpty(share.Item3) ? $" - {share.Item3}" : "";

                            // Skip IPC$ and admin shares in non-verbose mode
                            bool isAdminShare = share.Item1.EndsWith("$");
                            if (isAdminShare && !OutputHelper.IsVerbose)
                            {
                                continue;
                            }

                            Console.WriteLine($"    \\\\{host}\\{share.Item1} [{shareType}]{remark}");
                            accessibleShares.Add(Tuple.Create(host, share.Item1, share.Item3));

                            // Check if accessible and look for interesting files
                            if (!isAdminShare)
                            {
                                CheckShareAccess(host, share.Item1);
                            }
                        }
                        Console.WriteLine();
                    }
                }
                catch (Exception ex)
                {
                    OutputHelper.Verbose($"[!] Error on {host}: {ex.Message}");
                }
            }

            // Clear progress line
            Console.Write("\r" + new string(' ', 60) + "\r");

            // Summary
            Console.WriteLine("========================================");
            Console.WriteLine("[*] SUMMARY");
            Console.WriteLine("========================================");
            Console.WriteLine($"    Hosts total:      {hosts.Count}");
            if (skipped > 0)
                Console.WriteLine($"    Hosts skipped:    {skipped} (DNS resolution failed)");
            Console.WriteLine($"    Hosts scanned:    {hosts.Count - skipped}");
            Console.WriteLine($"    Hosts accessible: {accessibleHosts}");
            Console.WriteLine($"    Shares found:     {totalShares}");

            // List non-default shares
            var interestingShares = accessibleShares.Where(s =>
                !s.Item2.EndsWith("$") &&
                s.Item2.ToUpper() != "NETLOGON" &&
                s.Item2.ToUpper() != "SYSVOL").ToList();

            if (interestingShares.Count > 0)
            {
                Console.WriteLine($"\n[!] Non-default shares found: {interestingShares.Count}");
                foreach (var share in interestingShares.Take(20))
                {
                    Console.WriteLine($"    \\\\{share.Item1}\\{share.Item2}");
                }
                if (interestingShares.Count > 20)
                    Console.WriteLine($"    ... and {interestingShares.Count - 20} more");
            }
        }

        
        /// Get shares from a specific host using multiple methods (like netexec/snaffler)
        private static List<Tuple<string, uint, string>> GetHostShares(string host)
        {
            var shares = new List<Tuple<string, uint, string>>();

            // Establish authenticated SMB session if using alternate credentials
            // This is REQUIRED when running from non-domain-joined machine
            if (!EstablishSmbConnection(host, out string smbError))
            {
                OutputHelper.Verbose($"    [!] Could not establish SMB session: {smbError}");
                // Don't return - some methods might still work
            }

            try
            {
                // Method 1: Try NetShareEnum API first (most reliable with authenticated session)
                shares = GetHostSharesNetApi(host);
                if (shares.Count > 0)
                    return shares;

                // Method 2: Try net view command (works well with authenticated session)
                shares = GetHostSharesNetView(host);
                if (shares.Count > 0)
                    return shares;

                // Method 3: Try SMB enumeration via file system
                shares = GetHostSharesSMB(host);
                if (shares.Count > 0)
                    return shares;

                // Method 4: Try WMI as last resort
                shares = GetHostSharesWMI(host);

                return shares;
            }
            finally
            {
                // Clean up SMB connection
                CloseSmbConnection(host);
            }
        }

        
        /// Check if host is reachable on SMB port with timeout
        
        private static bool IsHostReachable(string host, int port = 445, int timeoutMs = 2000)
        {
            try
            {
                // First try to resolve hostname if it's not an IP
                System.Net.IPAddress ip;
                if (!System.Net.IPAddress.TryParse(host, out ip))
                {
                    // Try to resolve using custom DNS if available
                    if (!string.IsNullOrEmpty(AuthContext.DnsServer))
                    {
                        string resolved = ResolveDnsWithServer(host, AuthContext.DnsServer);
                        if (string.IsNullOrEmpty(resolved))
                            return false;
                        host = resolved;
                    }
                    else
                    {
                        // Try system DNS with timeout
                        try
                        {
                            var dnsTask = System.Threading.Tasks.Task.Run(() => System.Net.Dns.GetHostAddresses(host));
                            if (!dnsTask.Wait(timeoutMs))
                                return false;
                            if (dnsTask.Result.Length == 0)
                                return false;
                            host = dnsTask.Result[0].ToString();
                        }
                        catch
                        {
                            return false;
                        }
                    }
                }

                using (var client = new System.Net.Sockets.TcpClient())
                {
                    var result = client.BeginConnect(host, port, null, null);
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

        
        /// Get shares using direct SMB/file system enumeration (like netexec/snaffler)
        private static List<Tuple<string, uint, string>> GetHostSharesSMB(string host)
        {
            var shares = new List<Tuple<string, uint, string>>();

            // Quick connectivity check first
            if (!IsHostReachable(host, 445, 2000))
            {
                OutputHelper.Verbose($"    [!] Host unreachable (port 445)");
                return shares;
            }

            try
            {
                // This is how netexec and similar tools work - direct SMB enumeration
                string uncPath = $@"\\{host}";

                // Try to get directories from the root (this lists shares)
                DirectoryInfo rootDir = new DirectoryInfo(uncPath);

                foreach (DirectoryInfo dir in rootDir.GetDirectories())
                {
                    string shareName = dir.Name;
                    uint shareType = STYPE_DISKTREE; // Assume disk share

                    // Check if it's accessible
                    string sharePath = $@"\\{host}\{shareName}";
                    bool accessible = false;
                    try
                    {
                        accessible = Directory.Exists(sharePath);
                    }
                    catch { }

                    shares.Add(Tuple.Create(shareName, shareType, accessible ? "Accessible" : ""));
                }

                if (shares.Count > 0)
                    OutputHelper.Verbose($"    [+] SMB enumeration found {shares.Count} shares");
            }
            catch (UnauthorizedAccessException)
            {
                OutputHelper.Verbose($"    [!] SMB enumeration: Access Denied");
            }
            catch (IOException ex)
            {
                OutputHelper.Verbose($"    [!] SMB enumeration failed: {ex.Message}");
            }
            catch (Exception ex)
            {
                OutputHelper.Verbose($"    [!] SMB enumeration error: {ex.Message}");
            }

            return shares;
        }

        
        /// Get shares using 'net view' command (works well when SMB session is established)
        
        private static List<Tuple<string, uint, string>> GetHostSharesNetView(string host)
        {
            var shares = new List<Tuple<string, uint, string>>();

            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "net",
                    Arguments = $"view \\\\{host}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var process = System.Diagnostics.Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit(10000);

                    if (process.ExitCode == 0)
                    {
                        // Parse net view output
                        // Format: "ShareName           Disk      Comment"
                        var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                        bool foundShares = false;

                        foreach (var line in lines)
                        {
                            // Skip header lines
                            if (line.StartsWith("---") || line.StartsWith("Recursos") ||
                                line.StartsWith("Shared") || line.StartsWith("Nombre") ||
                                line.StartsWith("Se ha completado") || line.StartsWith("The command"))
                            {
                                if (line.StartsWith("---"))
                                    foundShares = true;
                                continue;
                            }

                            if (!foundShares)
                                continue;

                            // Parse share line
                            string trimmedLine = line.Trim();
                            if (string.IsNullOrEmpty(trimmedLine))
                                continue;

                            // Split by multiple spaces
                            var parts = System.Text.RegularExpressions.Regex.Split(trimmedLine, @"\s{2,}");
                            if (parts.Length >= 1)
                            {
                                string shareName = parts[0].Trim();
                                string shareType = parts.Length > 1 ? parts[1].Trim() : "Disk";
                                string comment = parts.Length > 2 ? parts[2].Trim() : "";

                                uint type = shareType.ToLower().Contains("print") ? STYPE_PRINTQ : STYPE_DISKTREE;
                                shares.Add(Tuple.Create(shareName, type, comment));
                            }
                        }

                        if (shares.Count > 0)
                            OutputHelper.Verbose($"    [+] net view found {shares.Count} shares");
                    }
                    else
                    {
                        string error = process.StandardError.ReadToEnd();
                        OutputHelper.Verbose($"    [!] net view failed: {error.Trim()}");
                    }
                }
            }
            catch (Exception ex)
            {
                OutputHelper.Verbose($"    [!] net view error: {ex.Message}");
            }

            return shares;
        }

        
        /// Get shares using NetShareEnum API
        private static List<Tuple<string, uint, string>> GetHostSharesNetApi(string host)
        {
            var shares = new List<Tuple<string, uint, string>>();

            IntPtr bufPtr = IntPtr.Zero;
            int entriesRead = 0;
            int totalEntries = 0;
            int resumeHandle = 0;

            try
            {
                // NetShareEnum can take either "servername" or "\\servername"
                // Try with backslashes first as it's more common
                string serverName = host.StartsWith(@"\\") ? host : $@"\\{host}";
                OutputHelper.Verbose($"    [*] NetShareEnum: {serverName}");

                int result = NetShareEnum(serverName, 1, out bufPtr, -1, out entriesRead, out totalEntries, ref resumeHandle);

                // If failed with \\, try without
                if (result != 0 && serverName.StartsWith(@"\\"))
                {
                    OutputHelper.Verbose($"    [*] NetShareEnum: {host} (without \\\\)");
                    result = NetShareEnum(host, 1, out bufPtr, -1, out entriesRead, out totalEntries, ref resumeHandle);
                }

                if (result == 0) // NERR_Success
                {
                    IntPtr currentPtr = bufPtr;
                    int structSize = Marshal.SizeOf(typeof(SHARE_INFO_1));

                    for (int i = 0; i < entriesRead; i++)
                    {
                        SHARE_INFO_1 shareInfo = (SHARE_INFO_1)Marshal.PtrToStructure(currentPtr, typeof(SHARE_INFO_1));
                        shares.Add(Tuple.Create(shareInfo.shi1_netname, shareInfo.shi1_type, shareInfo.shi1_remark ?? ""));
                        currentPtr = IntPtr.Add(currentPtr, structSize);
                    }

                    if (shares.Count > 0)
                        OutputHelper.Verbose($"    [+] NetShareEnum found {shares.Count} shares");
                }
                else
                {
                    string errorMsg = result switch
                    {
                        5 => "Access Denied",
                        53 => "Network path not found",
                        1231 => "Network location cannot be reached",
                        2114 => "Server service not started",
                        _ => $"Error code {result}"
                    };
                    OutputHelper.Verbose($"    [!] NetShareEnum failed: {errorMsg}");
                }
            }
            finally
            {
                if (bufPtr != IntPtr.Zero)
                    NetApiBufferFree(bufPtr);
            }

            return shares;
        }

        
        /// Get shares using WMI (fallback method)
        private static List<Tuple<string, uint, string>> GetHostSharesWMI(string host)
        {
            var shares = new List<Tuple<string, uint, string>>();

            try
            {
                System.Management.ManagementScope scope = new System.Management.ManagementScope($"\\\\{host}\\root\\cimv2");
                scope.Connect();

                System.Management.ObjectQuery query = new System.Management.ObjectQuery("SELECT * FROM Win32_Share");
                System.Management.ManagementObjectSearcher searcher = new System.Management.ManagementObjectSearcher(scope, query);

                foreach (System.Management.ManagementObject share in searcher.Get())
                {
                    string name = share["Name"]?.ToString() ?? "";
                    uint type = Convert.ToUInt32(share["Type"] ?? 0);
                    string description = share["Description"]?.ToString() ?? "";

                    shares.Add(Tuple.Create(name, type, description));
                }

                if (shares.Count > 0)
                    OutputHelper.Verbose($"    [+] WMI found {shares.Count} shares");
            }
            catch (Exception ex)
            {
                OutputHelper.Verbose($"    [!] WMI failed: {ex.Message}");
            }

            return shares;
        }

        
        /// Get friendly name for share type
        private static string GetShareTypeName(uint shareType)
        {
            uint baseType = shareType & 0xFFFF;
            bool isSpecial = (shareType & STYPE_SPECIAL) != 0;

            string typeName;
            switch (baseType)
            {
                case STYPE_DISKTREE:
                    typeName = "Disk";
                    break;
                case STYPE_PRINTQ:
                    typeName = "Printer";
                    break;
                case STYPE_DEVICE:
                    typeName = "Device";
                    break;
                case STYPE_IPC:
                    typeName = "IPC";
                    break;
                default:
                    typeName = "Unknown";
                    break;
            }

            if (isSpecial)
                typeName += "/Admin";

            return typeName;
        }

        
        /// Check if a share is accessible and look for interesting files
        
        private static void CheckShareAccess(string host, string shareName)
        {
            string sharePath = $"\\\\{host}\\{shareName}";

            try
            {
                if (Directory.Exists(sharePath))
                {
                    // Check write permissions by attempting to create a temp file
                    bool canWrite = false;
                    string testFile = Path.Combine(sharePath, $".spicyad_test_{Guid.NewGuid():N}.tmp");
                    try
                    {
                        using (var fs = File.Create(testFile, 1, FileOptions.DeleteOnClose))
                        {
                            canWrite = true;
                        }
                        // Clean up just in case
                        try { File.Delete(testFile); } catch { }
                    }
                    catch { }

                    Console.ForegroundColor = ConsoleColor.Green;
                    if (canWrite)
                    {
                        Console.WriteLine($"        [READABLE] [WRITABLE]");
                    }
                    else
                    {
                        Console.WriteLine($"        [READABLE]");
                    }
                    Console.ResetColor();

                    // In verbose mode, list some files and check for interesting ones
                    if (OutputHelper.IsVerbose)
                    {
                        try
                        {
                            var files = Directory.GetFiles(sharePath, "*.*", SearchOption.TopDirectoryOnly).Take(10);
                            foreach (string file in files)
                            {
                                OutputHelper.Verbose($"            {Path.GetFileName(file)}");
                            }

                            // Quick check for interesting file patterns
                            var allFiles = Directory.GetFiles(sharePath, "*.*", SearchOption.AllDirectories);
                            var interesting = allFiles.Where(f =>
                                f.EndsWith(".config", StringComparison.OrdinalIgnoreCase) ||
                                f.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) ||
                                f.EndsWith(".ini", StringComparison.OrdinalIgnoreCase) ||
                                f.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ||
                                f.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase) ||
                                f.EndsWith(".bat", StringComparison.OrdinalIgnoreCase) ||
                                f.IndexOf("password", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                f.IndexOf("credential", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                f.IndexOf("secret", StringComparison.OrdinalIgnoreCase) >= 0
                            ).ToList();

                            if (interesting.Count > 0)
                            {
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.WriteLine($"        [!] Found {interesting.Count} potentially interesting files");
                                Console.ResetColor();
                                foreach (var file in interesting.Take(5))
                                {
                                    Console.WriteLine($"            {file}");
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"        [ACCESS DENIED]");
                Console.ResetColor();
            }
            catch { }
        }

        // =============================================
        // DELEGATION ENUMERATION
        // =============================================

        
        /// Enumerate all delegation configurations in the domain
        public static void EnumerateDelegations()
        {
            Console.WriteLine("[*] Enumerating Kerberos Delegation Configurations...\n");

            EnumerateUnconstrainedDelegation();
            Console.WriteLine();
            EnumerateConstrainedDelegation();
            Console.WriteLine();
            EnumerateRBCD();
        }

        
        /// Enumerate accounts with Unconstrained Delegation (TrustedForDelegation)
        /// These can be used to capture TGTs from any service authenticating to them
        public static void EnumerateUnconstrainedDelegation()
        {
            Console.WriteLine("========================================");
            Console.WriteLine("[*] UNCONSTRAINED DELEGATION");
            Console.WriteLine("========================================");
            Console.WriteLine("[*] Accounts trusted to authenticate on behalf of ANY service\n");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);

                // TrustedForDelegation flag (0x80000) in userAccountControl
                // Exclude Domain Controllers (they have this by default)
                searcher.Filter = "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))";
                searcher.PropertiesToLoad.Add("samAccountName");
                searcher.PropertiesToLoad.Add("distinguishedName");
                searcher.PropertiesToLoad.Add("objectClass");
                searcher.PropertiesToLoad.Add("dNSHostName");
                searcher.PropertiesToLoad.Add("servicePrincipalName");
                searcher.PageSize = 1000;

                SearchResultCollection results = searcher.FindAll();

                if (results.Count == 0)
                {
                    Console.WriteLine("[+] No non-DC accounts with Unconstrained Delegation found.");
                    return;
                }

                Console.WriteLine($"[!] Found {results.Count} account(s) with Unconstrained Delegation:\n");

                foreach (SearchResult result in results)
                {
                    string samAccountName = result.Properties["samAccountName"].Count > 0 ?
                        result.Properties["samAccountName"][0].ToString() : "N/A";
                    string dn = result.Properties["distinguishedName"].Count > 0 ?
                        result.Properties["distinguishedName"][0].ToString() : "";

                    bool isComputer = false;
                    if (result.Properties["objectClass"].Count > 0)
                    {
                        foreach (var objClass in result.Properties["objectClass"])
                        {
                            if (objClass.ToString().Equals("computer", StringComparison.OrdinalIgnoreCase))
                            {
                                isComputer = true;
                                break;
                            }
                        }
                    }

                    string accountType = isComputer ? "COMPUTER" : "USER";
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[!] {samAccountName} ({accountType})");
                    Console.ResetColor();

                    if (isComputer && result.Properties["dNSHostName"].Count > 0)
                    {
                        Console.WriteLine($"    DNS: {result.Properties["dNSHostName"][0]}");
                    }

                    OutputHelper.Verbose($"    DN: {dn}");

                    // Show SPNs in verbose mode
                    if (OutputHelper.IsVerbose && result.Properties["servicePrincipalName"].Count > 0)
                    {
                        Console.WriteLine("    SPNs:");
                        foreach (var spn in result.Properties["servicePrincipalName"])
                        {
                            Console.WriteLine($"        {spn}");
                        }
                    }
                    Console.WriteLine();
                }

                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[!] RISK: Unconstrained delegation allows capturing TGTs from ANY user");
                Console.WriteLine("[!]       authenticating to these services. Compromise = domain compromise.");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        
        /// Enumerate accounts with Constrained Delegation (msDS-AllowedToDelegateTo)
        /// These can impersonate any user to specific services
        public static void EnumerateConstrainedDelegation()
        {
            Console.WriteLine("========================================");
            Console.WriteLine("[*] CONSTRAINED DELEGATION");
            Console.WriteLine("========================================");
            Console.WriteLine("[*] Accounts that can delegate to SPECIFIC services (S4U2Proxy)\n");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);

                // Accounts with msDS-AllowedToDelegateTo attribute set
                searcher.Filter = "(msDS-AllowedToDelegateTo=*)";
                searcher.PropertiesToLoad.Add("samAccountName");
                searcher.PropertiesToLoad.Add("distinguishedName");
                searcher.PropertiesToLoad.Add("objectClass");
                searcher.PropertiesToLoad.Add("dNSHostName");
                searcher.PropertiesToLoad.Add("msDS-AllowedToDelegateTo");
                searcher.PropertiesToLoad.Add("userAccountControl");
                searcher.PageSize = 1000;

                SearchResultCollection results = searcher.FindAll();

                if (results.Count == 0)
                {
                    Console.WriteLine("[+] No accounts with Constrained Delegation found.");
                    return;
                }

                Console.WriteLine($"[+] Found {results.Count} account(s) with Constrained Delegation:\n");

                foreach (SearchResult result in results)
                {
                    string samAccountName = result.Properties["samAccountName"].Count > 0 ?
                        result.Properties["samAccountName"][0].ToString() : "N/A";
                    string dn = result.Properties["distinguishedName"].Count > 0 ?
                        result.Properties["distinguishedName"][0].ToString() : "";

                    bool isComputer = false;
                    if (result.Properties["objectClass"].Count > 0)
                    {
                        foreach (var objClass in result.Properties["objectClass"])
                        {
                            if (objClass.ToString().Equals("computer", StringComparison.OrdinalIgnoreCase))
                            {
                                isComputer = true;
                                break;
                            }
                        }
                    }

                    // Check for protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION)
                    int uac = result.Properties["userAccountControl"].Count > 0 ?
                        (int)result.Properties["userAccountControl"][0] : 0;
                    bool protocolTransition = (uac & 0x1000000) != 0; // TRUSTED_TO_AUTH_FOR_DELEGATION

                    string accountType = isComputer ? "COMPUTER" : "USER";
                    Console.ForegroundColor = protocolTransition ? ConsoleColor.Red : ConsoleColor.Yellow;
                    Console.WriteLine($"[{(protocolTransition ? "!" : "+")}] {samAccountName} ({accountType})");
                    Console.ResetColor();

                    if (protocolTransition)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("    [!] Protocol Transition ENABLED (S4U2Self) - Can impersonate ANY user!");
                        Console.ResetColor();
                    }

                    if (isComputer && result.Properties["dNSHostName"].Count > 0)
                    {
                        Console.WriteLine($"    DNS: {result.Properties["dNSHostName"][0]}");
                    }

                    OutputHelper.Verbose($"    DN: {dn}");

                    // Show delegation targets
                    if (result.Properties["msDS-AllowedToDelegateTo"].Count > 0)
                    {
                        Console.WriteLine("    Allowed to delegate to:");
                        foreach (var target in result.Properties["msDS-AllowedToDelegateTo"])
                        {
                            string targetStr = target.ToString();
                            // Highlight interesting targets
                            if (targetStr.StartsWith("ldap/", StringComparison.OrdinalIgnoreCase) ||
                                targetStr.StartsWith("cifs/", StringComparison.OrdinalIgnoreCase) ||
                                targetStr.StartsWith("http/", StringComparison.OrdinalIgnoreCase))
                            {
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.WriteLine($"        [!] {targetStr}");
                                Console.ResetColor();
                            }
                            else
                            {
                                Console.WriteLine($"        {targetStr}");
                            }
                        }
                    }
                    Console.WriteLine();
                }

                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[*] RISK: Constrained delegation with protocol transition allows");
                Console.WriteLine("[*]       impersonating ANY user to the listed services.");
                Console.WriteLine("[*]       ldap/ = DCSync potential, cifs/ = file access, http/ = web admin");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        
        /// Enumerate Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity)
        public static void EnumerateRBCD()
        {
            Console.WriteLine("========================================");
            Console.WriteLine("[*] RESOURCE-BASED CONSTRAINED DELEGATION (RBCD)");
            Console.WriteLine("========================================");
            Console.WriteLine("[*] Resources that allow other accounts to impersonate users to them\n");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);

                // Accounts with msDS-AllowedToActOnBehalfOfOtherIdentity attribute set
                searcher.Filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)";
                searcher.PropertiesToLoad.Add("samAccountName");
                searcher.PropertiesToLoad.Add("distinguishedName");
                searcher.PropertiesToLoad.Add("objectClass");
                searcher.PropertiesToLoad.Add("dNSHostName");
                searcher.PropertiesToLoad.Add("msDS-AllowedToActOnBehalfOfOtherIdentity");
                searcher.PageSize = 1000;

                SearchResultCollection results = searcher.FindAll();

                if (results.Count == 0)
                {
                    Console.WriteLine("[+] No accounts with RBCD configured found.");
                    return;
                }

                Console.WriteLine($"[!] Found {results.Count} account(s) with RBCD configured:\n");

                foreach (SearchResult result in results)
                {
                    string samAccountName = result.Properties["samAccountName"].Count > 0 ?
                        result.Properties["samAccountName"][0].ToString() : "N/A";
                    string dn = result.Properties["distinguishedName"].Count > 0 ?
                        result.Properties["distinguishedName"][0].ToString() : "";

                    bool isComputer = false;
                    if (result.Properties["objectClass"].Count > 0)
                    {
                        foreach (var objClass in result.Properties["objectClass"])
                        {
                            if (objClass.ToString().Equals("computer", StringComparison.OrdinalIgnoreCase))
                            {
                                isComputer = true;
                                break;
                            }
                        }
                    }

                    string accountType = isComputer ? "COMPUTER" : "USER";
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[!] {samAccountName} ({accountType})");
                    Console.ResetColor();

                    if (isComputer && result.Properties["dNSHostName"].Count > 0)
                    {
                        Console.WriteLine($"    DNS: {result.Properties["dNSHostName"][0]}");
                    }

                    OutputHelper.Verbose($"    DN: {dn}");

                    // Parse the security descriptor to show who can delegate
                    if (result.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"].Count > 0)
                    {
                        try
                        {
                            byte[] sdBytes = (byte[])result.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"][0];
                            var sd = new System.Security.AccessControl.RawSecurityDescriptor(sdBytes, 0);

                            Console.WriteLine("    Accounts allowed to delegate TO this resource:");

                            foreach (var ace in sd.DiscretionaryAcl)
                            {
                                var accessAce = ace as System.Security.AccessControl.CommonAce;
                                if (accessAce != null)
                                {
                                    string sidStr = accessAce.SecurityIdentifier.ToString();
                                    string accountName = ResolveAccountName(accessAce.SecurityIdentifier);

                                    Console.ForegroundColor = ConsoleColor.Yellow;
                                    Console.WriteLine($"        [!] {accountName} ({sidStr})");
                                    Console.ResetColor();
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            OutputHelper.Verbose($"    [!] Could not parse RBCD descriptor: {ex.Message}");
                        }
                    }
                    Console.WriteLine();
                }

                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[*] RISK: RBCD allows the listed accounts to impersonate ANY user");
                Console.WriteLine("[*]       (except those in Protected Users) to the target resource.");
                Console.WriteLine("[*]       If you control one of the allowed accounts, you can compromise the target.");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        
        /// Resolve a SID to account name
        private static string ResolveAccountName(System.Security.Principal.SecurityIdentifier sid)
        {
            try
            {
                return sid.Translate(typeof(System.Security.Principal.NTAccount)).ToString();
            }
            catch
            {
                return sid.ToString();
            }
        }

        
        /// Find accounts where we might be able to configure RBCD
        /// (accounts where low-priv users have write permissions)
        public static void FindRBCDTargets()
        {
            Console.WriteLine("========================================");
            Console.WriteLine("[*] POTENTIAL RBCD TARGETS");
            Console.WriteLine("========================================");
            Console.WriteLine("[*] Looking for computers where you might have write access...\n");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);

                // Find computers - we'll check ACLs
                searcher.Filter = "(objectClass=computer)";
                searcher.PropertiesToLoad.Add("samAccountName");
                searcher.PropertiesToLoad.Add("distinguishedName");
                searcher.PropertiesToLoad.Add("dNSHostName");
                searcher.PropertiesToLoad.Add("nTSecurityDescriptor");
                searcher.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;
                searcher.PageSize = 1000;

                SearchResultCollection results = searcher.FindAll();

                var currentUser = System.Security.Principal.WindowsIdentity.GetCurrent();
                var currentUserSids = new HashSet<string>();
                currentUserSids.Add(currentUser.User.ToString());
                foreach (var group in currentUser.Groups)
                {
                    currentUserSids.Add(group.ToString());
                }

                int vulnerableCount = 0;
                var vulnerableComputers = new List<string>();

                foreach (SearchResult result in results)
                {
                    string samAccountName = result.Properties["samAccountName"].Count > 0 ?
                        result.Properties["samAccountName"][0].ToString() : "N/A";
                    string dn = result.Properties["distinguishedName"].Count > 0 ?
                        result.Properties["distinguishedName"][0].ToString() : "";

                    try
                    {
                        DirectoryEntry compEntry = result.GetDirectoryEntry();
                        var sd = compEntry.ObjectSecurity;

                        foreach (System.DirectoryServices.ActiveDirectoryAccessRule rule in sd.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier)))
                        {
                            string sidStr = rule.IdentityReference.ToString();

                            // Check if current user or their groups have write access
                            if (currentUserSids.Contains(sidStr))
                            {
                                // Check for GenericAll, GenericWrite, WriteProperty, or WriteDacl
                                var rights = rule.ActiveDirectoryRights;
                                if (rights.HasFlag(System.DirectoryServices.ActiveDirectoryRights.GenericAll) ||
                                    rights.HasFlag(System.DirectoryServices.ActiveDirectoryRights.GenericWrite) ||
                                    rights.HasFlag(System.DirectoryServices.ActiveDirectoryRights.WriteProperty) ||
                                    rights.HasFlag(System.DirectoryServices.ActiveDirectoryRights.WriteDacl) ||
                                    rights.HasFlag(System.DirectoryServices.ActiveDirectoryRights.WriteOwner))
                                {
                                    if (rule.AccessControlType == System.Security.AccessControl.AccessControlType.Allow)
                                    {
                                        vulnerableCount++;
                                        vulnerableComputers.Add(samAccountName);

                                        Console.ForegroundColor = ConsoleColor.Green;
                                        Console.WriteLine($"[+] {samAccountName}");
                                        Console.ResetColor();
                                        Console.WriteLine($"    Rights: {rights}");

                                        if (result.Properties["dNSHostName"].Count > 0)
                                            Console.WriteLine($"    DNS: {result.Properties["dNSHostName"][0]}");

                                        OutputHelper.Verbose($"    DN: {dn}");
                                        Console.WriteLine();
                                        break; // Don't need to check more ACEs for this computer
                                    }
                                }
                            }
                        }
                    }
                    catch { }
                }

                if (vulnerableCount == 0)
                {
                    Console.WriteLine("[*] No computers found where current user has write access.");
                    Console.WriteLine("[*] Try running as a different user or check for other privilege escalation paths.");
                }
                else
                {
                    Console.WriteLine($"\n[+] Found {vulnerableCount} potential RBCD targets");
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("\n[*] NEXT STEPS:");
                    Console.WriteLine("[*] 1. Create or control a machine account (MAQ > 0?)");
                    Console.WriteLine("[*] 2. Configure RBCD on target: Set msDS-AllowedToActOnBehalfOfOtherIdentity");
                    Console.WriteLine("[*] 3. Use S4U2Self + S4U2Proxy to get service ticket as admin");
                    Console.ResetColor();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        public static void GetKrbtgtInfo()
        {
            Console.WriteLine("[*] Querying krbtgt Account Information...\n");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(&(objectClass=user)(samAccountName=krbtgt))";
                searcher.PropertiesToLoad.Add("samAccountName");
                searcher.PropertiesToLoad.Add("distinguishedName");
                searcher.PropertiesToLoad.Add("pwdLastSet");
                searcher.PropertiesToLoad.Add("whenCreated");
                searcher.PropertiesToLoad.Add("userAccountControl");
                searcher.PropertiesToLoad.Add("description");

                SearchResult result = searcher.FindOne();

                if (result != null)
                {
                    string samAccountName = result.Properties["samAccountName"].Count > 0 ?
                        result.Properties["samAccountName"][0].ToString() : "N/A";
                    string distinguishedName = result.Properties["distinguishedName"].Count > 0 ?
                        result.Properties["distinguishedName"][0].ToString() : "N/A";
                    string description = result.Properties["description"].Count > 0 ?
                        result.Properties["description"][0].ToString() : "N/A";

                    Console.WriteLine($"[+] Account: {samAccountName}");
                    OutputHelper.Verbose($"[+] Distinguished Name: {distinguishedName}");
                    OutputHelper.Verbose($"[+] Description: {description}");

                    // Get whenCreated
                    if (result.Properties["whenCreated"].Count > 0)
                    {
                        DateTime whenCreated = (DateTime)result.Properties["whenCreated"][0];
                        OutputHelper.Verbose($"[+] Account Created: {whenCreated:yyyy-MM-dd HH:mm:ss} UTC");
                    }

                    // Get pwdLastSet and convert from FileTime
                    if (result.Properties["pwdLastSet"].Count > 0)
                    {
                        long pwdLastSetValue = (long)result.Properties["pwdLastSet"][0];

                        if (pwdLastSetValue == 0)
                        {
                            Console.WriteLine("[!] Password Last Set: Never (or must change at next logon)");
                        }
                        else
                        {
                            DateTime pwdLastSet = DateTime.FromFileTimeUtc(pwdLastSetValue);
                            DateTime now = DateTime.UtcNow;
                            TimeSpan timeSinceChange = now - pwdLastSet;

                            Console.WriteLine($"[+] Password Last Set: {pwdLastSet:yyyy-MM-dd HH:mm:ss} UTC");
                            Console.WriteLine($"[+] Days Since Password Change: {timeSinceChange.Days} days");

                            // Security recommendations
                            if (timeSinceChange.Days > 180)
                            {
                                Console.WriteLine("[!] WARNING: krbtgt password is older than 180 days!");
                                Console.WriteLine("[!] Microsoft recommends rotating krbtgt password regularly.");
                                Console.WriteLine("[!] Old krbtgt passwords can be used for Golden Ticket attacks.");
                            }
                            else if (timeSinceChange.Days > 90)
                            {
                                Console.WriteLine("[*] NOTICE: krbtgt password is older than 90 days.");
                                Console.WriteLine("[*] Consider rotating krbtgt password soon.");
                            }
                            else
                            {
                                Console.WriteLine("[+] krbtgt password is relatively recent.");
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine("[!] Could not retrieve pwdLastSet attribute");
                    }

                    // Get userAccountControl flags
                    if (result.Properties["userAccountControl"].Count > 0)
                    {
                        int uac = (int)result.Properties["userAccountControl"][0];
                        bool disabled = (uac & 0x0002) != 0;

                        Console.WriteLine($"[+] Account Status: {(disabled ? "DISABLED" : "ENABLED")}");
                    }
                }
                else
                {
                    Console.WriteLine("[!] krbtgt account not found");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }



        /// Enumerate LAPS passwords from computers where we have read access
        /// Supports both Legacy LAPS (ms-Mcs-AdmPwd) and Windows LAPS (msLAPS-Password)

        public static void EnumerateLAPS(string targetComputer = null)
        {
            Console.WriteLine("[*] Enumerating LAPS Passwords...\n");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);

                // Build filter - either specific computer or all computers
                if (!string.IsNullOrEmpty(targetComputer))
                {
                    string computerName = targetComputer.TrimEnd('$');
                    searcher.Filter = $"(&(objectClass=computer)(|(samAccountName={computerName}$)(samAccountName={computerName})(name={computerName})))";
                }
                else
                {
                    // Search all computers
                    searcher.Filter = "(objectClass=computer)";
                }

                // Request LAPS attributes (both legacy and Windows LAPS)
                searcher.PropertiesToLoad.Add("samAccountName");
                searcher.PropertiesToLoad.Add("dNSHostName");
                searcher.PropertiesToLoad.Add("ms-Mcs-AdmPwd");              // Legacy LAPS password
                searcher.PropertiesToLoad.Add("ms-Mcs-AdmPwdExpirationTime"); // Legacy LAPS expiration
                searcher.PropertiesToLoad.Add("msLAPS-Password");             // Windows LAPS password (encrypted JSON)
                searcher.PropertiesToLoad.Add("msLAPS-PasswordExpirationTime"); // Windows LAPS expiration
                searcher.PropertiesToLoad.Add("msLAPS-EncryptedPassword");    // Windows LAPS encrypted password
                searcher.PropertiesToLoad.Add("msLAPS-EncryptedPasswordHistory"); // Windows LAPS history
                searcher.PageSize = 1000;

                SearchResultCollection results = searcher.FindAll();

                int totalComputers = 0;
                int lapsFound = 0;
                var lapsPasswords = new List<Tuple<string, string, string, DateTime?>>();

                foreach (SearchResult result in results)
                {
                    totalComputers++;
                    string computerName = result.Properties["samAccountName"].Count > 0
                        ? result.Properties["samAccountName"][0].ToString().TrimEnd('$')
                        : "Unknown";
                    string dnsName = result.Properties["dNSHostName"].Count > 0
                        ? result.Properties["dNSHostName"][0].ToString()
                        : "";

                    // Check Legacy LAPS (ms-Mcs-AdmPwd)
                    if (result.Properties.Contains("ms-Mcs-AdmPwd") && result.Properties["ms-Mcs-AdmPwd"].Count > 0)
                    {
                        string password = result.Properties["ms-Mcs-AdmPwd"][0].ToString();
                        DateTime? expiration = null;

                        if (result.Properties.Contains("ms-Mcs-AdmPwdExpirationTime") &&
                            result.Properties["ms-Mcs-AdmPwdExpirationTime"].Count > 0)
                        {
                            try
                            {
                                long expTime = (long)result.Properties["ms-Mcs-AdmPwdExpirationTime"][0];
                                if (expTime > 0)
                                    expiration = DateTime.FromFileTimeUtc(expTime);
                            }
                            catch { }
                        }

                        lapsPasswords.Add(Tuple.Create(computerName, dnsName, password, expiration));
                        lapsFound++;
                    }

                    // Check Windows LAPS (msLAPS-Password) - cleartext JSON
                    if (result.Properties.Contains("msLAPS-Password") && result.Properties["msLAPS-Password"].Count > 0)
                    {
                        string jsonPassword = result.Properties["msLAPS-Password"][0].ToString();
                        DateTime? expiration = null;

                        if (result.Properties.Contains("msLAPS-PasswordExpirationTime") &&
                            result.Properties["msLAPS-PasswordExpirationTime"].Count > 0)
                        {
                            try
                            {
                                long expTime = (long)result.Properties["msLAPS-PasswordExpirationTime"][0];
                                if (expTime > 0)
                                    expiration = DateTime.FromFileTimeUtc(expTime);
                            }
                            catch { }
                        }

                        // Parse JSON to extract password: {"n":"Administrator","t":"...","p":"PASSWORD"}
                        string password = ParseWindowsLapsJson(jsonPassword);
                        lapsPasswords.Add(Tuple.Create(computerName, dnsName, password, expiration));
                        lapsFound++;
                    }

                    // Check Windows LAPS encrypted password (requires decryption with DPAPI-NG)
                    if (result.Properties.Contains("msLAPS-EncryptedPassword") &&
                        result.Properties["msLAPS-EncryptedPassword"].Count > 0)
                    {
                        // Encrypted passwords require DPAPI-NG decryption which needs authorized user context
                        // Just note that encrypted LAPS exists
                        if (!lapsPasswords.Any(p => p.Item1 == computerName))
                        {
                            OutputHelper.Verbose($"[*] {computerName}: msLAPS-EncryptedPassword found (requires DPAPI-NG decryption)");
                        }
                    }
                }

                // Display results
                if (lapsFound > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"[+] Found {lapsFound} LAPS password(s) on {totalComputers} computer(s):\n");
                    Console.ResetColor();

                    foreach (var entry in lapsPasswords)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"[+] Computer: {entry.Item1}");
                        Console.ResetColor();
                        if (!string.IsNullOrEmpty(entry.Item2))
                            Console.WriteLine($"    DNS Name: {entry.Item2}");
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"    Password: {entry.Item3}");
                        Console.ResetColor();
                        if (entry.Item4.HasValue)
                        {
                            Console.WriteLine($"    Expires:  {entry.Item4.Value:yyyy-MM-dd HH:mm:ss} UTC");
                            if (entry.Item4.Value < DateTime.UtcNow)
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine($"    [!] PASSWORD EXPIRED");
                                Console.ResetColor();
                            }
                        }
                        Console.WriteLine();
                    }

                    // Save to file
                    string filename = $"laps_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
                    using (var writer = new System.IO.StreamWriter(filename))
                    {
                        writer.WriteLine($"# LAPS Passwords - {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                        writer.WriteLine($"# Total: {lapsFound} passwords from {totalComputers} computers");
                        writer.WriteLine();
                        foreach (var entry in lapsPasswords)
                        {
                            writer.WriteLine($"{entry.Item1}\t{entry.Item3}\t{entry.Item2}\t{(entry.Item4.HasValue ? entry.Item4.Value.ToString("yyyy-MM-dd HH:mm:ss") : "")}");
                        }
                    }
                    Console.WriteLine($"[+] Results saved to: {filename}");
                }
                else
                {
                    Console.WriteLine($"[*] Checked {totalComputers} computer(s)");
                    Console.WriteLine("[!] No LAPS passwords found (no read access or LAPS not deployed)");
                    Console.WriteLine("\n[*] Note: LAPS password read access requires:");
                    Console.WriteLine("    - Legacy LAPS: Read permission on ms-Mcs-AdmPwd attribute");
                    Console.WriteLine("    - Windows LAPS: Read permission on msLAPS-Password or msLAPS-EncryptedPassword");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
                OutputHelper.Verbose($"[!] Stack trace: {ex.StackTrace}");
            }
        }

        
        /// Parse Windows LAPS JSON format: {"n":"Administrator","t":"...","p":"PASSWORD"}
        
        private static string ParseWindowsLapsJson(string json)
        {
            try
            {
                // Simple JSON parsing without dependencies
                // Format: {"n":"name","t":"time","p":"password"}
                int pIndex = json.IndexOf("\"p\":");
                if (pIndex > 0)
                {
                    int startQuote = json.IndexOf('"', pIndex + 4);
                    if (startQuote > 0)
                    {
                        int endQuote = json.IndexOf('"', startQuote + 1);
                        // Handle escaped quotes
                        while (endQuote > 0 && json[endQuote - 1] == '\\')
                        {
                            endQuote = json.IndexOf('"', endQuote + 1);
                        }
                        if (endQuote > startQuote)
                        {
                            return json.Substring(startQuote + 1, endQuote - startQuote - 1)
                                .Replace("\\\"", "\"")
                                .Replace("\\\\", "\\");
                        }
                    }
                }
                // Return full JSON if can't parse
                return json;
            }
            catch
            {
                return json;
            }
        }
    }
}

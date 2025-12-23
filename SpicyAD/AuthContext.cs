using System;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Principal;

namespace SpicyAD
{
    public static class AuthContext
    {
        public static string Username { get; private set; }
        public static string Password { get; private set; }
        public static string DomainName { get; private set; }
        public static string DcIp { get; private set; }
        public static string DnsServer { get; private set; }
        public static string CredentialDomain { get; private set; }
        public static bool UseAlternateCredentials { get; private set; }
        public static bool IsDomainJoined { get; private set; }
        public static bool UseLdaps { get; private set; }

        /// <summary>
        /// Get the LDAP protocol prefix (always LDAP:// - SSL is handled via AuthenticationTypes)
        /// </summary>
        public static string LdapProtocol => "LDAP://";

        /// <summary>
        /// Enable or disable LDAPS (SSL/TLS on port 636)
        /// </summary>
        public static void SetLdaps(bool enabled)
        {
            UseLdaps = enabled;
            if (enabled)
            {
                Console.WriteLine("[*] Using LDAPS (SSL/TLS, port 636)");
            }
        }

        
        /// Initialize - detect domain context (fast, no network calls)
        
        public static bool Initialize()
        {
            UseAlternateCredentials = false;
            IsDomainJoined = false;
            UseLdaps = false;
            DcIp = null;
            DomainName = null;

            // Fast domain detection - no network calls
            try
            {
                DomainName = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;

                if (!string.IsNullOrEmpty(DomainName))
                {
                    IsDomainJoined = true;
                    WindowsIdentity currentIdentity = WindowsIdentity.GetCurrent();
                    Username = currentIdentity.Name;

                    Console.WriteLine($"[*] Current User: {Username}");
                    Console.WriteLine($"[*] Domain: {DomainName}");
                }
                else
                {
                    // Not domain joined
                    IsDomainJoined = false;
                    Username = WindowsIdentity.GetCurrent().Name;
                    Console.WriteLine($"[*] Current User: {Username}");
                    Console.WriteLine("[*] Not domain-joined. Use /domain: and /dc-ip: flags.");
                }
            }
            catch
            {
                IsDomainJoined = false;
                Username = Environment.UserName;
            }

            return true;
        }

        
        /// Set target domain and DC for non-domain-joined scenarios
        
        public static void SetTarget(string domain, string dcIp = null)
        {
            DomainName = domain;
            DcIp = dcIp;
        }

        
        /// Set custom DNS server
        
        public static void SetDns(string dns)
        {
            DnsServer = dns;
        }

        
        /// Auto-detect domain from DC using RootDSE query
        /// Only requires DC IP - domain name is extracted automatically
        
        public static bool AutoDetectFromDC(string dcIp)
        {
            if (string.IsNullOrEmpty(dcIp))
                return false;

            try
            {
                OutputHelper.Verbose($"[*] Auto-detecting domain from DC: {dcIp}");

                // Connect to RootDSE (usually allows anonymous or authenticated access)
                string rootDsePath = $"{LdapProtocol}{dcIp}/RootDSE";
                DirectoryEntry rootDse;

                if (UseAlternateCredentials && !string.IsNullOrEmpty(Username) && !string.IsNullOrEmpty(Password))
                {
                    rootDse = new DirectoryEntry(rootDsePath, Username, Password);
                }
                else
                {
                    rootDse = new DirectoryEntry(rootDsePath);
                }

                // Get defaultNamingContext (e.g., DC=evilcorp,DC=net)
                string defaultNC = rootDse.Properties["defaultNamingContext"][0].ToString();
                OutputHelper.Verbose($"[*] Default Naming Context: {defaultNC}");

                // Convert DC=evilcorp,DC=net to evilcorp.net
                string domain = ConvertDNToDomain(defaultNC);
                if (!string.IsNullOrEmpty(domain))
                {
                    DomainName = domain;
                    DcIp = dcIp;

                    // Use DC as DNS server if not specified
                    if (string.IsNullOrEmpty(DnsServer))
                    {
                        DnsServer = dcIp;
                    }

                    Console.WriteLine($"[+] Auto-detected domain: {domain}");
                    return true;
                }
            }
            catch (Exception ex)
            {
                OutputHelper.Verbose($"[!] Auto-detection failed: {ex.Message}");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[!] Could not auto-detect domain from DC. Use /domain: to specify manually.");
                Console.ResetColor();
            }

            return false;
        }

        
        /// Convert Distinguished Name to domain (DC=evilcorp,DC=net -> evilcorp.net)
        
        private static string ConvertDNToDomain(string dn)
        {
            if (string.IsNullOrEmpty(dn))
                return null;

            var parts = dn.Split(',')
                .Where(p => p.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                .Select(p => p.Substring(3));

            return string.Join(".", parts);
        }

        
        /// Prompt for credentials (impacket style)
        
        public static bool PromptCredentials()
        {
            Console.Write("[?] Enter domain\\username: ");
            string userInput = Console.ReadLine()?.Trim();

            if (string.IsNullOrEmpty(userInput))
            {
                Console.WriteLine("[!] Username required.");
                return false;
            }

            if (userInput.Contains("\\"))
            {
                string[] parts = userInput.Split('\\');
                CredentialDomain = parts[0];
                Username = parts[1];
            }
            else
            {
                CredentialDomain = DomainName;
                Username = userInput;
            }

            Console.Write("[?] Password: ");
            Password = ReadPassword();
            Console.WriteLine();

            UseAlternateCredentials = true;
            return true;
        }

        
        /// Set credentials programmatically
        
        public static void SetCredentials(string username, string password, string domain = null)
        {
            if (username.Contains("\\"))
            {
                string[] parts = username.Split('\\');
                CredentialDomain = parts[0];
                Username = parts[1];
            }
            else
            {
                Username = username;
                CredentialDomain = domain ?? DomainName;
            }
            Password = password;
            UseAlternateCredentials = true;
        }

        
        /// Check if we need credentials (not domain joined and no creds set)
        
        public static bool NeedsCredentials()
        {
            return !IsDomainJoined && !UseAlternateCredentials;
        }

        
        /// Ensure we have valid context - prompt for creds if needed
        
        public static bool EnsureContext(string targetDomain = null, string dcIp = null)
        {
            // Set target if provided
            if (!string.IsNullOrEmpty(targetDomain))
            {
                DomainName = targetDomain;
            }
            if (!string.IsNullOrEmpty(dcIp))
            {
                DcIp = dcIp;

                // Auto-set DNS to DC if not specified
                if (string.IsNullOrEmpty(DnsServer))
                {
                    DnsServer = dcIp;
                }
            }

            // If domain joined, we're good
            if (IsDomainJoined)
            {
                return true;
            }

            // Need domain specified
            if (string.IsNullOrEmpty(DomainName))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[!] Not domain-joined. Use /domain: to specify target.");
                Console.ResetColor();
                return false;
            }

            // Show target info
            string targetInfo = $"[*] Target: {DomainName}";
            if (!string.IsNullOrEmpty(DcIp))
                targetInfo += $" (DC: {DcIp})";
            Console.WriteLine(targetInfo);

            // If we already have credentials (from command line), show them and continue
            if (UseAlternateCredentials)
            {
                Console.WriteLine($"[*] Using credentials: {CredentialDomain}\\{Username}");
                if (!string.IsNullOrEmpty(DnsServer))
                {
                    Console.WriteLine($"[*] DNS Server: {DnsServer}");
                }
                return true;
            }

            // Need to prompt for credentials
            return PromptCredentials();
        }

        public static void ChangeContext()
        {
            Console.WriteLine("\n========== AUTHENTICATION CONTEXT ==========");
            Console.WriteLine("[1] Use current user context");
            Console.WriteLine("[2] Use alternate credentials");
            Console.Write("\nSelect an option: ");

            string choice = Console.ReadLine();

            if (choice == "2")
            {
                Console.Write("Enter domain\\username: ");
                string userInput = Console.ReadLine();

                Console.Write("Enter password: ");
                Password = ReadPassword();
                Console.WriteLine();

                if (userInput.Contains("\\"))
                {
                    string[] parts = userInput.Split('\\');
                    CredentialDomain = parts[0];
                    Username = parts[1];
                }
                else
                {
                    CredentialDomain = DomainName; // Use FQDN if no domain specified
                    Username = userInput;
                }

                UseAlternateCredentials = true;
                Console.WriteLine($"[+] Switched to alternate credentials: {CredentialDomain}\\{Username}");
                OutputHelper.Verbose($"[*] LDAP Path will use: {LdapProtocol}{DomainName}");
                OutputHelper.Verbose($"[*] Credentials: {CredentialDomain}\\{Username} (password length: {Password?.Length ?? 0})");
            }
            else
            {
                UseAlternateCredentials = false;
                Initialize();
                Console.WriteLine("[+] Switched back to current user context");
            }
        }

        
        /// Gets the LDAP server target - DC IP if specified, otherwise domain FQDN, or null for domain-joined default
        
        public static string GetLdapServer()
        {
            if (!string.IsNullOrEmpty(DcIp))
                return DcIp;
            if (!string.IsNullOrEmpty(DomainName))
                return DomainName;
            return null; // Let LDAP use default domain discovery
        }

        
        /// Get RootDSE entry - uses DC IP if specified
        
        public static DirectoryEntry GetRootDSE()
        {
            // If domain-joined and no alternate credentials and no LDAPS, let Windows handle it
            if (IsDomainJoined && !UseAlternateCredentials && string.IsNullOrEmpty(DcIp) && !UseLdaps)
            {
                OutputHelper.Verbose("[*] LDAP Path: LDAP://RootDSE (domain-joined, current user)");
                return new DirectoryEntry("LDAP://RootDSE");
            }

            string server = GetLdapServer();

            // LDAPS requires explicit server - use domain name if no DC IP specified
            if (UseLdaps && string.IsNullOrEmpty(server))
            {
                server = DomainName;
            }

            string ldapPath = string.IsNullOrEmpty(server) ? $"{LdapProtocol}RootDSE" : $"{LdapProtocol}{server}/RootDSE";

            OutputHelper.Verbose($"[*] LDAP Path: {ldapPath}" + (UseAlternateCredentials ? $" (as {Username})" : ""));

            DirectoryEntry entry;
            if (UseAlternateCredentials)
            {
                entry = new DirectoryEntry(ldapPath, Username, Password);
            }
            else
            {
                entry = new DirectoryEntry(ldapPath);
            }

            // For LDAPS, set authentication type
            if (UseLdaps)
            {
                entry.AuthenticationType = AuthenticationTypes.SecureSocketsLayer | AuthenticationTypes.Secure;
            }

            return entry;
        }

        public static DirectoryEntry GetDirectoryEntry()
        {
            // If domain-joined and no alternate credentials and no explicit DC and no LDAPS, let Windows handle it
            if (IsDomainJoined && !UseAlternateCredentials && string.IsNullOrEmpty(DcIp) && !UseLdaps)
            {
                return new DirectoryEntry($"LDAP://{DomainName}");
            }

            string server = GetLdapServer();

            // LDAPS requires explicit server - use domain name if no DC IP specified
            if (UseLdaps && string.IsNullOrEmpty(server))
            {
                server = DomainName;
            }

            string ldapPath = string.IsNullOrEmpty(server) ? $"{LdapProtocol}{DomainName}" : $"{LdapProtocol}{server}";

            DirectoryEntry entry;
            if (UseAlternateCredentials)
            {
                // Use just username - domain is inferred from LDAP path
                entry = new DirectoryEntry(ldapPath, Username, Password);
            }
            else
            {
                entry = new DirectoryEntry(ldapPath);
            }

            // For LDAPS, set authentication type
            if (UseLdaps)
            {
                entry.AuthenticationType = AuthenticationTypes.SecureSocketsLayer | AuthenticationTypes.Secure;
            }

            return entry;
        }

        public static DirectoryEntry GetDirectoryEntry(string path)
        {
            // If path needs a server, inject one (domain name for domain-joined, DC IP for external)
            if (path.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
            {
                string afterProtocol = path.Substring(7);

                // Check if path doesn't have a server (starts with CN=, DC=, OU=)
                if (afterProtocol.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ||
                    afterProtocol.StartsWith("DC=", StringComparison.OrdinalIgnoreCase) ||
                    afterProtocol.StartsWith("OU=", StringComparison.OrdinalIgnoreCase))
                {
                    // Need to inject a server
                    if (!string.IsNullOrEmpty(DcIp))
                    {
                        path = $"LDAP://{DcIp}/{afterProtocol}";
                    }
                    else if (!string.IsNullOrEmpty(DomainName))
                    {
                        path = $"LDAP://{DomainName}/{afterProtocol}";
                    }
                }
            }

            OutputHelper.Verbose($"[*] LDAP Path: {path}" + (UseLdaps ? " (SSL)" : ""));

            DirectoryEntry entry;
            if (UseAlternateCredentials)
            {
                entry = new DirectoryEntry(path, Username, Password);
            }
            else
            {
                entry = new DirectoryEntry(path);
            }

            // For LDAPS, set authentication type
            if (UseLdaps)
            {
                entry.AuthenticationType = AuthenticationTypes.SecureSocketsLayer | AuthenticationTypes.Secure;
            }

            return entry;
        }

        public static PrincipalContext GetPrincipalContext()
        {
            // Use DC IP if available, otherwise domain name
            string server = GetLdapServer() ?? DomainName;

            if (UseAlternateCredentials)
            {
                // PrincipalContext expects username without domain prefix when domain is specified
                return new PrincipalContext(ContextType.Domain, server, Username, Password);
            }
            else
            {
                return new PrincipalContext(ContextType.Domain, server);
            }
        }

        private static string ReadPassword()
        {
            // Show input so user can verify what they're typing
            return Console.ReadLine()?.Trim() ?? "";
        }
    }
}

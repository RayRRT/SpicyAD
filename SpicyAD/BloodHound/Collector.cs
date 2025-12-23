using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.Security.Principal;
using System.IO;

namespace SpicyAD.BloodHound
{
    /// <summary>
    /// Main orchestrator for BloodHound data collection
    /// </summary>
    public class Collector
    {
        private readonly CollectionMethod _methods;
        private readonly string _outputDir;
        private readonly bool _prettyPrint;
        private readonly string _zipName;
        private readonly int _threads;
        private readonly bool _stealth;

        private string _domainName;
        private string _domainSid;
        private string _domainDN;

        public Collector(
            CollectionMethod methods = CollectionMethod.Default,
            string outputDir = null,
            string zipName = null,
            bool prettyPrint = false,
            int threads = 10,
            bool stealth = false)
        {
            _methods = methods;
            // Normalize path - handle Windows paths properly
            if (!string.IsNullOrEmpty(outputDir))
            {
                _outputDir = Path.GetFullPath(outputDir);
            }
            else
            {
                _outputDir = Directory.GetCurrentDirectory();
            }
            _zipName = zipName;
            _prettyPrint = prettyPrint;
            _threads = threads;
            _stealth = stealth;
        }

        /// <summary>
        /// Run the collection
        /// </summary>
        public bool Run()
        {
            var stopwatch = Stopwatch.StartNew();

            PrintBanner();

            // Initialize domain context
            if (!InitializeDomainContext())
            {
                return false;
            }

            Console.WriteLine($"\n[*] Collection Methods: {_methods}");
            Console.WriteLine($"[*] Output Directory: {_outputDir}");
            Console.WriteLine();

            // Create JSON writer
            using (var writer = new JsonWriter(_outputDir, _prettyPrint, _methods))
            {
                // Create LDAP collector
                var ldapCollector = new LdapCollector(_domainName, _domainSid, _domainDN, _methods);

                // Collect in order
                Console.WriteLine("========================================");
                Console.WriteLine("[*] LDAP ENUMERATION");
                Console.WriteLine("========================================\n");

                // Domain first (for context)
                var domains = ldapCollector.CollectDomains();
                if (domains.Count > 0)
                {
                    writer.WriteDomains(domains);
                }

                // Users
                var users = ldapCollector.CollectUsers();
                if (users.Count > 0)
                {
                    writer.WriteUsers(users);
                }

                // Groups
                if ((_methods & CollectionMethod.Group) != 0)
                {
                    var groups = ldapCollector.CollectGroups();
                    if (groups.Count > 0)
                    {
                        writer.WriteGroups(groups);
                    }
                }

                // Computers (collect but don't write yet - sessions will be added)
                var computers = ldapCollector.CollectComputers();

                // OUs
                if ((_methods & CollectionMethod.Container) != 0)
                {
                    var ous = ldapCollector.CollectOUs();
                    if (ous.Count > 0)
                    {
                        writer.WriteOUs(ous);
                    }
                }

                // GPOs
                if ((_methods & CollectionMethod.Container) != 0)
                {
                    var gpos = ldapCollector.CollectGPOs();
                    if (gpos.Count > 0)
                    {
                        writer.WriteGPOs(gpos);
                    }
                }

                // Containers
                if ((_methods & CollectionMethod.Container) != 0)
                {
                    var containers = ldapCollector.CollectContainers();
                    if (containers.Count > 0)
                    {
                        writer.WriteContainers(containers);
                    }
                }

                // Certificate Templates (ADCS)
                if ((_methods & CollectionMethod.CertServices) != 0)
                {
                    var certTemplates = ldapCollector.CollectCertTemplates();
                    if (certTemplates.Count > 0)
                    {
                        writer.WriteCertTemplates(certTemplates);
                    }

                    var enterpriseCAs = ldapCollector.CollectEnterpriseCAs();
                    if (enterpriseCAs.Count > 0)
                    {
                        writer.WriteEnterpriseCAs(enterpriseCAs);
                    }
                }

                // Session collection (if requested and not stealth)
                if ((_methods & CollectionMethod.Session) != 0 && !_stealth && computers.Count > 0)
                {
                    Console.WriteLine("\n========================================");
                    Console.WriteLine("[*] SESSION ENUMERATION");
                    Console.WriteLine("========================================\n");

                    var sessionCollector = new SessionCollector(computers, _threads, _domainSid, _domainName);
                    sessionCollector.CollectSessions();
                }

                // Local group collection (if requested and not stealth)
                if ((_methods & CollectionMethod.LocalGroup) != 0 && !_stealth && computers.Count > 0)
                {
                    Console.WriteLine("\n========================================");
                    Console.WriteLine("[*] LOCAL GROUP ENUMERATION");
                    Console.WriteLine("========================================\n");

                    var localGroupCollector = new LocalGroupCollector(computers, _threads, _domainSid, _domainName);
                    localGroupCollector.CollectLocalGroups();
                }

                // Write computers (after session/local group collection)
                if (computers.Count > 0)
                {
                    writer.WriteComputers(computers);
                }

                // Create ZIP
                Console.WriteLine("\n========================================");
                Console.WriteLine("[*] FINALIZING OUTPUT");
                Console.WriteLine("========================================");
                Console.WriteLine($"\n[*] Total objects collected: {writer.TotalObjects}");

                string zipPath = writer.CreateZip(_zipName);

                stopwatch.Stop();

                // Summary
                Console.WriteLine();
                Console.WriteLine("========================================");
                Console.WriteLine("[*] COLLECTION COMPLETE");
                Console.WriteLine("========================================");
                Console.WriteLine($"[+] Duration: {stopwatch.Elapsed.TotalSeconds:F1} seconds");
                Console.WriteLine($"[+] Objects: {writer.TotalObjects}");
                if (!string.IsNullOrEmpty(zipPath))
                {
                    Console.WriteLine($"[+] Output: {zipPath}");
                    Console.WriteLine();
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[*] Import this file into BloodHound to analyze attack paths!");
                    Console.ResetColor();
                }
            }

            return true;
        }

        /// <summary>
        /// Initialize domain context - get domain name, SID, and DN
        /// </summary>
        private bool InitializeDomainContext()
        {
            Console.WriteLine("[*] Initializing domain context...");

            try
            {
                // Get RootDSE
                DirectoryEntry rootDse = AuthContext.GetRootDSE();

                // Get default naming context (domain DN)
                if (rootDse.Properties.Contains("defaultNamingContext"))
                {
                    _domainDN = rootDse.Properties["defaultNamingContext"][0].ToString();
                }
                else
                {
                    Console.WriteLine("[!] Could not get defaultNamingContext from RootDSE");
                    return false;
                }

                // Get domain name from AuthContext or convert DN
                _domainName = AuthContext.DomainName?.ToUpper();
                if (string.IsNullOrEmpty(_domainName))
                {
                    _domainName = ConvertDNToDomain(_domainDN)?.ToUpper();
                }

                if (string.IsNullOrEmpty(_domainName))
                {
                    Console.WriteLine("[!] Could not determine domain name");
                    return false;
                }

                // Get domain SID
                DirectoryEntry domainEntry = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(domainEntry);
                searcher.Filter = "(objectClass=domain)";
                searcher.PropertiesToLoad.Add("objectSid");

                SearchResult result = searcher.FindOne();
                if (result != null && result.Properties.Contains("objectSid"))
                {
                    byte[] sidBytes = result.Properties["objectSid"][0] as byte[];
                    if (sidBytes != null)
                    {
                        _domainSid = new SecurityIdentifier(sidBytes, 0).ToString();
                    }
                }

                if (string.IsNullOrEmpty(_domainSid))
                {
                    Console.WriteLine("[!] Could not get domain SID");
                    return false;
                }

                Console.WriteLine($"[+] Domain: {_domainName}");
                Console.WriteLine($"[+] Domain SID: {_domainSid}");
                OutputHelper.Verbose($"[+] Domain DN: {_domainDN}");

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error initializing domain context: {ex.Message}");
                return false;
            }
        }

        private string ConvertDNToDomain(string dn)
        {
            if (string.IsNullOrEmpty(dn))
                return null;

            var parts = new List<string>();
            foreach (string part in dn.Split(','))
            {
                if (part.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                {
                    parts.Add(part.Substring(3));
                }
            }
            return string.Join(".", parts);
        }

        private void PrintBanner()
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[*] SpicyAD BloodHound Ingestor v1.0");
            Console.ResetColor();
        }

        /// <summary>
        /// Parse collection method string to enum
        /// </summary>
        public static CollectionMethod ParseCollectionMethod(string methodStr)
        {
            if (string.IsNullOrEmpty(methodStr))
                return CollectionMethod.Default;

            methodStr = methodStr.ToLower().Trim();

            return methodStr switch
            {
                "default" => CollectionMethod.Default,
                "all" => CollectionMethod.All,
                "dconly" => CollectionMethod.DCOnly,
                "session" => CollectionMethod.Session,
                "localgroup" => CollectionMethod.LocalGroup,
                "group" => CollectionMethod.Group,
                "acl" => CollectionMethod.ACL,
                "trusts" => CollectionMethod.Trusts,
                "container" => CollectionMethod.Container,
                "computeronly" => CollectionMethod.ComputerOnly,
                "objectprops" => CollectionMethod.ObjectProps,
                "certservices" => CollectionMethod.CertServices,
                _ => ParseMultipleMethods(methodStr)
            };
        }

        private static CollectionMethod ParseMultipleMethods(string methodStr)
        {
            CollectionMethod result = CollectionMethod.None;

            foreach (string part in methodStr.Split(new[] { ',', '|', '+' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string trimmed = part.Trim().ToLower();
                CollectionMethod parsed = trimmed switch
                {
                    "group" => CollectionMethod.Group,
                    "localadmin" => CollectionMethod.LocalAdmin,
                    "session" => CollectionMethod.Session,
                    "trusts" => CollectionMethod.Trusts,
                    "acl" => CollectionMethod.ACL,
                    "container" => CollectionMethod.Container,
                    "rdp" => CollectionMethod.RDP,
                    "objectprops" => CollectionMethod.ObjectProps,
                    "dcom" => CollectionMethod.DCOM,
                    "spntargets" => CollectionMethod.SPNTargets,
                    "psremote" => CollectionMethod.PSRemote,
                    "certservices" => CollectionMethod.CertServices,
                    _ => CollectionMethod.None
                };
                result |= parsed;
            }

            return result == CollectionMethod.None ? CollectionMethod.Default : result;
        }

        /// <summary>
        /// Show help for BloodHound collection
        /// </summary>
        public static void ShowHelp()
        {
            Console.WriteLine(@"
BloodHound Ingestor - Collect AD data for BloodHound analysis

USAGE:
    SpicyAD.exe bloodhound [options]

OPTIONS:
    /collection:<method>    Collection method(s) to use
                           Default, All, DCOnly, Session, LocalGroup,
                           Group, ACL, Trusts, Container, ComputerOnly
                           Can combine with comma: Group,ACL,Session

    /outputdir:<path>       Output directory for files (default: current)
    /zipfilename:<name>     Custom name for output ZIP file
    /threads:<n>            Threads for session/local group enum (default: 10)
    /stealth                Skip session and local group enumeration
    /pretty                 Pretty-print JSON output (larger files)

EXAMPLES:
    SpicyAD.exe bloodhound
        Run default collection

    SpicyAD.exe bloodhound /collection:all
        Collect everything

    SpicyAD.exe bloodhound /collection:dconly /stealth
        Stealth mode - LDAP only, no computer enumeration

    SpicyAD.exe bloodhound /collection:session /threads:20
        Session enumeration with 20 threads

    SpicyAD.exe bloodhound /outputdir:C:\loot /zipfilename:target.zip
        Custom output location

COLLECTION METHODS:
    Default     = Group, Session, Trusts, ACL, ObjectProps, Container, LocalAdmin
    All         = All collection methods
    DCOnly      = Group, ACL, Trusts, ObjectProps, Container (no computer enum)
    Session     = Network session enumeration (NetSessionEnum)
    LocalGroup  = Local group membership (LocalAdmin, RDP, DCOM, PSRemote)
    Group       = Group membership enumeration
    ACL         = Access Control List collection
    Trusts      = Domain trust enumeration
    Container   = OU, GPO, and container enumeration
    ComputerOnly= Session and local group enum only
");
        }
    }
}

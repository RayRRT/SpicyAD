using System;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;

namespace SpicyAD
{
    public static class DomainOperations
    {
        public static void ChangeUserPassword(string targetUser = null, string oldPassword = null, string newPassword = null)
        {
            Console.WriteLine("[*] Change User Password\n");

            try
            {
                // Prompt for missing parameters
                if (string.IsNullOrEmpty(targetUser))
                {
                    Console.Write("Enter target username: ");
                    targetUser = Console.ReadLine();
                }

                if (string.IsNullOrEmpty(newPassword))
                {
                    Console.Write("Enter new password: ");
                    newPassword = ReadPassword();
                    Console.WriteLine();
                }

                // Find the user
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = $"(&(objectClass=user)(samAccountName={targetUser}))";
                searcher.PropertiesToLoad.Add("distinguishedName");

                SearchResult result = searcher.FindOne();

                if (result == null)
                {
                    Console.WriteLine($"[!] User {targetUser} not found.");
                    return;
                }

                string dn = result.Properties["distinguishedName"][0].ToString();
                Console.WriteLine($"[*] Target DN: {dn}");

                // Try to change the password
                try
                {
                    DirectoryEntry userEntry = AuthContext.GetDirectoryEntry($"LDAP://{dn}");

                    // Method 1: Using SetPassword (requires reset password permission)
                    try
                    {
                        userEntry.Invoke("SetPassword", new object[] { newPassword });
                        userEntry.CommitChanges();
                        Console.WriteLine($"[+] Successfully changed password for {targetUser}");
                    }
                    catch
                    {
                        // Method 2: Using ChangePassword (requires change password permission)
                        PrincipalContext ctx = AuthContext.GetPrincipalContext();
                        UserPrincipal user = UserPrincipal.FindByIdentity(ctx, targetUser);

                        if (user != null)
                        {
                            user.SetPassword(newPassword);
                            user.Save();
                            Console.WriteLine($"[+] Successfully changed password for {targetUser}");
                        }
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine($"[!] Access denied. You don't have permission to change the password for {targetUser}.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Error changing password: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        public static void AddMachineAccount(string machineName = null, string machinePassword = null)
        {
            Console.WriteLine("[*] Add Machine Account to Domain\n");

            try
            {
                // Prompt for missing parameters
                if (string.IsNullOrEmpty(machineName))
                {
                    Console.Write("Enter machine account name (without $): ");
                    machineName = Console.ReadLine();
                }

                if (!machineName.EndsWith("$"))
                {
                    machineName += "$";
                }

                if (string.IsNullOrEmpty(machinePassword))
                {
                    Console.Write("Enter machine password (leave empty for random): ");
                    machinePassword = ReadPassword();
                    Console.WriteLine();
                }

                if (string.IsNullOrEmpty(machinePassword))
                {
                    // Generate random password
                    machinePassword = GenerateRandomPassword(32);
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"[*] Generated random password: {machinePassword}");
                    Console.ResetColor();
                }

                // Check MachineAccountQuota
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(objectClass=domain)";
                searcher.PropertiesToLoad.Add("ms-DS-MachineAccountQuota");

                SearchResult result = searcher.FindOne();
                if (result != null && result.Properties.Contains("ms-DS-MachineAccountQuota"))
                {
                    int quota = (int)result.Properties["ms-DS-MachineAccountQuota"][0];
                    OutputHelper.Verbose($"[*] Machine Account Quota: {quota}");

                    if (quota == 0)
                    {
                        Console.WriteLine("[!] Machine Account Quota is 0. You may not be able to add a machine account.");
                    }
                }

                // Try to add the machine account
                try
                {
                    string computersDN = $"CN=Computers,{de.Properties["distinguishedName"][0]}";
                    DirectoryEntry computersOU = AuthContext.GetDirectoryEntry($"LDAP://{computersDN}");

                    DirectoryEntry newComputer = computersOU.Children.Add($"CN={machineName.TrimEnd('$')}", "computer");
                    newComputer.Properties["samAccountName"].Add(machineName);
                    newComputer.Properties["userAccountControl"].Add(0x1000); // WORKSTATION_TRUST_ACCOUNT
                    newComputer.Properties["dNSHostName"].Add($"{machineName.TrimEnd('$')}.{AuthContext.DomainName}");
                    newComputer.Properties["servicePrincipalName"].Add($"HOST/{machineName.TrimEnd('$')}");
                    newComputer.Properties["servicePrincipalName"].Add($"HOST/{machineName.TrimEnd('$')}.{AuthContext.DomainName}");

                    newComputer.CommitChanges();

                    // Set password
                    newComputer.Invoke("SetPassword", new object[] { machinePassword });
                    newComputer.CommitChanges();

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"[+] Successfully added machine account: {machineName}");
                    Console.WriteLine($"[+] Password: {machinePassword}");
                    Console.WriteLine($"[+] Machine DN: {newComputer.Properties["distinguishedName"][0]}");
                    Console.ResetColor();
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine("[!] Access denied. You don't have permission to add machine accounts or quota is 0.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Error adding machine account: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        public static void AddUserAccount(string username = null, string password = null, string fullName = null)
        {
            Console.WriteLine("[*] Add User Account to Domain\n");

            try
            {
                // Prompt for missing parameters
                if (string.IsNullOrEmpty(username))
                {
                    Console.Write("Enter username: ");
                    username = Console.ReadLine();
                }

                if (string.IsNullOrEmpty(password))
                {
                    Console.Write("Enter password: ");
                    password = ReadPassword();
                    Console.WriteLine();
                }

                if (string.IsNullOrEmpty(fullName))
                {
                    Console.Write("Enter full name (optional): ");
                    fullName = Console.ReadLine();
                }

                // Try to add the user account
                try
                {
                    PrincipalContext ctx = AuthContext.GetPrincipalContext();

                    UserPrincipal newUser = new UserPrincipal(ctx);
                    newUser.SamAccountName = username;
                    newUser.SetPassword(password);

                    if (!string.IsNullOrEmpty(fullName))
                    {
                        newUser.DisplayName = fullName;
                        newUser.Name = fullName;
                    }
                    else
                    {
                        newUser.Name = username;
                    }

                    newUser.Enabled = true;
                    newUser.Save();

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"[+] Successfully added user account: {username}");
                    Console.WriteLine($"[+] User DN: {newUser.DistinguishedName}");
                    Console.ResetColor();
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine("[!] Access denied. You don't have permission to add user accounts.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Error adding user account: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        public static void DeleteUserAccount()
        {
            Console.WriteLine("[*] Delete User Account from Domain\n");

            try
            {
                Console.Write("Enter username to delete: ");
                string username = Console.ReadLine()?.Trim();

                if (string.IsNullOrEmpty(username))
                {
                    Console.WriteLine("[!] Username is required.");
                    return;
                }

                // Find the user
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = $"(&(objectClass=user)(samAccountName={username}))";
                searcher.PropertiesToLoad.Add("distinguishedName");
                searcher.PropertiesToLoad.Add("memberOf");

                SearchResult result = searcher.FindOne();

                if (result == null)
                {
                    Console.WriteLine($"[!] User {username} not found.");
                    return;
                }

                string userDN = result.Properties["distinguishedName"][0].ToString();
                Console.WriteLine($"[*] Found user: {userDN}");

                // Show group memberships
                if (result.Properties.Contains("memberOf") && result.Properties["memberOf"].Count > 0)
                {
                    Console.WriteLine($"[*] User is member of {result.Properties["memberOf"].Count} group(s)");
                }

                // Confirm deletion
                Console.Write($"\n[?] Are you sure you want to delete user '{username}'? (y/n): ");
                string confirm = Console.ReadLine()?.Trim().ToLower();

                if (confirm != "y" && confirm != "yes")
                {
                    Console.WriteLine("[*] Operation cancelled.");
                    return;
                }

                // Delete the user
                try
                {
                    DirectoryEntry userEntry = AuthContext.GetDirectoryEntry($"LDAP://{userDN}");
                    userEntry.DeleteTree();

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"[+] Successfully deleted user: {username}");
                    Console.ResetColor();
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine("[!] Access denied. You don't have permission to delete this user.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Error deleting user: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        public static void DeleteUserAccount(string username, bool skipConfirm = false)
        {
            Console.WriteLine($"[*] Deleting user: {username}");

            try
            {
                // Find the user
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = $"(&(objectClass=user)(samAccountName={username}))";
                searcher.PropertiesToLoad.Add("distinguishedName");

                SearchResult result = searcher.FindOne();

                if (result == null)
                {
                    Console.WriteLine($"[!] User {username} not found.");
                    return;
                }

                string userDN = result.Properties["distinguishedName"][0].ToString();

                if (!skipConfirm)
                {
                    Console.Write($"[?] Are you sure you want to delete user '{username}'? (y/n): ");
                    string confirm = Console.ReadLine()?.Trim().ToLower();

                    if (confirm != "y" && confirm != "yes")
                    {
                        Console.WriteLine("[*] Operation cancelled.");
                        return;
                    }
                }

                // Delete the user
                DirectoryEntry userEntry = AuthContext.GetDirectoryEntry($"LDAP://{userDN}");
                userEntry.DeleteTree();

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] Successfully deleted user: {username}");
                Console.ResetColor();
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("[!] Access denied. You don't have permission to delete this user.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error deleting user: {ex.Message}");
            }
        }

        private static string ReadPassword()
        {
            // Show input so user can verify what they're typing
            return Console.ReadLine()?.Trim() ?? "";
        }

        private static string GenerateRandomPassword(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
            Random random = new Random();
            char[] password = new char[length];

            for (int i = 0; i < length; i++)
            {
                password[i] = chars[random.Next(chars.Length)];
            }

            return new string(password);
        }

        
        /// Add a user to a domain group
        public static void AddUserToGroup()
        {
            Console.WriteLine("[*] Add User to Domain Group\n");

            try
            {
                Console.Write("Enter username to add: ");
                string username = Console.ReadLine()?.Trim();

                Console.Write("Enter group name: ");
                string groupName = Console.ReadLine()?.Trim();

                if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(groupName))
                {
                    Console.WriteLine("[!] Username and group name are required.");
                    return;
                }

                AddUserToGroup(username, groupName);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        
        /// Add a user to a domain group (programmatic)
        public static void AddUserToGroup(string username, string groupName)
        {
            Console.WriteLine($"[*] Adding {username} to group {groupName}");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);

                // Find the user
                searcher.Filter = $"(&(objectClass=user)(samAccountName={username}))";
                searcher.PropertiesToLoad.Add("distinguishedName");
                SearchResult userResult = searcher.FindOne();

                if (userResult == null)
                {
                    Console.WriteLine($"[!] User {username} not found.");
                    return;
                }

                string userDN = userResult.Properties["distinguishedName"][0].ToString();
                OutputHelper.Verbose($"[*] User DN: {userDN}");

                // Find the group
                searcher.Filter = $"(&(objectClass=group)(samAccountName={groupName}))";
                searcher.PropertiesToLoad.Add("distinguishedName");
                SearchResult groupResult = searcher.FindOne();

                if (groupResult == null)
                {
                    // Try with CN
                    searcher.Filter = $"(&(objectClass=group)(cn={groupName}))";
                    groupResult = searcher.FindOne();
                }

                if (groupResult == null)
                {
                    Console.WriteLine($"[!] Group {groupName} not found.");
                    return;
                }

                string groupDN = groupResult.Properties["distinguishedName"][0].ToString();
                OutputHelper.Verbose($"[*] Group DN: {groupDN}");

                // Add user to group
                DirectoryEntry groupEntry = AuthContext.GetDirectoryEntry($"LDAP://{groupDN}");
                groupEntry.Properties["member"].Add(userDN);
                groupEntry.CommitChanges();

                Console.WriteLine($"[+] Successfully added {username} to {groupName}");
            }
            catch (System.Runtime.InteropServices.COMException ex) when (ex.Message.Contains("already a member"))
            {
                Console.WriteLine($"[!] User {username} is already a member of {groupName}");
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine($"[!] Access denied. You don't have permission to modify this group.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error adding user to group: {ex.Message}");
            }
        }

        
        /// Remove a user from a domain group
        public static void RemoveUserFromGroup(string username, string groupName)
        {
            Console.WriteLine($"[*] Removing {username} from group {groupName}");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);

                // Find the user
                searcher.Filter = $"(&(objectClass=user)(samAccountName={username}))";
                searcher.PropertiesToLoad.Add("distinguishedName");
                SearchResult userResult = searcher.FindOne();

                if (userResult == null)
                {
                    Console.WriteLine($"[!] User {username} not found.");
                    return;
                }

                string userDN = userResult.Properties["distinguishedName"][0].ToString();

                // Find the group
                searcher.Filter = $"(&(objectClass=group)(samAccountName={groupName}))";
                searcher.PropertiesToLoad.Add("distinguishedName");
                SearchResult groupResult = searcher.FindOne();

                if (groupResult == null)
                {
                    Console.WriteLine($"[!] Group {groupName} not found.");
                    return;
                }

                string groupDN = groupResult.Properties["distinguishedName"][0].ToString();

                // Remove user from group
                DirectoryEntry groupEntry = AuthContext.GetDirectoryEntry($"LDAP://{groupDN}");
                groupEntry.Properties["member"].Remove(userDN);
                groupEntry.CommitChanges();

                Console.WriteLine($"[+] Successfully removed {username} from {groupName}");
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine($"[!] Access denied. You don't have permission to modify this group.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error removing user from group: {ex.Message}");
            }
        }
    }
}

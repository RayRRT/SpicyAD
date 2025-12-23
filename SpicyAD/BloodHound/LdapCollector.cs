using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;
using System.Linq;

namespace SpicyAD.BloodHound
{
    /// <summary>
    /// Collects Active Directory objects via LDAP for BloodHound
    /// </summary>
    public class LdapCollector
    {
        private readonly AclProcessor _aclProcessor;
        private readonly string _domainName;
        private readonly string _domainSid;
        private readonly string _domainDN;
        private readonly CollectionMethod _methods;

        // Cache for object lookups
        private readonly Dictionary<string, string> _dnToSid = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, PrincipalType> _sidToType = new Dictionary<string, PrincipalType>();

        public LdapCollector(string domainName, string domainSid, string domainDN, CollectionMethod methods)
        {
            _domainName = domainName?.ToUpper();
            _domainSid = domainSid;
            _domainDN = domainDN;
            _methods = methods;
            _aclProcessor = new AclProcessor(domainSid, domainName);
        }

        #region Users

        /// <summary>
        /// Collect all domain users
        /// </summary>
        public List<BloodHoundUser> CollectUsers()
        {
            var users = new List<BloodHoundUser>();
            Console.WriteLine("[*] Collecting Users...");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(&(objectClass=user)(objectCategory=person))";
                searcher.PageSize = 1000;
                searcher.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;

                // Properties to load
                searcher.PropertiesToLoad.AddRange(new string[]
                {
                    "samAccountName", "distinguishedName", "objectSid", "objectGuid",
                    "userAccountControl", "servicePrincipalName", "memberOf",
                    "pwdLastSet", "lastLogonTimestamp", "lastLogon", "whenCreated",
                    "adminCount", "description", "displayName", "mail", "title",
                    "homeDirectory", "scriptPath", "userPassword", "unixUserPassword",
                    "msDS-AllowedToDelegateTo", "sIDHistory", "primaryGroupID",
                    "nTSecurityDescriptor"
                });

                SearchResultCollection results = searcher.FindAll();
                int count = 0;

                foreach (SearchResult result in results)
                {
                    try
                    {
                        var user = ProcessUser(result);
                        if (user != null)
                        {
                            users.Add(user);
                            count++;

                            // Cache for ACL resolution
                            CacheObject(user.ObjectIdentifier, user.Properties.DistinguishedName, PrincipalType.User);
                        }
                    }
                    catch (Exception ex)
                    {
                        OutputHelper.Verbose($"[!] Error processing user: {ex.Message}");
                    }
                }

                OutputHelper.Verbose($"    Processed {count} users");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error collecting users: {ex.Message}");
            }

            return users;
        }

        private BloodHoundUser ProcessUser(SearchResult result)
        {
            string sid = GetSidString(result, "objectSid");
            if (string.IsNullOrEmpty(sid))
                return null;

            string samAccountName = GetStringProperty(result, "samAccountName");
            string dn = GetStringProperty(result, "distinguishedName");
            int uac = GetIntProperty(result, "userAccountControl");
            int primaryGroupId = GetIntProperty(result, "primaryGroupID", 513);

            var user = new BloodHoundUser
            {
                ObjectIdentifier = sid,
                PrimaryGroupSID = $"{_domainSid}-{primaryGroupId}",
                Properties = new UserProperties
                {
                    Domain = _domainName,
                    Name = $"{samAccountName}@{_domainName}".ToUpper(),
                    DistinguishedName = dn,
                    SamAccountName = samAccountName,
                    Description = GetStringProperty(result, "description"),
                    DisplayName = GetStringProperty(result, "displayName"),
                    Email = GetStringProperty(result, "mail"),
                    Title = GetStringProperty(result, "title"),
                    HomeDirectory = GetStringProperty(result, "homeDirectory"),
                    LogonScript = GetStringProperty(result, "scriptPath"),

                    // Timestamps
                    WhenCreated = GetTimestamp(result, "whenCreated"),
                    LastLogon = GetFileTimeTimestamp(result, "lastLogon"),
                    LastLogonTimestamp = GetFileTimeTimestamp(result, "lastLogonTimestamp"),
                    PwdLastSet = GetFileTimeTimestamp(result, "pwdLastSet"),

                    // UAC flags
                    Enabled = (uac & (int)UACFlags.ACCOUNTDISABLE) == 0,
                    DontReqPreauth = (uac & (int)UACFlags.DONT_REQ_PREAUTH) != 0,
                    PasswordNotReqd = (uac & (int)UACFlags.PASSWD_NOTREQD) != 0,
                    UnconstrainedDelegation = (uac & (int)UACFlags.TRUSTED_FOR_DELEGATION) != 0,
                    TrustedToAuth = (uac & (int)UACFlags.TRUSTED_TO_AUTH_FOR_DELEGATION) != 0,
                    Sensitive = (uac & (int)UACFlags.NOT_DELEGATED) != 0,

                    // SPNs
                    HasSPN = result.Properties.Contains("servicePrincipalName") &&
                             result.Properties["servicePrincipalName"].Count > 0,
                    ServicePrincipalNames = GetStringList(result, "servicePrincipalName"),

                    // Admin count
                    AdminCount = GetIntProperty(result, "adminCount") == 1,

                    // SID History
                    SidHistory = GetSidHistoryList(result)
                }
            };

            // Constrained delegation targets
            if (result.Properties.Contains("msDS-AllowedToDelegateTo"))
            {
                foreach (var target in result.Properties["msDS-AllowedToDelegateTo"])
                {
                    user.AllowedToDelegate.Add(new TypedPrincipal
                    {
                        ObjectIdentifier = target.ToString(),
                        ObjectType = "Computer"  // SPNs target computers
                    });
                }
            }

            // ACLs
            if ((_methods & CollectionMethod.ACL) != 0)
            {
                byte[] sd = GetByteArrayProperty(result, "nTSecurityDescriptor");
                if (sd != null)
                {
                    user.Aces = _aclProcessor.ProcessAcl(sd, "user");
                    user.IsACLProtected = _aclProcessor.IsAclProtected(sd);
                }
            }

            return user;
        }

        #endregion

        #region Computers

        /// <summary>
        /// Collect all domain computers
        /// </summary>
        public List<BloodHoundComputer> CollectComputers()
        {
            var computers = new List<BloodHoundComputer>();
            Console.WriteLine("[*] Collecting Computers...");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(objectClass=computer)";
                searcher.PageSize = 1000;
                searcher.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;

                searcher.PropertiesToLoad.AddRange(new string[]
                {
                    "samAccountName", "distinguishedName", "objectSid", "objectGuid",
                    "dNSHostName", "userAccountControl", "operatingSystem",
                    "operatingSystemVersion", "servicePrincipalName",
                    "pwdLastSet", "lastLogonTimestamp", "lastLogon", "whenCreated",
                    "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
                    "ms-Mcs-AdmPwd", "msLAPS-Password", "sIDHistory", "primaryGroupID",
                    "nTSecurityDescriptor", "description"
                });

                SearchResultCollection results = searcher.FindAll();
                int count = 0;

                foreach (SearchResult result in results)
                {
                    try
                    {
                        var computer = ProcessComputer(result);
                        if (computer != null)
                        {
                            computers.Add(computer);
                            count++;

                            // Cache for ACL resolution
                            CacheObject(computer.ObjectIdentifier, computer.Properties.DistinguishedName, PrincipalType.Computer);
                        }
                    }
                    catch (Exception ex)
                    {
                        OutputHelper.Verbose($"[!] Error processing computer: {ex.Message}");
                    }
                }

                OutputHelper.Verbose($"    Processed {count} computers");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error collecting computers: {ex.Message}");
            }

            return computers;
        }

        private BloodHoundComputer ProcessComputer(SearchResult result)
        {
            string sid = GetSidString(result, "objectSid");
            if (string.IsNullOrEmpty(sid))
                return null;

            string samAccountName = GetStringProperty(result, "samAccountName")?.TrimEnd('$');
            string dn = GetStringProperty(result, "distinguishedName");
            int uac = GetIntProperty(result, "userAccountControl");
            int primaryGroupId = GetIntProperty(result, "primaryGroupID", 515);

            // Check if Domain Controller
            bool isDC = (uac & (int)UACFlags.SERVER_TRUST_ACCOUNT) != 0 ||
                        primaryGroupId == 516 || primaryGroupId == 521;

            var computer = new BloodHoundComputer
            {
                ObjectIdentifier = sid,
                PrimaryGroupSID = $"{_domainSid}-{primaryGroupId}",
                IsDC = isDC,
                Properties = new ComputerProperties
                {
                    Domain = _domainName,
                    Name = $"{samAccountName}.{_domainName}".ToUpper(),
                    DistinguishedName = dn,
                    SamAccountName = samAccountName,
                    Description = GetStringProperty(result, "description"),
                    OperatingSystem = GetStringProperty(result, "operatingSystem"),

                    // Timestamps
                    WhenCreated = GetTimestamp(result, "whenCreated"),
                    LastLogon = GetFileTimeTimestamp(result, "lastLogon"),
                    LastLogonTimestamp = GetFileTimeTimestamp(result, "lastLogonTimestamp"),
                    PwdLastSet = GetFileTimeTimestamp(result, "pwdLastSet"),

                    // UAC flags
                    Enabled = (uac & (int)UACFlags.ACCOUNTDISABLE) == 0,
                    UnconstrainedDelegation = (uac & (int)UACFlags.TRUSTED_FOR_DELEGATION) != 0 && !isDC,
                    TrustedToAuth = (uac & (int)UACFlags.TRUSTED_TO_AUTH_FOR_DELEGATION) != 0,

                    // LAPS
                    HasLaps = result.Properties.Contains("ms-Mcs-AdmPwd") ||
                              result.Properties.Contains("msLAPS-Password"),

                    // SPNs
                    ServicePrincipalNames = GetStringList(result, "servicePrincipalName"),

                    // SID History
                    SidHistory = GetSidHistoryList(result)
                }
            };

            // Constrained delegation targets
            if (result.Properties.Contains("msDS-AllowedToDelegateTo"))
            {
                foreach (var target in result.Properties["msDS-AllowedToDelegateTo"])
                {
                    computer.AllowedToDelegate.Add(new TypedPrincipal
                    {
                        ObjectIdentifier = target.ToString(),
                        ObjectType = "Computer"
                    });
                }
            }

            // RBCD - AllowedToAct
            if (result.Properties.Contains("msDS-AllowedToActOnBehalfOfOtherIdentity"))
            {
                byte[] rbcdBytes = GetByteArrayProperty(result, "msDS-AllowedToActOnBehalfOfOtherIdentity");
                if (rbcdBytes != null)
                {
                    computer.AllowedToAct = ParseRbcdDescriptor(rbcdBytes);
                }
            }

            // Initialize collection status (will be filled by SessionCollector)
            computer.Sessions = new ResultStatus<List<SessionInfo>> { Collected = false };
            computer.LocalAdmins = new ResultStatus<List<LocalGroupMember>> { Collected = false };
            computer.RemoteDesktopUsers = new ResultStatus<List<LocalGroupMember>> { Collected = false };
            computer.DcomUsers = new ResultStatus<List<LocalGroupMember>> { Collected = false };
            computer.PSRemoteUsers = new ResultStatus<List<LocalGroupMember>> { Collected = false };

            // ACLs
            if ((_methods & CollectionMethod.ACL) != 0)
            {
                byte[] sd = GetByteArrayProperty(result, "nTSecurityDescriptor");
                if (sd != null)
                {
                    computer.Aces = _aclProcessor.ProcessAcl(sd, "computer");
                    computer.IsACLProtected = _aclProcessor.IsAclProtected(sd);
                }
            }

            return computer;
        }

        private List<TypedPrincipal> ParseRbcdDescriptor(byte[] rbcdBytes)
        {
            var result = new List<TypedPrincipal>();

            try
            {
                var sd = new System.Security.AccessControl.RawSecurityDescriptor(rbcdBytes, 0);
                if (sd.DiscretionaryAcl != null)
                {
                    foreach (var ace in sd.DiscretionaryAcl)
                    {
                        if (ace is System.Security.AccessControl.CommonAce commonAce)
                        {
                            string sid = commonAce.SecurityIdentifier.ToString();
                            result.Add(new TypedPrincipal
                            {
                                ObjectIdentifier = sid,
                                ObjectType = _aclProcessor.GetPrincipalType(sid).ToString()
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                OutputHelper.Verbose($"[!] Error parsing RBCD descriptor: {ex.Message}");
            }

            return result;
        }

        #endregion

        #region Groups

        /// <summary>
        /// Collect all domain groups
        /// </summary>
        public List<BloodHoundGroup> CollectGroups()
        {
            var groups = new List<BloodHoundGroup>();
            Console.WriteLine("[*] Collecting Groups...");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(objectClass=group)";
                searcher.PageSize = 1000;
                searcher.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;

                searcher.PropertiesToLoad.AddRange(new string[]
                {
                    "samAccountName", "distinguishedName", "objectSid", "objectGuid",
                    "member", "adminCount", "description", "whenCreated",
                    "nTSecurityDescriptor"
                });

                SearchResultCollection results = searcher.FindAll();
                int count = 0;

                foreach (SearchResult result in results)
                {
                    try
                    {
                        var group = ProcessGroup(result);
                        if (group != null)
                        {
                            groups.Add(group);
                            count++;

                            // Cache for ACL resolution
                            CacheObject(group.ObjectIdentifier, group.Properties.DistinguishedName, PrincipalType.Group);
                        }
                    }
                    catch (Exception ex)
                    {
                        OutputHelper.Verbose($"[!] Error processing group: {ex.Message}");
                    }
                }

                OutputHelper.Verbose($"    Processed {count} groups");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error collecting groups: {ex.Message}");
            }

            return groups;
        }

        private BloodHoundGroup ProcessGroup(SearchResult result)
        {
            string sid = GetSidString(result, "objectSid");
            if (string.IsNullOrEmpty(sid))
                return null;

            string samAccountName = GetStringProperty(result, "samAccountName");
            string dn = GetStringProperty(result, "distinguishedName");

            var group = new BloodHoundGroup
            {
                ObjectIdentifier = sid,
                Properties = new GroupProperties
                {
                    Domain = _domainName,
                    Name = $"{samAccountName}@{_domainName}".ToUpper(),
                    DistinguishedName = dn,
                    SamAccountName = samAccountName,
                    Description = GetStringProperty(result, "description"),
                    WhenCreated = GetTimestamp(result, "whenCreated"),
                    AdminCount = GetIntProperty(result, "adminCount") == 1
                }
            };

            // Group members - will be resolved to SIDs
            if (result.Properties.Contains("member") && (_methods & CollectionMethod.Group) != 0)
            {
                foreach (var memberDn in result.Properties["member"])
                {
                    string memberDnStr = memberDn.ToString();
                    // Member resolution happens later - for now just add DN
                    // We'll need to look up SIDs for members
                    var member = ResolveMember(memberDnStr);
                    if (member != null)
                    {
                        group.Members.Add(member);
                    }
                }
            }

            // ACLs
            if ((_methods & CollectionMethod.ACL) != 0)
            {
                byte[] sd = GetByteArrayProperty(result, "nTSecurityDescriptor");
                if (sd != null)
                {
                    group.Aces = _aclProcessor.ProcessAcl(sd, "group");
                    group.IsACLProtected = _aclProcessor.IsAclProtected(sd);
                }
            }

            return group;
        }

        private GroupMember ResolveMember(string memberDn)
        {
            // First check cache
            if (_dnToSid.TryGetValue(memberDn, out string cachedSid))
            {
                _sidToType.TryGetValue(cachedSid, out PrincipalType cachedType);
                return new GroupMember
                {
                    ObjectIdentifier = cachedSid,
                    ObjectType = cachedType.ToString()
                };
            }

            // Look up the member
            try
            {
                DirectoryEntry memberEntry = AuthContext.GetDirectoryEntry($"LDAP://{memberDn}");
                if (memberEntry.Properties.Contains("objectSid"))
                {
                    byte[] sidBytes = memberEntry.Properties["objectSid"][0] as byte[];
                    if (sidBytes != null)
                    {
                        string sid = new SecurityIdentifier(sidBytes, 0).ToString();
                        PrincipalType type = DetermineObjectType(memberEntry);

                        CacheObject(sid, memberDn, type);

                        return new GroupMember
                        {
                            ObjectIdentifier = sid,
                            ObjectType = type.ToString()
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                OutputHelper.Verbose($"[!] Could not resolve member {memberDn}: {ex.Message}");
            }

            return null;
        }

        private PrincipalType DetermineObjectType(DirectoryEntry entry)
        {
            if (!entry.Properties.Contains("objectClass"))
                return PrincipalType.Unknown;

            foreach (var objClass in entry.Properties["objectClass"])
            {
                string className = objClass.ToString().ToLower();
                if (className == "computer")
                    return PrincipalType.Computer;
                if (className == "group")
                    return PrincipalType.Group;
                if (className == "user")
                    return PrincipalType.User;
            }

            return PrincipalType.Unknown;
        }

        #endregion

        #region Domains

        /// <summary>
        /// Collect domain info and trusts
        /// </summary>
        public List<BloodHoundDomain> CollectDomains()
        {
            var domains = new List<BloodHoundDomain>();
            Console.WriteLine("[*] Collecting Domain...");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(objectClass=domain)";
                searcher.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;

                searcher.PropertiesToLoad.AddRange(new string[]
                {
                    "distinguishedName", "objectSid", "objectGuid",
                    "msDS-Behavior-Version", "description", "whenCreated",
                    "nTSecurityDescriptor", "gpLink"
                });

                SearchResult result = searcher.FindOne();
                if (result != null)
                {
                    var domain = ProcessDomain(result);
                    if (domain != null)
                    {
                        // Collect trusts
                        if ((_methods & CollectionMethod.Trusts) != 0)
                        {
                            domain.Trusts = CollectTrusts();
                        }

                        domains.Add(domain);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error collecting domain: {ex.Message}");
            }

            return domains;
        }

        private BloodHoundDomain ProcessDomain(SearchResult result)
        {
            string sid = GetSidString(result, "objectSid");
            if (string.IsNullOrEmpty(sid))
                return null;

            string dn = GetStringProperty(result, "distinguishedName");
            int funcLevel = GetIntProperty(result, "msDS-Behavior-Version");

            var domain = new BloodHoundDomain
            {
                ObjectIdentifier = sid,
                Properties = new DomainProperties
                {
                    Domain = _domainName,
                    Name = _domainName,
                    DistinguishedName = dn,
                    DomainSid = sid,
                    Description = GetStringProperty(result, "description"),
                    WhenCreated = GetTimestamp(result, "whenCreated"),
                    FunctionalLevel = GetFunctionalLevelName(funcLevel),
                    HighValue = true
                }
            };

            // GPO Links
            string gpLink = GetStringProperty(result, "gpLink");
            if (!string.IsNullOrEmpty(gpLink))
            {
                domain.Links = ParseGpLink(gpLink);
            }

            // ACLs
            if ((_methods & CollectionMethod.ACL) != 0)
            {
                byte[] sd = GetByteArrayProperty(result, "nTSecurityDescriptor");
                if (sd != null)
                {
                    domain.Aces = _aclProcessor.ProcessAcl(sd, "domain");
                    domain.IsACLProtected = _aclProcessor.IsAclProtected(sd);
                }
            }

            return domain;
        }

        private List<DomainTrust> CollectTrusts()
        {
            var trusts = new List<DomainTrust>();

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(objectClass=trustedDomain)";
                searcher.PageSize = 1000;

                searcher.PropertiesToLoad.AddRange(new string[]
                {
                    "name", "trustDirection", "trustType", "trustAttributes",
                    "securityIdentifier", "flatName"
                });

                SearchResultCollection results = searcher.FindAll();

                foreach (SearchResult result in results)
                {
                    try
                    {
                        string targetName = GetStringProperty(result, "name");
                        string targetSid = GetSidString(result, "securityIdentifier");
                        int direction = GetIntProperty(result, "trustDirection");
                        int trustType = GetIntProperty(result, "trustType");
                        int attrs = GetIntProperty(result, "trustAttributes");

                        var trust = new DomainTrust
                        {
                            TargetDomainName = targetName?.ToUpper(),
                            TargetDomainSid = targetSid,
                            TrustDirection = GetTrustDirection(direction),
                            TrustType = GetTrustType(trustType, attrs),
                            IsTransitive = (attrs & 0x1) != 0, // TRUST_ATTRIBUTE_NON_TRANSITIVE = 0
                            SidFilteringEnabled = (attrs & 0x4) != 0 // TRUST_ATTRIBUTE_QUARANTINED_DOMAIN
                        };

                        trusts.Add(trust);
                    }
                    catch (Exception ex)
                    {
                        OutputHelper.Verbose($"[!] Error processing trust: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                OutputHelper.Verbose($"[!] Error collecting trusts: {ex.Message}");
            }

            return trusts;
        }

        #endregion

        #region OUs

        /// <summary>
        /// Collect Organizational Units
        /// </summary>
        public List<BloodHoundOU> CollectOUs()
        {
            var ous = new List<BloodHoundOU>();
            Console.WriteLine("[*] Collecting OUs...");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(objectClass=organizationalUnit)";
                searcher.PageSize = 1000;
                searcher.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;

                searcher.PropertiesToLoad.AddRange(new string[]
                {
                    "name", "distinguishedName", "objectGuid",
                    "description", "whenCreated", "gpLink", "gpOptions",
                    "nTSecurityDescriptor"
                });

                SearchResultCollection results = searcher.FindAll();
                int count = 0;

                foreach (SearchResult result in results)
                {
                    try
                    {
                        var ou = ProcessOU(result);
                        if (ou != null)
                        {
                            ous.Add(ou);
                            count++;
                        }
                    }
                    catch (Exception ex)
                    {
                        OutputHelper.Verbose($"[!] Error processing OU: {ex.Message}");
                    }
                }

                OutputHelper.Verbose($"    Processed {count} OUs");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error collecting OUs: {ex.Message}");
            }

            return ous;
        }

        private BloodHoundOU ProcessOU(SearchResult result)
        {
            string guid = GetGuidString(result, "objectGuid");
            if (string.IsNullOrEmpty(guid))
                return null;

            string dn = GetStringProperty(result, "distinguishedName");
            string name = GetStringProperty(result, "name");
            int gpOptions = GetIntProperty(result, "gpOptions");

            var ou = new BloodHoundOU
            {
                ObjectIdentifier = guid,
                Properties = new OUProperties
                {
                    Domain = _domainName,
                    Name = $"{name}@{_domainName}".ToUpper(),
                    DistinguishedName = dn,
                    Description = GetStringProperty(result, "description"),
                    WhenCreated = GetTimestamp(result, "whenCreated"),
                    BlocksInheritance = (gpOptions & 1) != 0
                }
            };

            // GPO Links
            string gpLink = GetStringProperty(result, "gpLink");
            if (!string.IsNullOrEmpty(gpLink))
            {
                ou.Links = ParseGpLink(gpLink);
            }

            // ACLs
            if ((_methods & CollectionMethod.ACL) != 0)
            {
                byte[] sd = GetByteArrayProperty(result, "nTSecurityDescriptor");
                if (sd != null)
                {
                    ou.Aces = _aclProcessor.ProcessAcl(sd, "ou");
                    ou.IsACLProtected = _aclProcessor.IsAclProtected(sd);
                }
            }

            return ou;
        }

        #endregion

        #region GPOs

        /// <summary>
        /// Collect Group Policy Objects
        /// </summary>
        public List<BloodHoundGPO> CollectGPOs()
        {
            var gpos = new List<BloodHoundGPO>();
            Console.WriteLine("[*] Collecting GPOs...");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(objectClass=groupPolicyContainer)";
                searcher.PageSize = 1000;
                searcher.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;

                searcher.PropertiesToLoad.AddRange(new string[]
                {
                    "displayName", "distinguishedName", "objectGuid",
                    "description", "whenCreated", "gPCFileSysPath",
                    "nTSecurityDescriptor"
                });

                SearchResultCollection results = searcher.FindAll();
                int count = 0;

                foreach (SearchResult result in results)
                {
                    try
                    {
                        var gpo = ProcessGPO(result);
                        if (gpo != null)
                        {
                            gpos.Add(gpo);
                            count++;
                        }
                    }
                    catch (Exception ex)
                    {
                        OutputHelper.Verbose($"[!] Error processing GPO: {ex.Message}");
                    }
                }

                OutputHelper.Verbose($"    Processed {count} GPOs");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error collecting GPOs: {ex.Message}");
            }

            return gpos;
        }

        private BloodHoundGPO ProcessGPO(SearchResult result)
        {
            string guid = GetGuidString(result, "objectGuid");
            if (string.IsNullOrEmpty(guid))
                return null;

            string dn = GetStringProperty(result, "distinguishedName");
            string displayName = GetStringProperty(result, "displayName");
            string gpcPath = GetStringProperty(result, "gPCFileSysPath");

            var gpo = new BloodHoundGPO
            {
                ObjectIdentifier = guid,
                Properties = new GPOProperties
                {
                    Domain = _domainName,
                    Name = $"{displayName}@{_domainName}".ToUpper(),
                    DistinguishedName = dn,
                    Description = GetStringProperty(result, "description"),
                    WhenCreated = GetTimestamp(result, "whenCreated"),
                    GpcPath = gpcPath
                }
            };

            // ACLs
            if ((_methods & CollectionMethod.ACL) != 0)
            {
                byte[] sd = GetByteArrayProperty(result, "nTSecurityDescriptor");
                if (sd != null)
                {
                    gpo.Aces = _aclProcessor.ProcessAcl(sd, "gpo");
                    gpo.IsACLProtected = _aclProcessor.IsAclProtected(sd);
                }
            }

            return gpo;
        }

        #endregion

        #region Containers

        /// <summary>
        /// Collect Containers
        /// </summary>
        public List<BloodHoundContainer> CollectContainers()
        {
            var containers = new List<BloodHoundContainer>();
            Console.WriteLine("[*] Collecting Containers...");

            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(objectClass=container)";
                searcher.PageSize = 1000;
                searcher.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;

                searcher.PropertiesToLoad.AddRange(new string[]
                {
                    "name", "distinguishedName", "objectGuid",
                    "nTSecurityDescriptor"
                });

                SearchResultCollection results = searcher.FindAll();
                int count = 0;

                foreach (SearchResult result in results)
                {
                    try
                    {
                        var container = ProcessContainer(result);
                        if (container != null)
                        {
                            containers.Add(container);
                            count++;
                        }
                    }
                    catch (Exception ex)
                    {
                        OutputHelper.Verbose($"[!] Error processing container: {ex.Message}");
                    }
                }

                OutputHelper.Verbose($"    Processed {count} containers");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error collecting containers: {ex.Message}");
            }

            return containers;
        }

        private BloodHoundContainer ProcessContainer(SearchResult result)
        {
            string guid = GetGuidString(result, "objectGuid");
            if (string.IsNullOrEmpty(guid))
                return null;

            string dn = GetStringProperty(result, "distinguishedName");
            string name = GetStringProperty(result, "name");

            var container = new BloodHoundContainer
            {
                ObjectIdentifier = guid,
                Properties = new ContainerProperties
                {
                    Domain = _domainName,
                    Name = name,
                    DistinguishedName = dn
                }
            };

            // ACLs
            if ((_methods & CollectionMethod.ACL) != 0)
            {
                byte[] sd = GetByteArrayProperty(result, "nTSecurityDescriptor");
                if (sd != null)
                {
                    container.Aces = _aclProcessor.ProcessAcl(sd, "container");
                    container.IsACLProtected = _aclProcessor.IsAclProtected(sd);
                }
            }

            return container;
        }

        #endregion

        #region Certificate Services (ADCS)

        /// <summary>
        /// Collect Certificate Templates from Configuration NC
        /// </summary>
        public List<BloodHoundCertTemplate> CollectCertTemplates()
        {
            var templates = new List<BloodHoundCertTemplate>();
            Console.WriteLine("[*] Collecting Certificate Templates...");

            try
            {
                // Get Configuration NC
                DirectoryEntry rootDse = AuthContext.GetRootDSE();
                string configNC = rootDse.Properties["configurationNamingContext"][0].ToString();

                // Search in CN=Certificate Templates,CN=Public Key Services,CN=Services,<ConfigNC>
                string templatePath = $"LDAP://{AuthContext.GetLdapServer()}/CN=Certificate Templates,CN=Public Key Services,CN=Services,{configNC}";
                DirectoryEntry templateContainer = AuthContext.GetDirectoryEntry(templatePath);

                DirectorySearcher searcher = new DirectorySearcher(templateContainer);
                searcher.Filter = "(objectClass=pKICertificateTemplate)";
                searcher.PageSize = 1000;
                searcher.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;

                searcher.PropertiesToLoad.AddRange(new string[]
                {
                    "cn", "name", "displayName", "distinguishedName", "objectGuid",
                    "description", "whenCreated",
                    "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
                    "msPKI-Private-Key-Flag", "msPKI-RA-Signature",
                    "msPKI-Minimal-Key-Size", "msPKI-Template-Schema-Version",
                    "pKIExtendedKeyUsage", "pKIExpirationPeriod", "pKIOverlapPeriod",
                    "msPKI-Certificate-Application-Policy",
                    "nTSecurityDescriptor"
                });

                SearchResultCollection results = searcher.FindAll();
                int count = 0;

                foreach (SearchResult result in results)
                {
                    try
                    {
                        var template = ProcessCertTemplate(result);
                        if (template != null)
                        {
                            templates.Add(template);
                            count++;
                        }
                    }
                    catch (Exception ex)
                    {
                        OutputHelper.Verbose($"[!] Error processing cert template: {ex.Message}");
                    }
                }

                OutputHelper.Verbose($"    Processed {count} certificate templates");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error collecting certificate templates: {ex.Message}");
            }

            return templates;
        }

        private BloodHoundCertTemplate ProcessCertTemplate(SearchResult result)
        {
            string guid = GetGuidString(result, "objectGuid");
            if (string.IsNullOrEmpty(guid))
                return null;

            string dn = GetStringProperty(result, "distinguishedName");
            string name = GetStringProperty(result, "name") ?? GetStringProperty(result, "cn");
            string displayName = GetStringProperty(result, "displayName") ?? name;

            int nameFlag = GetIntProperty(result, "msPKI-Certificate-Name-Flag");
            int enrollmentFlag = GetIntProperty(result, "msPKI-Enrollment-Flag");
            int raSignature = GetIntProperty(result, "msPKI-RA-Signature");
            int schemaVersion = GetIntProperty(result, "msPKI-Template-Schema-Version");

            // Get EKUs
            var ekus = GetStringList(result, "pKIExtendedKeyUsage");
            var appPolicies = GetStringList(result, "msPKI-Certificate-Application-Policy");

            // Check for authentication EKUs
            bool authEnabled = ekus.Count == 0 || // No EKU = any purpose
                               ekus.Contains("1.3.6.1.5.5.7.3.2") || // Client Auth
                               ekus.Contains("1.3.6.1.5.2.3.4") || // PKINIT Client Auth
                               ekus.Contains("1.3.6.1.4.1.311.20.2.2") || // Smart Card Logon
                               ekus.Contains("2.5.29.37.0"); // Any Purpose

            // ESC1 indicators
            bool enrolleeSuppliesSubject = (nameFlag & 1) != 0; // CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
            bool requiresManagerApproval = (enrollmentFlag & 2) != 0; // CT_FLAG_PEND_ALL_REQUESTS

            var template = new BloodHoundCertTemplate
            {
                ObjectIdentifier = guid,
                Properties = new CertTemplateProperties
                {
                    Domain = _domainName,
                    Name = $"{name}@{_domainName}".ToUpper(),
                    DisplayName = displayName,
                    DistinguishedName = dn,
                    Description = GetStringProperty(result, "description"),
                    WhenCreated = GetTimestamp(result, "whenCreated"),
                    SchemaVersion = schemaVersion,
                    EnrollmentFlag = enrollmentFlag,
                    CertificateNameFlag = nameFlag,
                    EnrolleeSuppliesSubject = enrolleeSuppliesSubject,
                    RequiresManagerApproval = requiresManagerApproval,
                    AuthenticationEnabled = authEnabled,
                    AuthorizedSignatures = raSignature,
                    Ekus = ekus,
                    CertificateApplicationPolicy = appPolicies,
                    // Mark as high value if ESC1 vulnerable
                    HighValue = enrolleeSuppliesSubject && authEnabled && !requiresManagerApproval && raSignature == 0
                }
            };

            // ACLs - important for ESC4
            if ((_methods & CollectionMethod.ACL) != 0)
            {
                byte[] sd = GetByteArrayProperty(result, "nTSecurityDescriptor");
                if (sd != null)
                {
                    template.Aces = _aclProcessor.ProcessAcl(sd, "certtemplate");
                    template.IsACLProtected = _aclProcessor.IsAclProtected(sd);
                }
            }

            return template;
        }

        /// <summary>
        /// Collect Enterprise CAs from Configuration NC
        /// </summary>
        public List<BloodHoundEnterpriseCA> CollectEnterpriseCAs()
        {
            var cas = new List<BloodHoundEnterpriseCA>();
            Console.WriteLine("[*] Collecting Enterprise CAs...");

            try
            {
                // Get Configuration NC
                DirectoryEntry rootDse = AuthContext.GetRootDSE();
                string configNC = rootDse.Properties["configurationNamingContext"][0].ToString();

                // Search in CN=Enrollment Services,CN=Public Key Services,CN=Services,<ConfigNC>
                string caPath = $"LDAP://{AuthContext.GetLdapServer()}/CN=Enrollment Services,CN=Public Key Services,CN=Services,{configNC}";
                DirectoryEntry caContainer = AuthContext.GetDirectoryEntry(caPath);

                DirectorySearcher searcher = new DirectorySearcher(caContainer);
                searcher.Filter = "(objectClass=pKIEnrollmentService)";
                searcher.PageSize = 1000;
                searcher.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;

                searcher.PropertiesToLoad.AddRange(new string[]
                {
                    "cn", "name", "displayName", "distinguishedName", "objectGuid",
                    "description", "whenCreated", "dNSHostName",
                    "cACertificate", "certificateTemplates", "flags",
                    "nTSecurityDescriptor"
                });

                SearchResultCollection results = searcher.FindAll();
                int count = 0;

                foreach (SearchResult result in results)
                {
                    try
                    {
                        var ca = ProcessEnterpriseCA(result);
                        if (ca != null)
                        {
                            cas.Add(ca);
                            count++;
                        }
                    }
                    catch (Exception ex)
                    {
                        OutputHelper.Verbose($"[!] Error processing Enterprise CA: {ex.Message}");
                    }
                }

                OutputHelper.Verbose($"    Processed {count} Enterprise CAs");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error collecting Enterprise CAs: {ex.Message}");
            }

            return cas;
        }

        private BloodHoundEnterpriseCA ProcessEnterpriseCA(SearchResult result)
        {
            string guid = GetGuidString(result, "objectGuid");
            if (string.IsNullOrEmpty(guid))
                return null;

            string dn = GetStringProperty(result, "distinguishedName");
            string name = GetStringProperty(result, "name") ?? GetStringProperty(result, "cn");
            string dnsHostname = GetStringProperty(result, "dNSHostName");
            int flags = GetIntProperty(result, "flags");

            var ca = new BloodHoundEnterpriseCA
            {
                ObjectIdentifier = guid,
                Properties = new EnterpriseCaProperties
                {
                    Domain = _domainName,
                    Name = $"{name}@{_domainName}".ToUpper(),
                    DistinguishedName = dn,
                    Description = GetStringProperty(result, "description"),
                    WhenCreated = GetTimestamp(result, "whenCreated"),
                    DnsHostname = dnsHostname,
                    CaName = name,
                    Flags = flags,
                    HighValue = true
                }
            };

            // Enabled certificate templates
            if (result.Properties.Contains("certificateTemplates"))
            {
                foreach (var templateName in result.Properties["certificateTemplates"])
                {
                    ca.EnabledCertTemplates.Add(new TypedPrincipal
                    {
                        ObjectIdentifier = templateName.ToString(),
                        ObjectType = "CertTemplate"
                    });
                }
            }

            // ACLs - important for ManageCA/ManageCertificates
            if ((_methods & CollectionMethod.ACL) != 0)
            {
                byte[] sd = GetByteArrayProperty(result, "nTSecurityDescriptor");
                if (sd != null)
                {
                    ca.Aces = _aclProcessor.ProcessAcl(sd, "enterpriseca");
                    ca.IsACLProtected = _aclProcessor.IsAclProtected(sd);
                }
            }

            return ca;
        }

        #endregion

        #region Helper Methods

        private void CacheObject(string sid, string dn, PrincipalType type)
        {
            if (!string.IsNullOrEmpty(sid))
            {
                _sidToType[sid] = type;
                _aclProcessor.CachePrincipalType(sid, type);
            }
            if (!string.IsNullOrEmpty(dn) && !string.IsNullOrEmpty(sid))
            {
                _dnToSid[dn] = sid;
            }
        }

        private string GetStringProperty(SearchResult result, string propertyName)
        {
            if (result.Properties.Contains(propertyName) && result.Properties[propertyName].Count > 0)
                return result.Properties[propertyName][0]?.ToString();
            return null;
        }

        private int GetIntProperty(SearchResult result, string propertyName, int defaultValue = 0)
        {
            if (result.Properties.Contains(propertyName) && result.Properties[propertyName].Count > 0)
            {
                try { return Convert.ToInt32(result.Properties[propertyName][0]); }
                catch { }
            }
            return defaultValue;
        }

        private byte[] GetByteArrayProperty(SearchResult result, string propertyName)
        {
            if (result.Properties.Contains(propertyName) && result.Properties[propertyName].Count > 0)
                return result.Properties[propertyName][0] as byte[];
            return null;
        }

        private string GetSidString(SearchResult result, string propertyName)
        {
            byte[] sidBytes = GetByteArrayProperty(result, propertyName);
            if (sidBytes != null && sidBytes.Length > 0)
            {
                try { return new SecurityIdentifier(sidBytes, 0).ToString(); }
                catch { }
            }
            return null;
        }

        private string GetGuidString(SearchResult result, string propertyName)
        {
            byte[] guidBytes = GetByteArrayProperty(result, propertyName);
            if (guidBytes != null && guidBytes.Length == 16)
            {
                try { return new Guid(guidBytes).ToString().ToUpper(); }
                catch { }
            }
            return null;
        }

        private long GetTimestamp(SearchResult result, string propertyName)
        {
            if (result.Properties.Contains(propertyName) && result.Properties[propertyName].Count > 0)
            {
                try
                {
                    DateTime dt = (DateTime)result.Properties[propertyName][0];
                    return TimeHelper.ToUnixTimestamp(dt);
                }
                catch { }
            }
            return -1;
        }

        private long GetFileTimeTimestamp(SearchResult result, string propertyName)
        {
            if (result.Properties.Contains(propertyName) && result.Properties[propertyName].Count > 0)
            {
                try
                {
                    long fileTime = Convert.ToInt64(result.Properties[propertyName][0]);
                    return TimeHelper.FileTimeToUnixTimestamp(fileTime);
                }
                catch { }
            }
            return -1;
        }

        private List<string> GetStringList(SearchResult result, string propertyName)
        {
            var list = new List<string>();
            if (result.Properties.Contains(propertyName))
            {
                foreach (var item in result.Properties[propertyName])
                {
                    list.Add(item.ToString());
                }
            }
            return list;
        }

        private List<string> GetSidHistoryList(SearchResult result)
        {
            var list = new List<string>();
            if (result.Properties.Contains("sIDHistory"))
            {
                foreach (var item in result.Properties["sIDHistory"])
                {
                    try
                    {
                        byte[] sidBytes = item as byte[];
                        if (sidBytes != null)
                        {
                            list.Add(new SecurityIdentifier(sidBytes, 0).ToString());
                        }
                    }
                    catch { }
                }
            }
            return list;
        }

        private List<GPLink> ParseGpLink(string gpLinkStr)
        {
            var links = new List<GPLink>();
            if (string.IsNullOrEmpty(gpLinkStr))
                return links;

            // Format: [LDAP://cn={GUID},cn=policies,...;status][...]
            string[] parts = gpLinkStr.Split(new[] { ']' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string part in parts)
            {
                string trimmed = part.TrimStart('[');
                string[] segments = trimmed.Split(';');
                if (segments.Length >= 1)
                {
                    // Extract GUID from DN
                    string dn = segments[0];
                    int guidStart = dn.IndexOf("{", StringComparison.OrdinalIgnoreCase);
                    int guidEnd = dn.IndexOf("}", StringComparison.OrdinalIgnoreCase);
                    if (guidStart >= 0 && guidEnd > guidStart)
                    {
                        string guid = dn.Substring(guidStart, guidEnd - guidStart + 1);
                        bool enforced = segments.Length > 1 && segments[1] == "2";

                        links.Add(new GPLink
                        {
                            GUID = guid.ToUpper(),
                            IsEnforced = enforced
                        });
                    }
                }
            }

            return links;
        }

        private string GetFunctionalLevelName(int level)
        {
            return level switch
            {
                0 => "2000",
                1 => "2003 Interim",
                2 => "2003",
                3 => "2008",
                4 => "2008 R2",
                5 => "2012",
                6 => "2012 R2",
                7 => "2016",
                _ => "Unknown"
            };
        }

        private string GetTrustDirection(int direction)
        {
            return direction switch
            {
                0 => "Disabled",
                1 => "Inbound",
                2 => "Outbound",
                3 => "Bidirectional",
                _ => "Unknown"
            };
        }

        private string GetTrustType(int trustType, int attrs)
        {
            if ((attrs & 0x8) != 0) // TRUST_ATTRIBUTE_FOREST_TRANSITIVE
                return "Forest";

            return trustType switch
            {
                1 => "Downlevel",
                2 => "Uplevel",
                3 => "MIT",
                4 => "DCE",
                _ => "Unknown"
            };
        }

        #endregion
    }
}

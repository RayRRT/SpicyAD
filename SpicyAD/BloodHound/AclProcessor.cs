using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Linq;

namespace SpicyAD.BloodHound
{
    /// <summary>
    /// Processes Active Directory ACLs and converts them to BloodHound format
    /// </summary>
    public class AclProcessor
    {
        private readonly Dictionary<string, string> _sidNameCache = new Dictionary<string, string>();
        private readonly Dictionary<string, PrincipalType> _sidTypeCache = new Dictionary<string, PrincipalType>();
        private readonly string _domainSid;
        private readonly string _domainName;

        // ActiveDirectory Rights flags
        private const int RIGHT_GENERIC_ALL = 0x10000000;
        private const int RIGHT_GENERIC_WRITE = 0x40000000;
        private const int RIGHT_WRITE_OWNER = 0x00080000;
        private const int RIGHT_WRITE_DACL = 0x00040000;
        private const int RIGHT_WRITE_PROPERTY = 0x00000020;
        private const int RIGHT_EXTENDED_RIGHT = 0x00000100;
        private const int RIGHT_READ_PROPERTY = 0x00000010;
        private const int RIGHT_SELF = 0x00000008;

        public AclProcessor(string domainSid, string domainName)
        {
            _domainSid = domainSid;
            _domainName = domainName?.ToUpper();
        }

        /// <summary>
        /// Process security descriptor and return BloodHound ACEs
        /// </summary>
        public List<BloodHoundAce> ProcessAcl(byte[] securityDescriptor, string objectType = null)
        {
            var aces = new List<BloodHoundAce>();

            if (securityDescriptor == null || securityDescriptor.Length == 0)
                return aces;

            try
            {
                var sd = new RawSecurityDescriptor(securityDescriptor, 0);

                // Process owner
                if (sd.Owner != null)
                {
                    string ownerSid = sd.Owner.ToString();
                    // Skip well-known system owners
                    if (!IsSystemSid(ownerSid))
                    {
                        var ownerAce = new BloodHoundAce
                        {
                            PrincipalSID = ownerSid,
                            PrincipalType = GetPrincipalType(ownerSid).ToString(),
                            RightName = AceRights.Owns,
                            IsInherited = false
                        };
                        aces.Add(ownerAce);
                    }
                }

                // Process DACL
                if (sd.DiscretionaryAcl != null)
                {
                    foreach (var ace in sd.DiscretionaryAcl)
                    {
                        var processedAces = ProcessAce(ace, objectType);
                        aces.AddRange(processedAces);
                    }
                }
            }
            catch (Exception ex)
            {
                OutputHelper.Verbose($"[!] ACL processing error: {ex.Message}");
            }

            return aces;
        }

        /// <summary>
        /// Process a single ACE
        /// </summary>
        private List<BloodHoundAce> ProcessAce(GenericAce ace, string objectType)
        {
            var results = new List<BloodHoundAce>();

            // Only process Allow ACEs
            if (ace.AceType != AceType.AccessAllowed &&
                ace.AceType != AceType.AccessAllowedObject)
                return results;

            // Get common ACE properties
            var qualifiedAce = ace as KnownAce;
            if (qualifiedAce == null)
                return results;

            string principalSid = qualifiedAce.SecurityIdentifier.ToString();

            // Skip system SIDs
            if (IsSystemSid(principalSid))
                return results;

            int accessMask = qualifiedAce.AccessMask;
            bool isInherited = (ace.AceFlags & AceFlags.Inherited) != 0;

            // Handle object ACEs (with GUID)
            Guid? objectAceType = null;

            if (ace is ObjectAce objectAce)
            {
                if ((objectAce.ObjectAceFlags & ObjectAceFlags.ObjectAceTypePresent) != 0)
                    objectAceType = objectAce.ObjectAceType;
            }

            PrincipalType principalType = GetPrincipalType(principalSid);

            // GenericAll
            if ((accessMask & RIGHT_GENERIC_ALL) != 0)
            {
                results.Add(CreateAce(principalSid, principalType, AceRights.GenericAll, isInherited));
                return results; // GenericAll implies everything else
            }

            // GenericWrite
            if ((accessMask & RIGHT_GENERIC_WRITE) != 0)
            {
                results.Add(CreateAce(principalSid, principalType, AceRights.GenericWrite, isInherited));
            }

            // WriteOwner
            if ((accessMask & RIGHT_WRITE_OWNER) != 0)
            {
                results.Add(CreateAce(principalSid, principalType, AceRights.WriteOwner, isInherited));
            }

            // WriteDACL
            if ((accessMask & RIGHT_WRITE_DACL) != 0)
            {
                results.Add(CreateAce(principalSid, principalType, AceRights.WriteDacl, isInherited));
            }

            // Extended Rights
            if ((accessMask & RIGHT_EXTENDED_RIGHT) != 0)
            {
                results.AddRange(ProcessExtendedRights(principalSid, principalType, objectAceType, isInherited, objectType));
            }

            // WriteProperty
            if ((accessMask & RIGHT_WRITE_PROPERTY) != 0)
            {
                results.AddRange(ProcessWriteProperty(principalSid, principalType, objectAceType, isInherited, objectType));
            }

            // Self (AddSelf to groups)
            if ((accessMask & RIGHT_SELF) != 0 && objectAceType.HasValue)
            {
                if (objectAceType.Value == ADRightsGuid.Member)
                {
                    results.Add(CreateAce(principalSid, principalType, AceRights.AddSelf, isInherited));
                }
            }

            return results;
        }

        /// <summary>
        /// Process extended rights
        /// </summary>
        private List<BloodHoundAce> ProcessExtendedRights(string principalSid, PrincipalType principalType,
            Guid? objectAceType, bool isInherited, string objectType)
        {
            var results = new List<BloodHoundAce>();

            // All Extended Rights (no specific GUID or empty GUID)
            if (!objectAceType.HasValue || objectAceType.Value == Guid.Empty ||
                objectAceType.Value == ADRightsGuid.AllExtendedRights)
            {
                results.Add(CreateAce(principalSid, principalType, AceRights.AllExtendedRights, isInherited));
                return results;
            }

            // User-Force-Change-Password
            if (objectAceType.Value == ADRightsGuid.UserForceChangePassword)
            {
                results.Add(CreateAce(principalSid, principalType, AceRights.ForceChangePassword, isInherited));
            }
            // DS-Replication-Get-Changes
            else if (objectAceType.Value == ADRightsGuid.DSReplicationGetChanges)
            {
                results.Add(CreateAce(principalSid, principalType, AceRights.GetChanges, isInherited));
            }
            // DS-Replication-Get-Changes-All
            else if (objectAceType.Value == ADRightsGuid.DSReplicationGetChangesAll)
            {
                results.Add(CreateAce(principalSid, principalType, AceRights.GetChangesAll, isInherited));
            }
            // DS-Replication-Get-Changes-In-Filtered-Set
            else if (objectAceType.Value == ADRightsGuid.DSReplicationGetChangesInFilteredSet)
            {
                results.Add(CreateAce(principalSid, principalType, AceRights.GetChangesInFilteredSet, isInherited));
            }
            // Certificate Enrollment
            else if (objectAceType.Value == ADRightsGuid.CertificateEnrollment ||
                     objectAceType.Value == ADRightsGuid.CertificateAutoEnrollment)
            {
                results.Add(CreateAce(principalSid, principalType, AceRights.Enroll, isInherited));
            }

            return results;
        }

        /// <summary>
        /// Process write property rights
        /// </summary>
        private List<BloodHoundAce> ProcessWriteProperty(string principalSid, PrincipalType principalType,
            Guid? objectAceType, bool isInherited, string objectType)
        {
            var results = new List<BloodHoundAce>();

            // Write all properties (no specific GUID)
            if (!objectAceType.HasValue || objectAceType.Value == Guid.Empty)
            {
                results.Add(CreateAce(principalSid, principalType, AceRights.GenericWrite, isInherited));
                return results;
            }

            // Member (group membership)
            if (objectAceType.Value == ADRightsGuid.Member)
            {
                results.Add(CreateAce(principalSid, principalType, AceRights.AddMember, isInherited));
            }
            // msDS-KeyCredentialLink (Shadow Credentials)
            else if (objectAceType.Value == ADRightsGuid.MsDSKeyCredentialLink)
            {
                results.Add(CreateAce(principalSid, principalType, AceRights.AddKeyCredentialLink, isInherited));
            }
            // msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)
            else if (objectAceType.Value == ADRightsGuid.MsDSAllowedToActOnBehalfOfOtherIdentity)
            {
                results.Add(CreateAce(principalSid, principalType, AceRights.AddAllowedToAct, isInherited));
            }
            // ServicePrincipalName (Targeted Kerberoasting)
            else if (objectAceType.Value == ADRightsGuid.ServicePrincipalName)
            {
                results.Add(CreateAce(principalSid, principalType, AceRights.WriteSPN, isInherited));
            }
            // msDS-GroupMSAMembership (GMSA)
            else if (objectAceType.Value == ADRightsGuid.MsDSGroupMSAMembership)
            {
                results.Add(CreateAce(principalSid, principalType, AceRights.ReadGMSAPassword, isInherited));
            }
            // User-Account-Restrictions property set
            else if (objectAceType.Value == ADRightsGuid.UserAccountRestrictions)
            {
                results.Add(CreateAce(principalSid, principalType, AceRights.WriteAccountRestrictions, isInherited));
            }

            return results;
        }

        /// <summary>
        /// Create a BloodHound ACE
        /// </summary>
        private BloodHoundAce CreateAce(string principalSid, PrincipalType principalType, string rightName, bool isInherited)
        {
            return new BloodHoundAce
            {
                PrincipalSID = principalSid,
                PrincipalType = principalType.ToString(),
                RightName = rightName,
                IsInherited = isInherited
            };
        }

        /// <summary>
        /// Check if SID is a system/well-known SID that should be skipped
        /// </summary>
        private bool IsSystemSid(string sid)
        {
            if (string.IsNullOrEmpty(sid))
                return true;

            // Skip Local System, Creator Owner, Self
            if (sid == WellKnownSids.LocalSystem ||
                sid == WellKnownSids.CreatorOwner ||
                sid == WellKnownSids.Self)
                return true;

            // Skip NT AUTHORITY SIDs (S-1-5-X where X < 20)
            if (sid.StartsWith("S-1-5-") && !sid.StartsWith("S-1-5-21-"))
            {
                // Allow Authenticated Users (S-1-5-11) and other security principals
                if (sid == WellKnownSids.AuthenticatedUsers)
                    return false;

                string[] parts = sid.Split('-');
                if (parts.Length == 4)
                {
                    if (int.TryParse(parts[3], out int subAuth))
                    {
                        if (subAuth < 20 && subAuth != 11) // Keep Authenticated Users
                            return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Determine principal type from SID
        /// </summary>
        public PrincipalType GetPrincipalType(string sid)
        {
            if (string.IsNullOrEmpty(sid))
                return PrincipalType.Unknown;

            // Check cache
            if (_sidTypeCache.TryGetValue(sid, out PrincipalType cachedType))
                return cachedType;

            PrincipalType result = PrincipalType.Unknown;

            // Well-known SIDs
            if (sid == WellKnownSids.Everyone ||
                sid == WellKnownSids.AuthenticatedUsers)
            {
                result = PrincipalType.Group;
            }
            // Built-in groups (S-1-5-32-XXX)
            else if (sid.StartsWith("S-1-5-32-"))
            {
                result = PrincipalType.Group;
            }
            // Domain SIDs - check RID
            else if (sid.StartsWith("S-1-5-21-"))
            {
                string[] parts = sid.Split('-');
                if (parts.Length >= 8)
                {
                    if (int.TryParse(parts[parts.Length - 1], out int rid))
                    {
                        result = GetTypeFromRid(rid);
                    }
                }
            }

            // Cache result
            _sidTypeCache[sid] = result;
            return result;
        }

        /// <summary>
        /// Get principal type from RID
        /// </summary>
        private PrincipalType GetTypeFromRid(int rid)
        {
            // Well-known group RIDs
            switch (rid)
            {
                case 512: // Domain Admins
                case 513: // Domain Users
                case 514: // Domain Guests
                case 515: // Domain Computers
                case 516: // Domain Controllers
                case 517: // Cert Publishers
                case 518: // Schema Admins
                case 519: // Enterprise Admins
                case 520: // Group Policy Creator Owners
                case 521: // Read-only Domain Controllers
                case 522: // Cloneable Domain Controllers
                case 525: // Protected Users
                case 526: // Key Admins
                case 527: // Enterprise Key Admins
                case 553: // RAS and IAS Servers
                case 571: // Allowed RODC Password Replication
                case 572: // Denied RODC Password Replication
                    return PrincipalType.Group;

                case 500: // Administrator
                case 501: // Guest
                case 502: // krbtgt
                case 503: // DefaultAccount
                    return PrincipalType.User;
            }

            // RIDs 1000+ are typically user-created
            // Check by ending: computers typically end in $
            // But we can't determine this from RID alone
            // Default to User for RIDs >= 1000
            if (rid >= 1000)
            {
                // This will be refined by actual LDAP lookup in LdapCollector
                return PrincipalType.User;
            }

            return PrincipalType.Unknown;
        }

        /// <summary>
        /// Resolve SID to account name (with caching)
        /// </summary>
        public string ResolveSid(string sid)
        {
            if (string.IsNullOrEmpty(sid))
                return null;

            // Check cache
            if (_sidNameCache.TryGetValue(sid, out string cachedName))
                return cachedName;

            string name = null;

            try
            {
                var securityIdentifier = new SecurityIdentifier(sid);
                var ntAccount = securityIdentifier.Translate(typeof(NTAccount)) as NTAccount;
                name = ntAccount?.Value;
            }
            catch
            {
                // Could not resolve - might be from another domain
                name = sid;
            }

            // Cache result
            _sidNameCache[sid] = name ?? sid;
            return _sidNameCache[sid];
        }

        /// <summary>
        /// Cache a SID to type mapping (called by LdapCollector during enumeration)
        /// </summary>
        public void CachePrincipalType(string sid, PrincipalType type)
        {
            if (!string.IsNullOrEmpty(sid))
            {
                _sidTypeCache[sid] = type;
            }
        }

        /// <summary>
        /// Cache a SID to name mapping
        /// </summary>
        public void CacheSidName(string sid, string name)
        {
            if (!string.IsNullOrEmpty(sid) && !string.IsNullOrEmpty(name))
            {
                _sidNameCache[sid] = name;
            }
        }

        /// <summary>
        /// Check if ACL is protected (inheritance disabled)
        /// </summary>
        public bool IsAclProtected(byte[] securityDescriptor)
        {
            if (securityDescriptor == null || securityDescriptor.Length == 0)
                return false;

            try
            {
                var sd = new RawSecurityDescriptor(securityDescriptor, 0);
                return (sd.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Get owner SID from security descriptor
        /// </summary>
        public string GetOwnerSid(byte[] securityDescriptor)
        {
            if (securityDescriptor == null || securityDescriptor.Length == 0)
                return null;

            try
            {
                var sd = new RawSecurityDescriptor(securityDescriptor, 0);
                return sd.Owner?.ToString();
            }
            catch
            {
                return null;
            }
        }
    }
}

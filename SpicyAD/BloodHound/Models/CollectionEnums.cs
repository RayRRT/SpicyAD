using System;

namespace SpicyAD.BloodHound
{
    /// <summary>
    /// Collection methods - can be combined as flags
    /// </summary>
    [Flags]
    public enum CollectionMethod : long
    {
        None = 0,

        // LDAP-based collection
        Group = 1 << 0,           // Group membership
        LocalAdmin = 1 << 1,      // Local admin group members
        Session = 1 << 2,         // Network sessions (NetSessionEnum)
        Trusts = 1 << 3,          // Domain trusts
        ACL = 1 << 4,             // Access Control Lists
        Container = 1 << 5,       // Container/OU structure
        RDP = 1 << 6,             // Remote Desktop Users
        ObjectProps = 1 << 7,     // Object properties
        DCOM = 1 << 8,            // DCOM Users
        SPNTargets = 1 << 9,      // SPN targets
        PSRemote = 1 << 10,       // PS Remote Users
        UserRights = 1 << 11,     // User rights assignment
        CARegistry = 1 << 12,     // Certificate Authority registry
        DCRegistry = 1 << 13,     // Domain Controller registry
        CertServices = 1 << 14,   // Certificate Services (ADCS)

        // Composite methods
        LocalGroup = LocalAdmin | RDP | DCOM | PSRemote,
        ComputerOnly = LocalGroup | Session,
        DCOnly = Group | ACL | Trusts | ObjectProps | Container | CertServices,

        Default = Group | Session | Trusts | ACL | ObjectProps | Container | LocalAdmin | CertServices,
        All = Group | LocalAdmin | Session | Trusts | ACL | Container | RDP | ObjectProps |
              DCOM | SPNTargets | PSRemote | UserRights | CARegistry | DCRegistry | CertServices
    }

    /// <summary>
    /// BloodHound data types for JSON output
    /// </summary>
    public enum DataType
    {
        Users,
        Computers,
        Groups,
        Domains,
        OUs,
        GPOs,
        Containers,
        CertTemplates,
        EnterpriseCAs,
        RootCAs,
        AIACAs,
        NTAuthStores,
        IssuancePolicies
    }

    /// <summary>
    /// Principal types in BloodHound
    /// </summary>
    public enum PrincipalType
    {
        User,
        Computer,
        Group,
        Domain,
        OU,
        GPO,
        Container,
        CertTemplate,
        EnterpriseCA,
        RootCA,
        AIACA,
        NTAuthStore,
        IssuancePolicy,
        Unknown
    }

    /// <summary>
    /// ACE right names for BloodHound
    /// </summary>
    public static class AceRights
    {
        // Generic rights
        public const string GenericAll = "GenericAll";
        public const string GenericWrite = "GenericWrite";
        public const string WriteOwner = "WriteOwner";
        public const string WriteDacl = "WriteDacl";
        public const string Owns = "Owns";

        // Extended rights
        public const string ForceChangePassword = "ForceChangePassword";
        public const string AddMember = "AddMember";
        public const string ReadLAPSPassword = "ReadLAPSPassword";
        public const string ReadGMSAPassword = "ReadGMSAPassword";
        public const string AllExtendedRights = "AllExtendedRights";

        // DCSync rights
        public const string GetChanges = "GetChanges";
        public const string GetChangesAll = "GetChangesAll";
        public const string GetChangesInFilteredSet = "GetChangesInFilteredSet";

        // Write property rights
        public const string AddKeyCredentialLink = "AddKeyCredentialLink";
        public const string AddSelf = "AddSelf";
        public const string WriteSPN = "WriteSPN";
        public const string AddAllowedToAct = "AddAllowedToAct";
        public const string WriteAccountRestrictions = "WriteAccountRestrictions";

        // Certificate rights
        public const string Enroll = "Enroll";
        public const string ManageCA = "ManageCA";
        public const string ManageCertificates = "ManageCertificates";
    }

    /// <summary>
    /// Well-known GUIDs for extended rights and properties
    /// </summary>
    public static class ADRightsGuid
    {
        // Extended Rights
        public static readonly Guid UserForceChangePassword = new Guid("00299570-246d-11d0-a768-00aa006e0529");
        public static readonly Guid DSReplicationGetChanges = new Guid("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2");
        public static readonly Guid DSReplicationGetChangesAll = new Guid("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2");
        public static readonly Guid DSReplicationGetChangesInFilteredSet = new Guid("89e95b76-444d-4c62-991a-0facbeda640c");
        public static readonly Guid AllExtendedRights = new Guid("00000000-0000-0000-0000-000000000000");

        // Property Sets
        public static readonly Guid PersonalInformation = new Guid("77b5b886-944a-11d1-aebd-0000f80367c1");
        public static readonly Guid PublicInformation = new Guid("e48d0154-bcf8-11d1-8702-00c04fb96050");

        // Properties
        public static readonly Guid Member = new Guid("bf9679c0-0de6-11d0-a285-00aa003049e2");
        public static readonly Guid MsDSKeyCredentialLink = new Guid("5b47d60f-6090-40b2-9f37-2a4de88f3063");
        public static readonly Guid MsDSAllowedToActOnBehalfOfOtherIdentity = new Guid("3f78c3e5-f79a-46bd-a0b8-9d18116ddc79");
        public static readonly Guid ServicePrincipalName = new Guid("f3a64788-5306-11d1-a9c5-0000f80367c1");
        public static readonly Guid MsDSGroupMSAMembership = new Guid("888eedd6-ce04-df40-b462-b8a50e41ba38");
        public static readonly Guid UserAccountRestrictions = new Guid("4c164200-20c0-11d0-a768-00aa006e0529");

        // Certificate Rights
        public static readonly Guid CertificateEnrollment = new Guid("0e10c968-78fb-11d2-90d4-00c04f79dc55");
        public static readonly Guid CertificateAutoEnrollment = new Guid("a05b8cc2-17bc-4802-a710-e7c15ab866a2");
    }

    /// <summary>
    /// Well-known SIDs
    /// </summary>
    public static class WellKnownSids
    {
        public const string Everyone = "S-1-1-0";
        public const string AuthenticatedUsers = "S-1-5-11";
        public const string DomainUsers = "-513";        // Relative ID
        public const string DomainComputers = "-515";    // Relative ID
        public const string DomainAdmins = "-512";       // Relative ID
        public const string EnterpriseAdmins = "-519";   // Relative ID
        public const string Administrators = "S-1-5-32-544";
        public const string RemoteDesktopUsers = "S-1-5-32-555";
        public const string DCOMUsers = "S-1-5-32-562";
        public const string RemoteManagementUsers = "S-1-5-32-580";
        public const string Self = "S-1-5-10";
        public const string CreatorOwner = "S-1-3-0";
        public const string LocalSystem = "S-1-5-18";
    }

    /// <summary>
    /// User Account Control flags
    /// </summary>
    [Flags]
    public enum UACFlags : int
    {
        SCRIPT = 0x0001,
        ACCOUNTDISABLE = 0x0002,
        HOMEDIR_REQUIRED = 0x0008,
        LOCKOUT = 0x0010,
        PASSWD_NOTREQD = 0x0020,
        PASSWD_CANT_CHANGE = 0x0040,
        ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080,
        TEMP_DUPLICATE_ACCOUNT = 0x0100,
        NORMAL_ACCOUNT = 0x0200,
        INTERDOMAIN_TRUST_ACCOUNT = 0x0800,
        WORKSTATION_TRUST_ACCOUNT = 0x1000,
        SERVER_TRUST_ACCOUNT = 0x2000,
        DONT_EXPIRE_PASSWORD = 0x10000,
        MNS_LOGON_ACCOUNT = 0x20000,
        SMARTCARD_REQUIRED = 0x40000,
        TRUSTED_FOR_DELEGATION = 0x80000,
        NOT_DELEGATED = 0x100000,
        USE_DES_KEY_ONLY = 0x200000,
        DONT_REQ_PREAUTH = 0x400000,
        PASSWORD_EXPIRED = 0x800000,
        TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000,
        PARTIAL_SECRETS_ACCOUNT = 0x4000000
    }

    /// <summary>
    /// Trust direction
    /// </summary>
    public enum TrustDirection
    {
        Disabled = 0,
        Inbound = 1,
        Outbound = 2,
        Bidirectional = 3
    }

    /// <summary>
    /// Trust type
    /// </summary>
    public enum TrustType
    {
        ParentChild,
        CrossLink,
        External,
        Forest,
        Unknown
    }
}

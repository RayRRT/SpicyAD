using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace SpicyAD.BloodHound
{
    #region Output Wrapper

    /// <summary>
    /// Generic wrapper for BloodHound JSON output
    /// </summary>
    public class BloodHoundOutput<T>
    {
        [JsonProperty("data")]
        public List<T> Data { get; set; } = new List<T>();

        [JsonProperty("meta")]
        public BloodHoundMeta Meta { get; set; } = new BloodHoundMeta();
    }

    /// <summary>
    /// Metadata for BloodHound JSON output
    /// </summary>
    public class BloodHoundMeta
    {
        [JsonProperty("type")]
        public string Type { get; set; }

        [JsonProperty("count")]
        public int Count { get; set; }

        [JsonProperty("version")]
        public int Version { get; set; } = 6;  // BloodHound CE v6 format

        [JsonProperty("methods")]
        public long Methods { get; set; }
    }

    #endregion

    #region Common Types

    /// <summary>
    /// Typed principal reference (SID + Type)
    /// </summary>
    public class TypedPrincipal
    {
        [JsonProperty("ObjectIdentifier")]
        public string ObjectIdentifier { get; set; }

        [JsonProperty("ObjectType")]
        public string ObjectType { get; set; }
    }

    /// <summary>
    /// Access Control Entry for BloodHound
    /// </summary>
    public class BloodHoundAce
    {
        [JsonProperty("PrincipalSID")]
        public string PrincipalSID { get; set; }

        [JsonProperty("PrincipalType")]
        public string PrincipalType { get; set; }

        [JsonProperty("RightName")]
        public string RightName { get; set; }

        [JsonProperty("IsInherited")]
        public bool IsInherited { get; set; }
    }

    /// <summary>
    /// Session information
    /// </summary>
    public class SessionInfo
    {
        [JsonProperty("UserSID")]
        public string UserSID { get; set; }

        [JsonProperty("ComputerSID")]
        public string ComputerSID { get; set; }
    }

    /// <summary>
    /// Local group member
    /// </summary>
    public class LocalGroupMember
    {
        [JsonProperty("ObjectIdentifier")]
        public string ObjectIdentifier { get; set; }

        [JsonProperty("ObjectType")]
        public string ObjectType { get; set; }
    }

    /// <summary>
    /// Group member info
    /// </summary>
    public class GroupMember
    {
        [JsonProperty("ObjectIdentifier")]
        public string ObjectIdentifier { get; set; }

        [JsonProperty("ObjectType")]
        public string ObjectType { get; set; }
    }

    /// <summary>
    /// SPNTarget info
    /// </summary>
    public class SPNTarget
    {
        [JsonProperty("ComputerSID")]
        public string ComputerSID { get; set; }

        [JsonProperty("Port")]
        public int Port { get; set; }

        [JsonProperty("Service")]
        public string Service { get; set; }
    }

    /// <summary>
    /// Domain trust info
    /// </summary>
    public class DomainTrust
    {
        [JsonProperty("TargetDomainSid")]
        public string TargetDomainSid { get; set; }

        [JsonProperty("TargetDomainName")]
        public string TargetDomainName { get; set; }

        [JsonProperty("IsTransitive")]
        public bool IsTransitive { get; set; }

        [JsonProperty("SidFilteringEnabled")]
        public bool SidFilteringEnabled { get; set; }

        [JsonProperty("TrustDirection")]
        public string TrustDirection { get; set; }

        [JsonProperty("TrustType")]
        public string TrustType { get; set; }
    }

    /// <summary>
    /// GPO link info
    /// </summary>
    public class GPLink
    {
        [JsonProperty("GUID")]
        public string GUID { get; set; }

        [JsonProperty("IsEnforced")]
        public bool IsEnforced { get; set; }
    }

    /// <summary>
    /// Child object reference
    /// </summary>
    public class ChildObject
    {
        [JsonProperty("ObjectIdentifier")]
        public string ObjectIdentifier { get; set; }

        [JsonProperty("ObjectType")]
        public string ObjectType { get; set; }
    }

    #endregion

    #region User

    /// <summary>
    /// BloodHound User object
    /// </summary>
    public class BloodHoundUser
    {
        [JsonProperty("ObjectIdentifier")]
        public string ObjectIdentifier { get; set; }

        [JsonProperty("Properties")]
        public UserProperties Properties { get; set; } = new UserProperties();

        [JsonProperty("PrimaryGroupSID")]
        public string PrimaryGroupSID { get; set; }

        [JsonProperty("AllowedToDelegate")]
        public List<TypedPrincipal> AllowedToDelegate { get; set; } = new List<TypedPrincipal>();

        [JsonProperty("SPNTargets")]
        public List<SPNTarget> SPNTargets { get; set; } = new List<SPNTarget>();

        [JsonProperty("HasSIDHistory")]
        public List<TypedPrincipal> HasSIDHistory { get; set; } = new List<TypedPrincipal>();

        [JsonProperty("Aces")]
        public List<BloodHoundAce> Aces { get; set; } = new List<BloodHoundAce>();

        [JsonProperty("IsDeleted")]
        public bool IsDeleted { get; set; }

        [JsonProperty("IsACLProtected")]
        public bool IsACLProtected { get; set; }
    }

    public class UserProperties
    {
        [JsonProperty("domain")]
        public string Domain { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("distinguishedname")]
        public string DistinguishedName { get; set; }

        [JsonProperty("samaccountname")]
        public string SamAccountName { get; set; }

        [JsonProperty("description")]
        public string Description { get; set; }

        [JsonProperty("whencreated")]
        public long WhenCreated { get; set; }

        [JsonProperty("enabled")]
        public bool Enabled { get; set; }

        [JsonProperty("lastlogon")]
        public long LastLogon { get; set; }

        [JsonProperty("lastlogontimestamp")]
        public long LastLogonTimestamp { get; set; }

        [JsonProperty("pwdlastset")]
        public long PwdLastSet { get; set; }

        [JsonProperty("dontreqpreauth")]
        public bool DontReqPreauth { get; set; }

        [JsonProperty("passwordnotreqd")]
        public bool PasswordNotReqd { get; set; }

        [JsonProperty("unconstraineddelegation")]
        public bool UnconstrainedDelegation { get; set; }

        [JsonProperty("trustedtoauth")]
        public bool TrustedToAuth { get; set; }

        [JsonProperty("sensitive")]
        public bool Sensitive { get; set; }

        [JsonProperty("hasspn")]
        public bool HasSPN { get; set; }

        [JsonProperty("serviceprincipalnames")]
        public List<string> ServicePrincipalNames { get; set; } = new List<string>();

        [JsonProperty("admincount")]
        public bool AdminCount { get; set; }

        [JsonProperty("displayname")]
        public string DisplayName { get; set; }

        [JsonProperty("email")]
        public string Email { get; set; }

        [JsonProperty("title")]
        public string Title { get; set; }

        [JsonProperty("homedirectory")]
        public string HomeDirectory { get; set; }

        [JsonProperty("userpassword")]
        public string UserPassword { get; set; }

        [JsonProperty("sfupassword")]
        public string SfuPassword { get; set; }

        [JsonProperty("logonscript")]
        public string LogonScript { get; set; }

        [JsonProperty("sidhistory")]
        public List<string> SidHistory { get; set; } = new List<string>();
    }

    #endregion

    #region Computer

    /// <summary>
    /// BloodHound Computer object
    /// </summary>
    public class BloodHoundComputer
    {
        [JsonProperty("ObjectIdentifier")]
        public string ObjectIdentifier { get; set; }

        [JsonProperty("Properties")]
        public ComputerProperties Properties { get; set; } = new ComputerProperties();

        [JsonProperty("PrimaryGroupSID")]
        public string PrimaryGroupSID { get; set; }

        [JsonProperty("AllowedToDelegate")]
        public List<TypedPrincipal> AllowedToDelegate { get; set; } = new List<TypedPrincipal>();

        [JsonProperty("AllowedToAct")]
        public List<TypedPrincipal> AllowedToAct { get; set; } = new List<TypedPrincipal>();

        [JsonProperty("HasSIDHistory")]
        public List<TypedPrincipal> HasSIDHistory { get; set; } = new List<TypedPrincipal>();

        [JsonProperty("Sessions")]
        public ResultStatus<List<SessionInfo>> Sessions { get; set; } = new ResultStatus<List<SessionInfo>>();

        [JsonProperty("PrivilegedSessions")]
        public ResultStatus<List<SessionInfo>> PrivilegedSessions { get; set; } = new ResultStatus<List<SessionInfo>>();

        [JsonProperty("RegistrySessions")]
        public ResultStatus<List<SessionInfo>> RegistrySessions { get; set; } = new ResultStatus<List<SessionInfo>>();

        [JsonProperty("LocalAdmins")]
        public ResultStatus<List<LocalGroupMember>> LocalAdmins { get; set; } = new ResultStatus<List<LocalGroupMember>>();

        [JsonProperty("RemoteDesktopUsers")]
        public ResultStatus<List<LocalGroupMember>> RemoteDesktopUsers { get; set; } = new ResultStatus<List<LocalGroupMember>>();

        [JsonProperty("DcomUsers")]
        public ResultStatus<List<LocalGroupMember>> DcomUsers { get; set; } = new ResultStatus<List<LocalGroupMember>>();

        [JsonProperty("PSRemoteUsers")]
        public ResultStatus<List<LocalGroupMember>> PSRemoteUsers { get; set; } = new ResultStatus<List<LocalGroupMember>>();

        [JsonProperty("Aces")]
        public List<BloodHoundAce> Aces { get; set; } = new List<BloodHoundAce>();

        [JsonProperty("IsDeleted")]
        public bool IsDeleted { get; set; }

        [JsonProperty("IsACLProtected")]
        public bool IsACLProtected { get; set; }

        [JsonProperty("IsDC")]
        public bool IsDC { get; set; }
    }

    public class ComputerProperties
    {
        [JsonProperty("domain")]
        public string Domain { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("distinguishedname")]
        public string DistinguishedName { get; set; }

        [JsonProperty("samaccountname")]
        public string SamAccountName { get; set; }

        [JsonProperty("description")]
        public string Description { get; set; }

        [JsonProperty("whencreated")]
        public long WhenCreated { get; set; }

        [JsonProperty("enabled")]
        public bool Enabled { get; set; }

        [JsonProperty("lastlogon")]
        public long LastLogon { get; set; }

        [JsonProperty("lastlogontimestamp")]
        public long LastLogonTimestamp { get; set; }

        [JsonProperty("pwdlastset")]
        public long PwdLastSet { get; set; }

        [JsonProperty("unconstraineddelegation")]
        public bool UnconstrainedDelegation { get; set; }

        [JsonProperty("trustedtoauth")]
        public bool TrustedToAuth { get; set; }

        [JsonProperty("haslaps")]
        public bool HasLaps { get; set; }

        [JsonProperty("operatingsystem")]
        public string OperatingSystem { get; set; }

        [JsonProperty("serviceprincipalnames")]
        public List<string> ServicePrincipalNames { get; set; } = new List<string>();

        [JsonProperty("sidhistory")]
        public List<string> SidHistory { get; set; } = new List<string>();
    }

    /// <summary>
    /// Wrapper for results that may fail (collected/not collected)
    /// </summary>
    public class ResultStatus<T> where T : new()
    {
        [JsonProperty("Results")]
        public T Results { get; set; } = new T();

        [JsonProperty("Collected")]
        public bool Collected { get; set; }

        [JsonProperty("FailureReason")]
        public string FailureReason { get; set; }
    }

    #endregion

    #region Group

    /// <summary>
    /// BloodHound Group object
    /// </summary>
    public class BloodHoundGroup
    {
        [JsonProperty("ObjectIdentifier")]
        public string ObjectIdentifier { get; set; }

        [JsonProperty("Properties")]
        public GroupProperties Properties { get; set; } = new GroupProperties();

        [JsonProperty("Members")]
        public List<GroupMember> Members { get; set; } = new List<GroupMember>();

        [JsonProperty("Aces")]
        public List<BloodHoundAce> Aces { get; set; } = new List<BloodHoundAce>();

        [JsonProperty("IsDeleted")]
        public bool IsDeleted { get; set; }

        [JsonProperty("IsACLProtected")]
        public bool IsACLProtected { get; set; }
    }

    public class GroupProperties
    {
        [JsonProperty("domain")]
        public string Domain { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("distinguishedname")]
        public string DistinguishedName { get; set; }

        [JsonProperty("samaccountname")]
        public string SamAccountName { get; set; }

        [JsonProperty("description")]
        public string Description { get; set; }

        [JsonProperty("whencreated")]
        public long WhenCreated { get; set; }

        [JsonProperty("admincount")]
        public bool AdminCount { get; set; }
    }

    #endregion

    #region Domain

    /// <summary>
    /// BloodHound Domain object
    /// </summary>
    public class BloodHoundDomain
    {
        [JsonProperty("ObjectIdentifier")]
        public string ObjectIdentifier { get; set; }

        [JsonProperty("Properties")]
        public DomainProperties Properties { get; set; } = new DomainProperties();

        [JsonProperty("ChildObjects")]
        public List<ChildObject> ChildObjects { get; set; } = new List<ChildObject>();

        [JsonProperty("Trusts")]
        public List<DomainTrust> Trusts { get; set; } = new List<DomainTrust>();

        [JsonProperty("Links")]
        public List<GPLink> Links { get; set; } = new List<GPLink>();

        [JsonProperty("Aces")]
        public List<BloodHoundAce> Aces { get; set; } = new List<BloodHoundAce>();

        [JsonProperty("IsDeleted")]
        public bool IsDeleted { get; set; }

        [JsonProperty("IsACLProtected")]
        public bool IsACLProtected { get; set; }
    }

    public class DomainProperties
    {
        [JsonProperty("domain")]
        public string Domain { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("distinguishedname")]
        public string DistinguishedName { get; set; }

        [JsonProperty("domainsid")]
        public string DomainSid { get; set; }

        [JsonProperty("description")]
        public string Description { get; set; }

        [JsonProperty("whencreated")]
        public long WhenCreated { get; set; }

        [JsonProperty("functionallevel")]
        public string FunctionalLevel { get; set; }

        [JsonProperty("highvalue")]
        public bool HighValue { get; set; } = true;
    }

    #endregion

    #region OU

    /// <summary>
    /// BloodHound OU object
    /// </summary>
    public class BloodHoundOU
    {
        [JsonProperty("ObjectIdentifier")]
        public string ObjectIdentifier { get; set; }

        [JsonProperty("Properties")]
        public OUProperties Properties { get; set; } = new OUProperties();

        [JsonProperty("ChildObjects")]
        public List<ChildObject> ChildObjects { get; set; } = new List<ChildObject>();

        [JsonProperty("Links")]
        public List<GPLink> Links { get; set; } = new List<GPLink>();

        [JsonProperty("Aces")]
        public List<BloodHoundAce> Aces { get; set; } = new List<BloodHoundAce>();

        [JsonProperty("IsDeleted")]
        public bool IsDeleted { get; set; }

        [JsonProperty("IsACLProtected")]
        public bool IsACLProtected { get; set; }
    }

    public class OUProperties
    {
        [JsonProperty("domain")]
        public string Domain { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("distinguishedname")]
        public string DistinguishedName { get; set; }

        [JsonProperty("description")]
        public string Description { get; set; }

        [JsonProperty("whencreated")]
        public long WhenCreated { get; set; }

        [JsonProperty("blocksinheritance")]
        public bool BlocksInheritance { get; set; }
    }

    #endregion

    #region GPO

    /// <summary>
    /// BloodHound GPO object
    /// </summary>
    public class BloodHoundGPO
    {
        [JsonProperty("ObjectIdentifier")]
        public string ObjectIdentifier { get; set; }

        [JsonProperty("Properties")]
        public GPOProperties Properties { get; set; } = new GPOProperties();

        [JsonProperty("Aces")]
        public List<BloodHoundAce> Aces { get; set; } = new List<BloodHoundAce>();

        [JsonProperty("IsDeleted")]
        public bool IsDeleted { get; set; }

        [JsonProperty("IsACLProtected")]
        public bool IsACLProtected { get; set; }
    }

    public class GPOProperties
    {
        [JsonProperty("domain")]
        public string Domain { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("distinguishedname")]
        public string DistinguishedName { get; set; }

        [JsonProperty("description")]
        public string Description { get; set; }

        [JsonProperty("whencreated")]
        public long WhenCreated { get; set; }

        [JsonProperty("gpcpath")]
        public string GpcPath { get; set; }

        [JsonProperty("highvalue")]
        public bool HighValue { get; set; }
    }

    #endregion

    #region Container

    /// <summary>
    /// BloodHound Container object
    /// </summary>
    public class BloodHoundContainer
    {
        [JsonProperty("ObjectIdentifier")]
        public string ObjectIdentifier { get; set; }

        [JsonProperty("Properties")]
        public ContainerProperties Properties { get; set; } = new ContainerProperties();

        [JsonProperty("ChildObjects")]
        public List<ChildObject> ChildObjects { get; set; } = new List<ChildObject>();

        [JsonProperty("Aces")]
        public List<BloodHoundAce> Aces { get; set; } = new List<BloodHoundAce>();

        [JsonProperty("IsDeleted")]
        public bool IsDeleted { get; set; }

        [JsonProperty("IsACLProtected")]
        public bool IsACLProtected { get; set; }
    }

    public class ContainerProperties
    {
        [JsonProperty("domain")]
        public string Domain { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("distinguishedname")]
        public string DistinguishedName { get; set; }
    }

    #endregion

    #region Certificate Services (ADCS)

    /// <summary>
    /// BloodHound Certificate Template object
    /// </summary>
    public class BloodHoundCertTemplate
    {
        [JsonProperty("ObjectIdentifier")]
        public string ObjectIdentifier { get; set; }

        [JsonProperty("Properties")]
        public CertTemplateProperties Properties { get; set; } = new CertTemplateProperties();

        [JsonProperty("Aces")]
        public List<BloodHoundAce> Aces { get; set; } = new List<BloodHoundAce>();

        [JsonProperty("IsDeleted")]
        public bool IsDeleted { get; set; }

        [JsonProperty("IsACLProtected")]
        public bool IsACLProtected { get; set; }
    }

    public class CertTemplateProperties
    {
        [JsonProperty("domain")]
        public string Domain { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("displayname")]
        public string DisplayName { get; set; }

        [JsonProperty("distinguishedname")]
        public string DistinguishedName { get; set; }

        [JsonProperty("description")]
        public string Description { get; set; }

        [JsonProperty("whencreated")]
        public long WhenCreated { get; set; }

        [JsonProperty("validityperiod")]
        public string ValidityPeriod { get; set; }

        [JsonProperty("renewalperiod")]
        public string RenewalPeriod { get; set; }

        [JsonProperty("schemaversion")]
        public int SchemaVersion { get; set; }

        [JsonProperty("enrollmentflag")]
        public int EnrollmentFlag { get; set; }

        [JsonProperty("certificatenameflag")]
        public int CertificateNameFlag { get; set; }

        [JsonProperty("enrolleesuppliessubject")]
        public bool EnrolleeSuppliesSubject { get; set; }

        [JsonProperty("subjectaltrequireupn")]
        public bool SubjectAltRequireUpn { get; set; }

        [JsonProperty("subjectaltrequiredns")]
        public bool SubjectAltRequireDns { get; set; }

        [JsonProperty("subjectaltrequiredomaindns")]
        public bool SubjectAltRequireDomainDns { get; set; }

        [JsonProperty("subjectaltrequireemail")]
        public bool SubjectAltRequireEmail { get; set; }

        [JsonProperty("subjectaltrequirespn")]
        public bool SubjectAltRequireSpn { get; set; }

        [JsonProperty("subjectrequireemail")]
        public bool SubjectRequireEmail { get; set; }

        [JsonProperty("requiresmanagerapproval")]
        public bool RequiresManagerApproval { get; set; }

        [JsonProperty("authenticationenabled")]
        public bool AuthenticationEnabled { get; set; }

        [JsonProperty("nosecurityextension")]
        public bool NoSecurityExtension { get; set; }

        [JsonProperty("ekus")]
        public List<string> Ekus { get; set; } = new List<string>();

        [JsonProperty("certificateapplicationpolicy")]
        public List<string> CertificateApplicationPolicy { get; set; } = new List<string>();

        [JsonProperty("authorizedsignatures")]
        public int AuthorizedSignatures { get; set; }

        [JsonProperty("applicationpolicies")]
        public List<string> ApplicationPolicies { get; set; } = new List<string>();

        [JsonProperty("issuancepolicies")]
        public List<string> IssuancePolicies { get; set; } = new List<string>();

        // ESC vulnerability indicators
        [JsonProperty("highvalue")]
        public bool HighValue { get; set; }
    }

    /// <summary>
    /// BloodHound Enterprise CA object
    /// </summary>
    public class BloodHoundEnterpriseCA
    {
        [JsonProperty("ObjectIdentifier")]
        public string ObjectIdentifier { get; set; }

        [JsonProperty("Properties")]
        public EnterpriseCaProperties Properties { get; set; } = new EnterpriseCaProperties();

        [JsonProperty("EnabledCertTemplates")]
        public List<TypedPrincipal> EnabledCertTemplates { get; set; } = new List<TypedPrincipal>();

        [JsonProperty("HostingComputer")]
        public string HostingComputer { get; set; }

        [JsonProperty("Aces")]
        public List<BloodHoundAce> Aces { get; set; } = new List<BloodHoundAce>();

        [JsonProperty("IsDeleted")]
        public bool IsDeleted { get; set; }

        [JsonProperty("IsACLProtected")]
        public bool IsACLProtected { get; set; }
    }

    public class EnterpriseCaProperties
    {
        [JsonProperty("domain")]
        public string Domain { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("distinguishedname")]
        public string DistinguishedName { get; set; }

        [JsonProperty("description")]
        public string Description { get; set; }

        [JsonProperty("whencreated")]
        public long WhenCreated { get; set; }

        [JsonProperty("dnshostname")]
        public string DnsHostname { get; set; }

        [JsonProperty("caname")]
        public string CaName { get; set; }

        [JsonProperty("certchain")]
        public List<string> CertChain { get; set; } = new List<string>();

        [JsonProperty("certname")]
        public string CertName { get; set; }

        [JsonProperty("certthumbprint")]
        public string CertThumbprint { get; set; }

        [JsonProperty("flags")]
        public int Flags { get; set; }

        [JsonProperty("highvalue")]
        public bool HighValue { get; set; } = true;
    }

    #endregion
}

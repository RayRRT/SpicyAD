using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace SpicyAD.BloodHound
{
    /// <summary>
    /// Writes BloodHound-compatible JSON files and creates ZIP output
    /// </summary>
    public class JsonWriter : IDisposable
    {
        private readonly string _outputDir;
        private readonly string _timestamp;
        private readonly bool _prettyPrint;
        private readonly CollectionMethod _methods;
        private readonly List<string> _outputFiles = new List<string>();
        private readonly JsonSerializerSettings _jsonSettings;

        public int TotalObjects { get; private set; }

        public JsonWriter(string outputDir = null, bool prettyPrint = false, CollectionMethod methods = CollectionMethod.Default)
        {
            _outputDir = outputDir ?? Directory.GetCurrentDirectory();
            _timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
            _prettyPrint = prettyPrint;
            _methods = methods;

            // Ensure output directory exists
            if (!Directory.Exists(_outputDir))
            {
                Directory.CreateDirectory(_outputDir);
            }

            // Configure JSON serialization
            _jsonSettings = new JsonSerializerSettings
            {
                ContractResolver = new CamelCasePropertyNamesContractResolver(),
                NullValueHandling = NullValueHandling.Ignore,
                Formatting = _prettyPrint ? Formatting.Indented : Formatting.None
            };
        }

        /// <summary>
        /// Write Users JSON file
        /// </summary>
        public void WriteUsers(List<BloodHoundUser> users)
        {
            var output = CreateOutput(users, "users");
            WriteFile("users", output);
            TotalObjects += users.Count;
            Console.WriteLine($"    [+] Users: {users.Count}");
        }

        /// <summary>
        /// Write Computers JSON file
        /// </summary>
        public void WriteComputers(List<BloodHoundComputer> computers)
        {
            var output = CreateOutput(computers, "computers");
            WriteFile("computers", output);
            TotalObjects += computers.Count;
            Console.WriteLine($"    [+] Computers: {computers.Count}");
        }

        /// <summary>
        /// Write Groups JSON file
        /// </summary>
        public void WriteGroups(List<BloodHoundGroup> groups)
        {
            var output = CreateOutput(groups, "groups");
            WriteFile("groups", output);
            TotalObjects += groups.Count;
            Console.WriteLine($"    [+] Groups: {groups.Count}");
        }

        /// <summary>
        /// Write Domains JSON file
        /// </summary>
        public void WriteDomains(List<BloodHoundDomain> domains)
        {
            var output = CreateOutput(domains, "domains");
            WriteFile("domains", output);
            TotalObjects += domains.Count;
            Console.WriteLine($"    [+] Domains: {domains.Count}");
        }

        /// <summary>
        /// Write OUs JSON file
        /// </summary>
        public void WriteOUs(List<BloodHoundOU> ous)
        {
            var output = CreateOutput(ous, "ous");
            WriteFile("ous", output);
            TotalObjects += ous.Count;
            Console.WriteLine($"    [+] OUs: {ous.Count}");
        }

        /// <summary>
        /// Write GPOs JSON file
        /// </summary>
        public void WriteGPOs(List<BloodHoundGPO> gpos)
        {
            var output = CreateOutput(gpos, "gpos");
            WriteFile("gpos", output);
            TotalObjects += gpos.Count;
            Console.WriteLine($"    [+] GPOs: {gpos.Count}");
        }

        /// <summary>
        /// Write Containers JSON file
        /// </summary>
        public void WriteContainers(List<BloodHoundContainer> containers)
        {
            var output = CreateOutput(containers, "containers");
            WriteFile("containers", output);
            TotalObjects += containers.Count;
            Console.WriteLine($"    [+] Containers: {containers.Count}");
        }

        /// <summary>
        /// Write Certificate Templates JSON file
        /// </summary>
        public void WriteCertTemplates(List<BloodHoundCertTemplate> templates)
        {
            var output = CreateOutput(templates, "certtemplates");
            WriteFile("certtemplates", output);
            TotalObjects += templates.Count;
            Console.WriteLine($"    [+] Certificate Templates: {templates.Count}");
        }

        /// <summary>
        /// Write Enterprise CAs JSON file
        /// </summary>
        public void WriteEnterpriseCAs(List<BloodHoundEnterpriseCA> cas)
        {
            var output = CreateOutput(cas, "enterprisecas");
            WriteFile("enterprisecas", output);
            TotalObjects += cas.Count;
            Console.WriteLine($"    [+] Enterprise CAs: {cas.Count}");
        }

        /// <summary>
        /// Create output wrapper with metadata
        /// </summary>
        private BloodHoundOutput<T> CreateOutput<T>(List<T> data, string type)
        {
            return new BloodHoundOutput<T>
            {
                Data = data,
                Meta = new BloodHoundMeta
                {
                    Type = type,
                    Count = data.Count,
                    Version = 6,
                    Methods = (long)_methods
                }
            };
        }

        /// <summary>
        /// Write JSON file to disk
        /// </summary>
        private void WriteFile<T>(string dataType, BloodHoundOutput<T> output)
        {
            string filename = $"{_timestamp}_{dataType}.json";
            string filepath = Path.Combine(_outputDir, filename);

            string json = JsonConvert.SerializeObject(output, _jsonSettings);
            File.WriteAllText(filepath, json, Encoding.UTF8);

            _outputFiles.Add(filepath);
        }

        /// <summary>
        /// Create final ZIP archive with all JSON files
        /// </summary>
        public string CreateZip(string zipName = null)
        {
            if (_outputFiles.Count == 0)
            {
                Console.WriteLine("[!] No data files to compress");
                return null;
            }

            string zipFilename = zipName ?? $"{_timestamp}_BloodHound.zip";
            string zipPath = Path.Combine(_outputDir, zipFilename);

            Console.WriteLine($"\n[*] Creating ZIP archive...");

            try
            {
                // Delete existing zip if present
                if (File.Exists(zipPath))
                {
                    File.Delete(zipPath);
                }

                using (var zipArchive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
                {
                    foreach (string file in _outputFiles)
                    {
                        string entryName = Path.GetFileName(file);
                        zipArchive.CreateEntryFromFile(file, entryName, CompressionLevel.Optimal);
                    }
                }

                // Delete individual JSON files after zipping
                foreach (string file in _outputFiles)
                {
                    try { File.Delete(file); } catch { }
                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] Output: {zipPath}");
                Console.ResetColor();

                return zipPath;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error creating ZIP: {ex.Message}");
                Console.WriteLine($"[*] Individual JSON files preserved in: {_outputDir}");
                return null;
            }
        }

        /// <summary>
        /// Get list of output files
        /// </summary>
        public List<string> GetOutputFiles()
        {
            return new List<string>(_outputFiles);
        }

        public void Dispose()
        {
            // Cleanup if needed
        }
    }

    /// <summary>
    /// Helper class for time conversion
    /// </summary>
    public static class TimeHelper
    {
        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// Convert DateTime to Unix timestamp (seconds)
        /// </summary>
        public static long ToUnixTimestamp(DateTime dateTime)
        {
            if (dateTime == DateTime.MinValue)
                return -1;

            return (long)(dateTime.ToUniversalTime() - Epoch).TotalSeconds;
        }

        /// <summary>
        /// Convert Windows FileTime to Unix timestamp
        /// </summary>
        public static long FileTimeToUnixTimestamp(long fileTime)
        {
            if (fileTime <= 0)
                return -1;

            try
            {
                DateTime dt = DateTime.FromFileTimeUtc(fileTime);
                return ToUnixTimestamp(dt);
            }
            catch
            {
                return -1;
            }
        }

        /// <summary>
        /// Convert Windows FileTime to Unix timestamp (from object)
        /// </summary>
        public static long FileTimeToUnixTimestamp(object fileTimeObj)
        {
            if (fileTimeObj == null)
                return -1;

            try
            {
                long fileTime = Convert.ToInt64(fileTimeObj);
                return FileTimeToUnixTimestamp(fileTime);
            }
            catch
            {
                return -1;
            }
        }
    }
}

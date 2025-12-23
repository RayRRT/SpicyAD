using System;
using System.IO;
using System.Text;

namespace SpicyAD
{
    
    /// Centralized output control for verbose/minimal modes and logging
    /// Default: minimal output. Use /verbose flag for detailed output.
    public static class OutputHelper
    {
        private static bool _verbose = false;
        private static bool _logging = false;
        private static string _logPath = null;
        private static StringBuilder _logBuffer = new StringBuilder();

        
        /// Enable or disable verbose output
        public static void SetVerbose(bool value)
        {
            _verbose = value;
        }

        
        /// Toggle verbose mode
        public static void ToggleVerbose()
        {
            _verbose = !_verbose;
        }

        
        /// Check if verbose mode is enabled
        public static bool IsVerbose => _verbose;

        
        /// Check if logging is enabled
        public static bool IsLogging => _logging;

        
        /// Get current log path
        public static string LogPath => _logPath;

        
        /// Enable logging to file
        public static void EnableLogging(string path = null)
        {
            if (string.IsNullOrEmpty(path))
            {
                // Default: current directory with timestamp
                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                _logPath = Path.Combine(Environment.CurrentDirectory, $"SpicyAD_log_{timestamp}.txt");
            }
            else
            {
                // Check if path is a directory or file
                if (Directory.Exists(path))
                {
                    string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                    _logPath = Path.Combine(path, $"SpicyAD_log_{timestamp}.txt");
                }
                else
                {
                    _logPath = path;
                }
            }

            _logging = true;
            _logBuffer.Clear();

            // Write header
            string header = $"SpicyAD Log - Started at {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n";
            header += $"{"".PadRight(50, '=')}\n\n";
            _logBuffer.Append(header);

            Console.WriteLine($"[+] Logging enabled: {_logPath}");
        }

        
        /// Disable logging and save file
        public static void DisableLogging()
        {
            if (_logging && !string.IsNullOrEmpty(_logPath))
            {
                try
                {
                    // Write footer
                    _logBuffer.Append($"\n{"".PadRight(50, '=')}\n");
                    _logBuffer.Append($"SpicyAD Log - Ended at {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n");

                    File.WriteAllText(_logPath, _logBuffer.ToString());
                    Console.WriteLine($"[+] Log saved: {_logPath}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Error saving log: {ex.Message}");
                }
            }

            _logging = false;
            _logPath = null;
            _logBuffer.Clear();
        }

        
        /// Write to log buffer if logging is enabled
        private static void WriteToLog(string message)
        {
            if (_logging)
            {
                _logBuffer.AppendLine(message);
            }
        }

        
        /// Flush log to file (call periodically for long operations)
        public static void FlushLog()
        {
            if (_logging && !string.IsNullOrEmpty(_logPath) && _logBuffer.Length > 0)
            {
                try
                {
                    File.AppendAllText(_logPath, _logBuffer.ToString());
                    _logBuffer.Clear();
                }
                catch { }
            }
        }

        
        /// Print only in verbose mode
        public static void Verbose(string message)
        {
            if (_verbose)
            {
                Console.WriteLine(message);
            }
            // Always log verbose messages if logging is enabled
            WriteToLog(message);
        }

        
        /// Print only in verbose mode (no newline)
        public static void VerboseWrite(string message)
        {
            if (_verbose)
                Console.Write(message);
            // Log with marker for no-newline
            if (_logging)
                _logBuffer.Append(message);
        }

        
        /// Always print (important info) and log
        public static void Info(string message)
        {
            Console.WriteLine(message);
            WriteToLog(message);
        }

        
        /// Print success message (always shown) and log
        public static void Success(string message)
        {
            Console.WriteLine($"[+] {message}");
            WriteToLog($"[+] {message}");
        }

        
        /// Print error message (always shown) and log
        public static void Error(string message)
        {
            Console.WriteLine($"[!] {message}");
            WriteToLog($"[!] {message}");
        }

        
        /// Print status message (always shown) and log
        public static void Status(string message)
        {
            Console.WriteLine($"[*] {message}");
            WriteToLog($"[*] {message}");
        }

        
        /// Log a message without printing to console
        public static void LogOnly(string message)
        {
            WriteToLog(message);
        }

        
        /// Print and log (wrapper for Console.WriteLine that also logs)
        public static void WriteLine(string message)
        {
            Console.WriteLine(message);
            WriteToLog(message);
        }

        
        /// Print and log without newline
        public static void Write(string message)
        {
            Console.Write(message);
            if (_logging)
                _logBuffer.Append(message);
        }
    }
}

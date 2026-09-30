// OfficeSecurity-Setup.exe - made by MAKE-SETUP.bat with the C# compiler that is part of Windows
// (.NET Framework 4.8). The program files are embedded in it as "payload.zip". When started it
// unpacks them to a temporary folder, runs install.ps1 (the readable setup steps) and removes the
// temporary folder again. Arguments are passed on, for example: -Role Main -Quiet
// Written for the C# 5 compiler that ships with Windows.
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Text;
using System.Windows.Forms;

[assembly: AssemblyTitle("Office Computer Security Setup")]
[assembly: AssemblyProduct("Office Computer Security System")]
[assembly: AssemblyCompany("Office Computer Security System")]
[assembly: AssemblyVersion("0.1.0.0")]
[assembly: AssemblyFileVersion("0.1.0.0")]

internal static class Setup
{
    [STAThread]
    private static int Main(string[] args)
    {
        var work = Path.Combine(Path.GetTempPath(), "OfficeSecuritySetup-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(work);
            using (var payload = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip"))
            {
                if (payload == null)
                {
                    throw new InvalidOperationException("This setup program is incomplete (no program files inside). Make it again with MAKE-SETUP.bat.");
                }

                using (var zip = new ZipArchive(payload, ZipArchiveMode.Read))
                {
                    zip.ExtractToDirectory(work);
                }
            }

            var command = new StringBuilder("-NoProfile -ExecutionPolicy Bypass -File ");
            command.Append(Quote(Path.Combine(work, "install.ps1")));
            foreach (var arg in args)
            {
                command.Append(' ').Append(Quote(arg));
            }

            var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"), command.ToString());
            start.UseShellExecute = false;
            start.WorkingDirectory = work;
            using (var process = Process.Start(start))
            {
                process.WaitForExit();
                return process.ExitCode;
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show("Setup could not start:\n\n" + ex.Message, "Office Computer Security setup", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
        finally
        {
            try
            {
                Directory.Delete(work, true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private static string Quote(string value)
    {
        if (value.Length > 0 && value.IndexOfAny(new[] { ' ', '\t', '"' }) < 0)
        {
            return value;
        }

        // Standard Windows command-line quoting: backslashes before a quote are doubled.
        var result = new StringBuilder("\"");
        var backslashes = 0;
        foreach (var c in value)
        {
            if (c == '\\')
            {
                backslashes++;
                continue;
            }

            if (c == '"')
            {
                result.Append('\\', backslashes * 2 + 1);
            }
            else
            {
                result.Append('\\', backslashes);
            }

            backslashes = 0;
            result.Append(c);
        }

        result.Append('\\', backslashes * 2).Append('"');
        return result.ToString();
    }
}

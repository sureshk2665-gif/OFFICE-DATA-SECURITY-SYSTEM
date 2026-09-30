// OfficeSecurity-Setup.exe - made by MAKE-SETUP.bat with the C# compiler that is part of Windows
// (.NET Framework 4.8). The program files are embedded in it as "payload.zip".
//
// Double-clicked: a normal setup wizard (Welcome, type of computer, codes, progress, Finish).
// The actual steps are in install.ps1 (readable text), which the wizard runs without a window.
// With -Quiet (or -Uninstall) the arguments go straight to install.ps1, for unattended use and tests.
// "--smoke-test" builds every wizard page without showing it (used by the build pipeline).
//
// Written for the C# 5 compiler that ships with Windows (no newer language features).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Windows.Forms;

[assembly: AssemblyTitle("Office Computer Security Setup")]
[assembly: AssemblyProduct("Office Computer Security System")]
[assembly: AssemblyCompany("Office Computer Security System")]
[assembly: AssemblyVersion("0.1.0.0")]
[assembly: AssemblyFileVersion("0.1.0.0")]

internal static class Setup
{
    public const string ProductName = "Office Computer Security";

    [STAThread]
    private static int Main(string[] args)
    {
        if (HasArg(args, "-Quiet") || HasArg(args, "-Uninstall"))
        {
            return RunDirect(args);
        }

        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        if (HasArg(args, "--smoke-test"))
        {
            return Wizard.SmokeTest();
        }

        using (var wizard = new Wizard())
        {
            Application.Run(wizard);
            return wizard.ExitCode;
        }
    }

    private static bool HasArg(string[] args, string name)
    {
        foreach (var arg in args)
        {
            if (string.Equals(arg, name, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static int RunDirect(string[] args)
    {
        string work = null;
        try
        {
            work = Unpack();
            using (var process = Process.Start(PowerShell(work, args, false)))
            {
                process.WaitForExit();
                return process.ExitCode;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Setup could not start: " + ex.Message);
            return 1;
        }
        finally
        {
            DeleteFolder(work);
        }
    }

    public static string Unpack()
    {
        var work = Path.Combine(Path.GetTempPath(), "OfficeSecuritySetup-" + Guid.NewGuid().ToString("N"));
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

        return work;
    }

    public static ProcessStartInfo PowerShell(string work, IEnumerable<string> args, bool hidden)
    {
        var command = new StringBuilder("-NoProfile -ExecutionPolicy Bypass -File ");
        command.Append(Quote(Path.Combine(work, "install.ps1")));
        foreach (var arg in args)
        {
            command.Append(' ').Append(Quote(arg));
        }

        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"), command.ToString());
        start.UseShellExecute = false;
        start.WorkingDirectory = work;
        if (hidden)
        {
            start.CreateNoWindow = true;
            start.RedirectStandardOutput = true;
            start.RedirectStandardError = true;
            start.StandardOutputEncoding = Encoding.UTF8;
        }

        return start;
    }

    public static void DeleteFolder(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return;
        }

        try
        {
            Directory.Delete(path, true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
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

/// <summary>The setup wizard window.</summary>
internal sealed class Wizard : Form
{
    private static readonly Font TitleFont = new Font("Segoe UI", 12F, FontStyle.Bold);
    private static readonly Font BodyFont = new Font("Segoe UI", 9.75F);
    private static readonly Font BoldFont = new Font("Segoe UI", 9.75F, FontStyle.Bold);

    private readonly Label headerTitle = new Label();
    private readonly Label headerText = new Label();
    private readonly Panel body = new Panel();
    private readonly Button back = new Button();
    private readonly Button next = new Button();
    private readonly Button cancel = new Button();

    private readonly Panel welcomePage = new Panel();
    private readonly Label welcomeText = new Label();
    private readonly Panel typePage = new Panel();
    private readonly RadioButton mainChoice = new RadioButton();
    private readonly RadioButton staffChoice = new RadioButton();
    private readonly Panel codesPage = new Panel();
    private readonly TextBox serverBox = new TextBox();
    private readonly TextBox pairingBox = new TextBox();
    private readonly TextBox enrollmentBox = new TextBox();
    private readonly Panel progressPage = new Panel();
    private readonly Label progressStep = new Label();
    private readonly ProgressBar progressBar = new ProgressBar();
    private readonly TextBox progressDetails = new TextBox();
    private readonly Panel finishPage = new Panel();
    private readonly Label finishText = new Label();
    private readonly TextBox finishDetails = new TextBox();
    private readonly Button copyDetails = new Button();
    private readonly CheckBox openNow = new CheckBox();

    private readonly string installedRole;
    private Panel current;
    private bool installing;
    private bool succeeded;
    private string logFile;

    public Wizard()
    {
        installedRole = ReadInstalledRole();
        ExitCode = 2;

        Text = Setup.ProductName + " Setup";
        ClientSize = new Size(620, 440);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = true;
        StartPosition = FormStartPosition.CenterScreen;
        Font = BodyFont;
        BackColor = SystemColors.Control;
        try
        {
            Icon = Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location);
        }
        catch (ArgumentException)
        {
        }

        // Header (white band with title and one line of explanation), like other Windows setup programs.
        var header = new Panel { Dock = DockStyle.Top, Height = 70, BackColor = Color.White };
        headerTitle.Font = TitleFont;
        headerTitle.SetBounds(20, 12, 580, 26);
        headerText.SetBounds(22, 40, 580, 22);
        headerText.ForeColor = Color.FromArgb(80, 80, 80);
        header.Controls.Add(headerTitle);
        header.Controls.Add(headerText);
        var headerLine = new Label { Dock = DockStyle.Top, Height = 1, BackColor = Color.FromArgb(210, 210, 210) };

        var footer = new Panel { Dock = DockStyle.Bottom, Height = 56 };
        var footerLine = new Label { Dock = DockStyle.Top, Height = 1, BackColor = Color.FromArgb(210, 210, 210) };
        footer.Controls.Add(footerLine);
        back.Text = "< Back";
        back.SetBounds(330, 14, 88, 28);
        back.Click += delegate { GoBack(); };
        next.Text = "Next >";
        next.SetBounds(422, 14, 88, 28);
        next.Click += delegate { GoNext(); };
        cancel.Text = "Cancel";
        cancel.SetBounds(520, 14, 88, 28);
        cancel.Click += delegate { Close(); };
        footer.Controls.Add(back);
        footer.Controls.Add(next);
        footer.Controls.Add(cancel);
        AcceptButton = next;

        body.Dock = DockStyle.Fill;
        body.Padding = new Padding(24, 16, 24, 8);

        Controls.Add(body);
        Controls.Add(footer);
        Controls.Add(headerLine);
        Controls.Add(header);

        BuildWelcome();
        BuildType();
        BuildCodes();
        BuildProgress();
        BuildFinish();
        ShowPage(welcomePage);
    }

    public int ExitCode { get; private set; }

    public static int SmokeTest()
    {
        using (var wizard = new Wizard())
        {
            foreach (var page in new[] { wizard.welcomePage, wizard.typePage, wizard.codesPage, wizard.progressPage, wizard.finishPage })
            {
                wizard.ShowPage(page);
                wizard.PerformLayout();
            }
        }

        return 0;
    }

    private bool IsUpdate
    {
        get { return installedRole == "MAIN" || installedRole == "STAFF"; }
    }

    // ------------------------------------------------------------------ pages
    private void BuildWelcome()
    {
        welcomeText.SetBounds(0, 0, 570, 250);
        if (IsUpdate)
        {
            welcomeText.Text = Product() + " is already installed on this computer (" +
                (installedRole == "MAIN" ? "main office computer" : "staff computer") + ").\r\n\r\n" +
                "Setup will update it to this version. All accounts, computers, settings and records are kept" +
                (installedRole == "STAFF" ? ", and this computer stays registered." : ".") +
                "\r\n\r\nClick Install to continue.";
        }
        else
        {
            welcomeText.Text = "This will install " + Product() + " on this computer.\r\n\r\n" +
                "After setup, open \"Office Security\" from the desktop. Administrators and staff each have " +
                "their own separate sign-in and their own screens.\r\n\r\n" +
                "Install it on the MAIN OFFICE COMPUTER first (the computer that stays switched on), " +
                "then on each staff computer.\r\n\r\n" +
                "Click Next to continue.";
        }

        welcomePage.Controls.Add(welcomeText);
    }

    private void BuildType()
    {
        mainChoice.Text = "Main office computer";
        mainChoice.Font = BoldFont;
        mainChoice.SetBounds(0, 4, 560, 24);
        var mainText = new Label
        {
            Text = "Choose this for ONE computer only. It runs the office security server and has the Administrator sign-in.",
            ForeColor = Color.FromArgb(70, 70, 70),
        };
        mainText.SetBounds(20, 30, 540, 40);

        staffChoice.Text = "Staff computer";
        staffChoice.Font = BoldFont;
        staffChoice.SetBounds(0, 88, 560, 24);
        var staffText = new Label
        {
            Text = "Choose this for every other office computer. It installs the protection and the Staff sign-in. " +
                   "You need three codes from the Administrator sign-in on the main computer: Computers > Add computer.",
            ForeColor = Color.FromArgb(70, 70, 70),
        };
        staffText.SetBounds(20, 114, 540, 56);

        mainChoice.CheckedChanged += delegate { UpdateButtons(); };
        staffChoice.CheckedChanged += delegate { UpdateButtons(); };
        typePage.Controls.AddRange(new Control[] { mainChoice, mainText, staffChoice, staffText });
    }

    private void BuildCodes()
    {
        var intro = new Label
        {
            Text = "On the main office computer open Office Security > Administrator sign-in > Computers > Add computer, and type what it shows:",
        };
        intro.SetBounds(0, 0, 570, 40);
        codesPage.Controls.Add(intro);

        var y = 48;
        AddField(codesPage, "Server address (for example 192.168.0.166):", serverBox, ref y);
        AddField(codesPage, "Pairing code:", pairingBox, ref y);
        AddField(codesPage, "Enrollment code (valid for 24 hours):", enrollmentBox, ref y);
        serverBox.TextChanged += delegate { UpdateButtons(); };
        pairingBox.TextChanged += delegate { UpdateButtons(); };
        enrollmentBox.TextChanged += delegate { UpdateButtons(); };
    }

    private static void AddField(Panel page, string label, TextBox box, ref int y)
    {
        var caption = new Label { Text = label };
        caption.SetBounds(0, y, 560, 20);
        box.SetBounds(0, y + 22, 400, 24);
        page.Controls.Add(caption);
        page.Controls.Add(box);
        y += 58;
    }

    private void BuildProgress()
    {
        progressStep.SetBounds(0, 4, 570, 22);
        progressBar.SetBounds(0, 32, 570, 22);
        progressBar.Style = ProgressBarStyle.Marquee;
        progressBar.MarqueeAnimationSpeed = 30;
        progressDetails.SetBounds(0, 70, 570, 190);
        progressDetails.Multiline = true;
        progressDetails.ReadOnly = true;
        progressDetails.ScrollBars = ScrollBars.Vertical;
        progressDetails.BackColor = Color.White;
        progressDetails.Font = new Font("Consolas", 8.5F);
        progressPage.Controls.AddRange(new Control[] { progressStep, progressBar, progressDetails });
    }

    private void BuildFinish()
    {
        finishText.SetBounds(0, 0, 570, 96);
        finishDetails.SetBounds(0, 100, 570, 130);
        finishDetails.Multiline = true;
        finishDetails.ReadOnly = true;
        finishDetails.ScrollBars = ScrollBars.Vertical;
        finishDetails.BackColor = Color.White;
        finishDetails.Font = new Font("Consolas", 10F);
        copyDetails.Text = "Copy";
        copyDetails.SetBounds(0, 236, 88, 26);
        copyDetails.Click += delegate
        {
            try
            {
                Clipboard.SetText(finishDetails.Text);
                copyDetails.Text = "Copied";
            }
            catch (System.Runtime.InteropServices.ExternalException)
            {
            }
        };
        openNow.Text = "Open Office Security now";
        openNow.Checked = true;
        openNow.SetBounds(0, 272, 400, 24);
        finishPage.Controls.AddRange(new Control[] { finishText, finishDetails, copyDetails, openNow });
    }

    private void ShowPage(Panel page)
    {
        body.Controls.Clear();
        page.Dock = DockStyle.Fill;
        body.Controls.Add(page);
        current = page;

        if (page == welcomePage)
        {
            SetHeader(IsUpdate ? "Update " + Product() : "Welcome to " + Product() + " Setup", "Protects office computers. Version 0.1.");
        }
        else if (page == typePage)
        {
            SetHeader("Type of computer", "What will this computer be used as?");
        }
        else if (page == codesPage)
        {
            SetHeader("Connect to the main office computer", "These codes connect this computer to your office server.");
        }
        else if (page == progressPage)
        {
            SetHeader(IsUpdate ? "Updating" : "Installing", "Please wait while " + Product() + " is set up. This takes about a minute.");
        }
        else if (page == finishPage)
        {
            SetHeader(succeeded ? "Setup complete" : "Setup could not finish", succeeded ? Product() + " is ready." : "Nothing was left half-installed.");
        }

        UpdateButtons();
    }

    private void SetHeader(string title, string text)
    {
        headerTitle.Text = title;
        headerText.Text = text;
    }

    private void UpdateButtons()
    {
        back.Visible = current == typePage || current == codesPage || (current == finishPage && !succeeded);
        back.Enabled = true;
        cancel.Visible = current != finishPage;
        cancel.Enabled = !installing;
        next.Enabled = !installing;
        if (current == welcomePage)
        {
            next.Text = IsUpdate ? "Install" : "Next >";
        }
        else if (current == typePage)
        {
            next.Text = mainChoice.Checked ? "Install" : "Next >";
            next.Enabled = mainChoice.Checked || staffChoice.Checked;
        }
        else if (current == codesPage)
        {
            next.Text = "Install";
            next.Enabled = serverBox.Text.Trim().Length > 0 && pairingBox.Text.Trim().Length > 0 && enrollmentBox.Text.Trim().Length > 0;
        }
        else if (current == progressPage)
        {
            next.Text = "Next >";
            next.Enabled = false;
        }
        else if (current == finishPage)
        {
            next.Text = "Finish";
            next.Enabled = true;
        }
    }

    private void GoBack()
    {
        if (current == typePage)
        {
            ShowPage(welcomePage);
        }
        else if (current == codesPage)
        {
            ShowPage(typePage);
        }
        else if (current == finishPage && !succeeded)
        {
            // For example a mistyped code: go back and correct it.
            ShowPage(ChosenRole() == "Staff" && !IsUpdate ? codesPage : welcomePage);
        }
    }

    private void GoNext()
    {
        if (current == welcomePage)
        {
            if (IsUpdate)
            {
                StartInstall();
            }
            else
            {
                ShowPage(typePage);
            }
        }
        else if (current == typePage)
        {
            if (mainChoice.Checked)
            {
                StartInstall();
            }
            else
            {
                ShowPage(codesPage);
            }
        }
        else if (current == codesPage)
        {
            StartInstall();
        }
        else if (current == finishPage)
        {
            if (succeeded && openNow.Checked)
            {
                OpenProgram();
            }

            Close();
        }
    }

    private string ChosenRole()
    {
        if (installedRole == "MAIN")
        {
            return "Main";
        }

        if (installedRole == "STAFF")
        {
            return "Staff";
        }

        return mainChoice.Checked ? "Main" : "Staff";
    }

    // ------------------------------------------------------------------ installing
    private void StartInstall()
    {
        installing = true;
        progressDetails.Clear();
        progressStep.Text = "Unpacking the program files...";
        ShowPage(progressPage);

        var role = ChosenRole();
        var args = new List<string> { "-Role", role, "-Quiet" };
        if (role == "Staff" && !IsUpdate)
        {
            args.AddRange(new[] { "-Server", serverBox.Text.Trim(), "-PairingCode", pairingBox.Text.Trim(), "-EnrollmentCode", enrollmentBox.Text.Trim() });
        }

        var resultFile = Path.Combine(Path.GetTempPath(), "OfficeSecuritySetup-result-" + Guid.NewGuid().ToString("N") + ".txt");
        logFile = Path.Combine(Path.GetTempPath(), "OfficeSecurity-Setup.log");
        args.AddRange(new[] { "-ResultFile", resultFile, "-LogFile", logFile });

        var worker = new Thread(delegate() { Install(args, resultFile); });
        worker.IsBackground = true;
        worker.Start();
    }

    private void Install(List<string> args, string resultFile)
    {
        string work = null;
        var exitCode = 1;
        Dictionary<string, string> result;
        try
        {
            work = Setup.Unpack();
            using (var process = new Process())
            {
                process.StartInfo = Setup.PowerShell(work, args, true);
                process.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) { OnOutput(e.Data); } };
                process.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) { OnOutput(e.Data); } };
                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                process.WaitForExit();
                exitCode = process.ExitCode;
            }

            result = ReadResult(resultFile);
        }
        catch (Exception ex)
        {
            result = new Dictionary<string, string>();
            result["Message"] = ex.Message;
        }
        finally
        {
            Setup.DeleteFolder(work);
            try
            {
                File.Delete(resultFile);
            }
            catch (IOException)
            {
            }
        }

        BeginInvoke((MethodInvoker)delegate { Finished(exitCode, result); });
    }

    private void OnOutput(string line)
    {
        BeginInvoke((MethodInvoker)delegate
        {
            if (line.StartsWith("STEP: ", StringComparison.Ordinal))
            {
                progressStep.Text = line.Substring(6);
            }

            progressDetails.AppendText(line + "\r\n");
        });
    }

    private static Dictionary<string, string> ReadResult(string file)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!File.Exists(file))
        {
            return values;
        }

        foreach (var line in File.ReadAllLines(file, Encoding.UTF8))
        {
            var split = line.IndexOf('=');
            if (split > 0)
            {
                values[line.Substring(0, split)] = line.Substring(split + 1).Replace("\\n", "\r\n");
            }
        }

        return values;
    }

    private void Finished(int exitCode, Dictionary<string, string> result)
    {
        installing = false;
        succeeded = exitCode == 0;
        ExitCode = exitCode;
        string value;

        if (succeeded)
        {
            var role = result.TryGetValue("Role", out value) ? value : ChosenRole();
            var updated = result.TryGetValue("Status", out value) && value == "Updated";
            if (role == "Main")
            {
                finishText.Text = (updated ? "The main office computer was updated." : "This is now the main office computer. The server runs in the background and starts with Windows.") +
                    "\r\n\r\nNext: open Office Security and choose Administrator sign-in. The server address and pairing code are filled in for you." +
                    (result.ContainsKey("SetupCode") ? " The first time, create the administrator with the setup code below." : string.Empty);
                var details = new StringBuilder();
                if (result.TryGetValue("SetupCode", out value))
                {
                    details.Append("First administrator setup code:  ").Append(value).Append("\r\n\r\n");
                }

                if (result.TryGetValue("Addresses", out value))
                {
                    details.Append("Address for staff computers:  ").Append(value.Replace("|", "  or  ")).Append("\r\n");
                }

                if (result.TryGetValue("PairingCode", out value))
                {
                    details.Append("Pairing code:  ").Append(value).Append("\r\n");
                }

                details.Append("\r\n(Also saved in C:\\ProgramData\\OfficeSecurity\\Server)");
                finishDetails.Text = details.ToString();
                finishDetails.Visible = true;
                copyDetails.Visible = true;
            }
            else
            {
                finishText.Text = updated
                    ? "This staff computer was updated and is still protected."
                    : "This staff computer is now protected and registered.\r\n\r\nLast step: on the main office computer open Administrator sign-in > Computers, select this computer and click Approve.";
                finishText.Text += "\r\n\r\nStaff open Office Security from the desktop and choose Staff sign-in.";
                finishDetails.Visible = false;
                copyDetails.Visible = false;
            }

            openNow.Visible = true;
        }
        else
        {
            var message = result.TryGetValue("Message", out value) && value.Length > 0 ? value : "Setup stopped unexpectedly.";
            finishText.Text = message;
            finishDetails.Text = "Details were saved in " + logFile + "\r\n\r\n" + progressDetails.Text;
            finishDetails.Visible = true;
            copyDetails.Visible = true;
            openNow.Visible = false;
            openNow.Checked = false;
        }

        finishDetails.SelectionLength = 0;
        ShowPage(finishPage);
    }

    private static void OpenProgram()
    {
        var program = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"OfficeSecurity\App\OfficeSecurity.exe");
        if (!File.Exists(program))
        {
            return;
        }

        // Started through Explorer so it runs with normal (not administrator) rights, like a desktop shortcut.
        try
        {
            Process.Start(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), "\"" + program + "\"");
        }
        catch (System.ComponentModel.Win32Exception)
        {
        }
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (installing)
        {
            // Stopping half-way could leave a computer without its server or protection.
            e.Cancel = true;
            return;
        }

        if (current != finishPage && current != null && e.CloseReason == CloseReason.UserClosing &&
            MessageBox.Show(this, "Cancel setup? Nothing has been changed on this computer.", Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
        {
            e.Cancel = true;
            return;
        }

        base.OnFormClosing(e);
    }

    private static string Product()
    {
        return Setup.ProductName;
    }

    private static string ReadInstalledRole()
    {
        try
        {
            var file = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"OfficeSecurity\App\role.txt");
            return File.Exists(file) ? File.ReadAllText(file).Trim().ToUpperInvariant() : string.Empty;
        }
        catch (IOException)
        {
            return string.Empty;
        }
        catch (UnauthorizedAccessException)
        {
            return string.Empty;
        }
    }
}

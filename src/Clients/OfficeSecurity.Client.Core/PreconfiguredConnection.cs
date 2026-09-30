namespace OfficeSecurity.Client.Core;

/// <summary>
/// Server address and pairing code written by the setup program ("connection.txt" next to the program, in
/// Program Files so only administrators can change it). Used only to fill in the Connect screen: pairing still
/// checks the server against the pairing code exactly as when they are typed.
/// </summary>
public sealed record PreconfiguredConnection(string ServerAddress, string PairingCode)
{
    public static PreconfiguredConnection? Read() => Read(Path.Combine(AppContext.BaseDirectory, "connection.txt"));

    public static PreconfiguredConnection? Read(string file)
    {
        try
        {
            if (!File.Exists(file))
            {
                return null;
            }

            var lines = File.ReadAllLines(file).Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
            return lines.Count >= 2 && lines[0].Length <= 255 && lines[1].Length <= 64 ? new PreconfiguredConnection(lines[0], lines[1]) : null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }
}

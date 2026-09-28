namespace OfficeSecurity.Server.Application.Reports;

/// <summary>One table in a report.</summary>
public sealed record ReportSection(string Heading, IReadOnlyList<string> Columns, IReadOnlyList<IReadOnlyList<string>> Rows, string? Note = null);

/// <summary>A finished report, independent of the file format.</summary>
public sealed record ReportDocument(
    string Title,
    string Period,
    IReadOnlyList<KeyValuePair<string, string>> Facts,
    IReadOnlyList<ReportSection> Sections,
    string GeneratedText);

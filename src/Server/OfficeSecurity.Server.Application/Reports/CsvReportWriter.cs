using System.Text;

namespace OfficeSecurity.Server.Application.Reports;

/// <summary>
/// CSV (RFC 4180) in UTF-8 with a byte-order mark, so Excel opens it with the right characters. A report with
/// one table is written as that table only; a report with several tables gets a heading line before each.
/// Cells that a spreadsheet would treat as a formula are prefixed with an apostrophe (CSV injection).
/// </summary>
public static class CsvReportWriter
{
    public static byte[] Write(ReportDocument report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var text = new StringBuilder();
        var single = report.Sections.Count == 1;
        foreach (var section in report.Sections)
        {
            if (!single)
            {
                Line(text, [section.Heading]);
            }

            Line(text, section.Columns);
            foreach (var row in section.Rows)
            {
                Line(text, row);
            }

            if (section.Note is not null)
            {
                Line(text, [section.Note]);
            }

            if (!single)
            {
                text.Append("\r\n");
            }
        }

        var preamble = Encoding.UTF8.GetPreamble();
        var body = Encoding.UTF8.GetBytes(text.ToString());
        return [.. preamble, .. body];
    }

    public static string Cell(string? value)
    {
        value ??= string.Empty;
        if (value.Length > 0 && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
        {
            value = "'" + value;
        }

        return value.IndexOfAny([',', '"', '\r', '\n']) >= 0 || value != value.Trim()
            ? "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\""
            : value;
    }

    private static void Line(StringBuilder text, IEnumerable<string> cells)
    {
        text.AppendJoin(',', cells.Select(Cell));
        text.Append("\r\n");
    }
}

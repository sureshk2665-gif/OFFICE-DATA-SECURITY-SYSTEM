using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using OfficeSecurity.Server.Application.Reports;

namespace OfficeSecurity.Server.UnitTests;

public sealed partial class ReportWriterTests
{
    private static ReportDocument Sample(int rows) => new(
        "Blocked activity",
        "Period: 2026-09-21 00:00 to 2026-09-28 00:00",
        [new("Computer", "PC-01 (Accounts)")],
        [
            new ReportSection("Blocked activity", ["Time", "Computer", "Event", "Severity", "Details"],
                Enumerable.Range(1, rows).Select(i => (IReadOnlyList<string>)
                [
                    "2026-09-2" + (i % 7) + " 10:00", "PC-01", "Program blocked", "Warning",
                    i % 10 == 0
                        ? $"Blocked: C:\\{string.Concat(Enumerable.Repeat("VeryLongFolderNameWithoutSpaces", 12))}\\p{i}.exe and a longer explanation that has to wrap onto the next lines of the cell because it is long"
                        : $"Blocked by Application Control: C:\\Users\\anna\\AppData\\Local\\Temp\\very-long-folder-name-{i}\\program (copy) {i}.exe — started by explorer.exe",
                ]).ToList()),
        ],
        "Created 2026-09-28 09:00 by Owner · Office Security System");

    [Fact]
    public void Pdf_has_a_valid_structure_and_long_tables_continue_on_more_pages()
    {
        var pdf = PdfReportWriter.Write(Sample(300));
        var text = Encoding.Latin1.GetString(pdf);

        Assert.StartsWith("%PDF-1.4\n", text, StringComparison.Ordinal);
        Assert.EndsWith("%%EOF\n", text, StringComparison.Ordinal);

        // The cross-reference table points exactly at every object.
        var startXref = long.Parse(StartXref().Match(text).Groups[1].Value, CultureInfo.InvariantCulture);
        Assert.StartsWith("xref\n", text[(int)startXref..], StringComparison.Ordinal);
        var offsets = XrefEntry().Matches(text[(int)startXref..]).Select(m => int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture)).ToList();
        for (var i = 0; i < offsets.Count; i++)
        {
            Assert.StartsWith($"{i + 1} 0 obj\n", text[offsets[i]..], StringComparison.Ordinal);
        }

        // Every content stream's declared length is right.
        foreach (Match stream in StreamObject().Matches(text))
        {
            Assert.Equal(int.Parse(stream.Groups[1].Value, CultureInfo.InvariantCulture), stream.Groups[2].Value.Length);
        }

        var pages = int.Parse(PageCount().Match(text).Groups[1].Value, CultureInfo.InvariantCulture);
        Assert.True(pages >= 4, $"300 wrapped rows should need several pages, got {pages}");
        Assert.Contains($"(Page {pages} of {pages})", text, StringComparison.Ordinal);
        Assert.Contains("(Blocked activity \\(continued\\))", text, StringComparison.Ordinal); // header repeated; brackets escaped
        Assert.Contains("\\227", text, StringComparison.Ordinal); // the dash, as a Windows-1252 character
    }

    [Fact]
    public void Pdf_text_is_limited_to_the_font_characters()
    {
        Assert.Equal("Café -> OK ? ?", PdfReportWriter.ToFontText("Café → ✓ \u0B9A \u4E2D"));
        Assert.Equal("a b", PdfReportWriter.ToFontText("a\tb"));
        Assert.Equal(string.Empty, PdfReportWriter.ToFontText(null));
    }

    [Fact]
    public void Empty_sections_are_shown_as_empty()
    {
        var report = Sample(0);
        Assert.Contains("\\(nothing in this period\\)", Encoding.Latin1.GetString(PdfReportWriter.Write(report)), StringComparison.Ordinal);
        var sample = Environment.GetEnvironmentVariable("OCSS_PDF_SAMPLE");
        if (!string.IsNullOrEmpty(sample))
        {
            File.WriteAllBytes(sample, PdfReportWriter.Write(Sample(300))); // for checking with an independent PDF reader
        }
    }

    [Fact]
    public void Csv_quotes_and_neutralises_formulas()
    {
        Assert.Equal("plain", CsvReportWriter.Cell("plain"));
        Assert.Equal("\"a,b\"", CsvReportWriter.Cell("a,b"));
        Assert.Equal("\"say \"\"hi\"\"\"", CsvReportWriter.Cell("say \"hi\""));
        Assert.Equal("\"two\nlines\"", CsvReportWriter.Cell("two\nlines"));
        Assert.Equal("'=1+1", CsvReportWriter.Cell("=1+1"));
        Assert.Equal("'+44 20", CsvReportWriter.Cell("+44 20"));
        Assert.Equal("'@SUM(A1)", CsvReportWriter.Cell("@SUM(A1)"));
        Assert.Equal("\" padded \"", CsvReportWriter.Cell(" padded "));

        var csv = Encoding.UTF8.GetString(CsvReportWriter.Write(Sample(2)));
        Assert.StartsWith("\uFEFFTime,Computer,Event,Severity,Details\r\n", csv, StringComparison.Ordinal);
        Assert.Equal(3, csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries).Length);
    }

    [GeneratedRegex(@"startxref\n(\d+)\n%%EOF")]
    private static partial Regex StartXref();

    [GeneratedRegex(@"(\d{10}) 00000 n ")]
    private static partial Regex XrefEntry();

    [GeneratedRegex(@"<< /Length (\d+) >>\nstream\n(.*?)endstream", RegexOptions.Singleline)]
    private static partial Regex StreamObject();

    [GeneratedRegex(@"/Type /Pages /Kids \[[^\]]*\] /Count (\d+)")]
    private static partial Regex PageCount();
}

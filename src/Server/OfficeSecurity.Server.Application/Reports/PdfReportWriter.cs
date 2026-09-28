using System.Globalization;
using System.Text;

namespace OfficeSecurity.Server.Application.Reports;

/// <summary>
/// A small, dependency-free PDF writer for tabular reports: A4 landscape, the standard Helvetica fonts
/// (built into every PDF reader, nothing embedded), tables with wrapped text, a repeated header row and page
/// numbers. Text uses the Windows-1252 character set of those fonts: Western European characters are shown;
/// other characters appear as "?" (the CSV export keeps every character).
/// </summary>
public static class PdfReportWriter
{
    private const double PageWidth = 842;
    private const double PageHeight = 595;
    private const double Margin = 36;
    private const double Bottom = Margin + 18;
    private const double TableFont = 7.5;
    private const double LineHeight = 9.2;
    private const double CellPadding = 3;
    private const int MeasureRows = 400;

    // Helvetica character widths (Adobe AFM, 1/1000 em) for characters 32..126.
    private static readonly int[] Widths =
    [
        278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
        556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
        1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
        667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
        333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
        556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
    ];

    private static readonly Dictionary<char, byte> Cp1252 = new()
    {
        ['€'] = 0x80, ['‚'] = 0x82, ['ƒ'] = 0x83, ['„'] = 0x84, ['…'] = 0x85, ['†'] = 0x86, ['‡'] = 0x87, ['ˆ'] = 0x88,
        ['‰'] = 0x89, ['Š'] = 0x8A, ['‹'] = 0x8B, ['Œ'] = 0x8C, ['Ž'] = 0x8E, ['‘'] = 0x91, ['’'] = 0x92,
        ['“'] = 0x93, ['”'] = 0x94, ['•'] = 0x95, ['–'] = 0x96, ['—'] = 0x97, ['˜'] = 0x98, ['™'] = 0x99,
        ['š'] = 0x9A, ['›'] = 0x9B, ['œ'] = 0x9C, ['ž'] = 0x9E, ['Ÿ'] = 0x9F,
    };

    public static byte[] Write(ReportDocument report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var pages = new Layout(report).Pages;
        return Assemble(report.Title, pages);
    }

    /// <summary>Text as the font's single-byte characters.</summary>
    public static string ToFontText(string? text)
    {
        var result = new StringBuilder((text ?? string.Empty).Length);
        foreach (var c in text ?? string.Empty)
        {
            result.Append(c switch
            {
                >= ' ' and <= '~' => c.ToString(),
                >= ' ' and <= 'ÿ' => c.ToString(),
                '\t' or '\r' or '\n' => " ",
                '→' => "->",
                '←' => "<-",
                '✓' => "OK",
                '✗' => "X",
                '≥' => ">=",
                '≤' => "<=",
                _ when Cp1252.ContainsKey(c) => c.ToString(),
                _ when char.IsControl(c) => " ",
                _ when char.IsLowSurrogate(c) => string.Empty,
                _ => "?",
            });
        }

        return result.ToString();
    }

    public static double TextWidth(string text, double size, bool bold = false)
    {
        double units = 0;
        foreach (var c in text)
        {
            units += c is >= ' ' and <= '~' ? Widths[c - ' '] : 611;
        }

        return units * size / 1000 * (bold ? 1.1 : 1.0);
    }

    // ---------------------------------------------------------------- layout

    private sealed class Layout
    {
        private readonly ReportDocument _report;
        private StringBuilder _page = new();
        private double _y;

        public Layout(ReportDocument report)
        {
            _report = report;
            NewPage(first: true);
            Facts();
            foreach (var section in report.Sections)
            {
                Section(section);
            }

            Pages.Add(_page.ToString());
        }

        public List<string> Pages { get; } = [];

        private void NewPage(bool first)
        {
            if (!first)
            {
                Pages.Add(_page.ToString());
                _page = new StringBuilder();
            }

            _y = PageHeight - Margin;
            Text(Margin, _y - 12, first ? 16 : 10, true, _report.Title);
            _y -= first ? 20 : 14;
            if (first)
            {
                Text(Margin, _y - 10, 9.5, false, _report.Period);
                _y -= 14;
                Text(Margin, _y - 9, 8, false, _report.GeneratedText);
                _y -= 16;
            }
            else
            {
                _y -= 4;
            }
        }

        private void Facts()
        {
            if (_report.Facts.Count == 0)
            {
                return;
            }

            var labelWidth = Math.Min(260, _report.Facts.Max(f => TextWidth(ToFontText(f.Key), 9, true)) + 12);
            foreach (var (label, value) in _report.Facts)
            {
                var lines = Wrap(ToFontText(value), PageWidth - 2 * Margin - labelWidth, 9);
                Ensure(lines.Count * 11 + 2);
                Text(Margin, _y - 9, 9, true, ToFontText(label));
                for (var i = 0; i < lines.Count; i++)
                {
                    Text(Margin + labelWidth, _y - 9 - i * 11, 9, false, lines[i]);
                }

                _y -= lines.Count * 11 + 2;
            }

            _y -= 8;
        }

        private void Section(ReportSection section)
        {
            var columns = section.Columns.Select(ToFontText).ToList();
            var rows = section.Rows.Select(r => r.Select(ToFontText).ToList()).ToList();
            var widths = ColumnWidths(columns, rows);

            Ensure(40);
            Text(Margin, _y - 11, 11, true, ToFontText(section.Heading));
            _y -= 18;
            Header(columns, widths);
            if (rows.Count == 0)
            {
                Text(Margin + CellPadding, _y - 9, 8, false, "(nothing in this period)");
                _y -= 14;
            }

            foreach (var row in rows)
            {
                var cells = row.Select((cell, i) => Wrap(cell, widths[i] - 2 * CellPadding, TableFont)).ToList();
                var height = cells.Max(c => c.Count) * LineHeight + 2 * CellPadding - 2;
                if (_y - height < Bottom)
                {
                    NewPage(first: false);
                    Text(Margin, _y - 9, 9, true, ToFontText(section.Heading) + " (continued)");
                    _y -= 14;
                    Header(columns, widths);
                }

                var x = Margin;
                for (var i = 0; i < cells.Count; i++)
                {
                    for (var line = 0; line < cells[i].Count; line++)
                    {
                        Text(x + CellPadding, _y - CellPadding - TableFont - line * LineHeight + 1.5, TableFont, false, cells[i][line]);
                    }

                    x += widths[i];
                }

                _y -= height;
                _page.Append(CultureInfo.InvariantCulture, $"0.82 G 0.4 w {Margin:0.##} {_y:0.##} m {PageWidth - Margin:0.##} {_y:0.##} l S\n");
            }

            if (section.Note is not null)
            {
                Ensure(14);
                Text(Margin, _y - 10, 8, false, ToFontText(section.Note));
                _y -= 14;
            }

            _y -= 14;
        }

        private void Header(List<string> columns, double[] widths)
        {
            var cells = columns.Select((c, i) => Wrap(c, widths[i] - 2 * CellPadding, TableFont, bold: true)).ToList();
            var height = cells.Max(c => c.Count) * LineHeight + 2 * CellPadding - 2;
            _page.Append(CultureInfo.InvariantCulture, $"0.9 g {Margin:0.##} {_y - height:0.##} {PageWidth - 2 * Margin:0.##} {height:0.##} re f 0 g\n");
            var x = Margin;
            for (var i = 0; i < cells.Count; i++)
            {
                for (var line = 0; line < cells[i].Count; line++)
                {
                    Text(x + CellPadding, _y - CellPadding - TableFont - line * LineHeight + 1.5, TableFont, true, cells[i][line]);
                }

                x += widths[i];
            }

            _y -= height;
        }

        private void Ensure(double height)
        {
            if (_y - height < Bottom)
            {
                NewPage(first: false);
            }
        }

        private void Text(double x, double y, double size, bool bold, string text)
        {
            if (text.Length == 0)
            {
                return;
            }

            _page.Append(CultureInfo.InvariantCulture, $"BT /{(bold ? "F2" : "F1")} {size:0.##} Tf {x:0.##} {y:0.##} Td (");
            foreach (var c in text)
            {
                var code = c <= 'ÿ' ? (byte)c : Cp1252.GetValueOrDefault(c, (byte)'?');
                _page.Append(code switch
                {
                    (byte)'(' => "\\(",
                    (byte)')' => "\\)",
                    (byte)'\\' => "\\\\",
                    < 32 or > 126 => "\\" + Convert.ToString(code, 8).PadLeft(3, '0'),
                    _ => ((char)code).ToString(),
                });
            }

            _page.Append(") Tj ET\n");
        }

        private static double[] ColumnWidths(List<string> columns, List<List<string>> rows)
        {
            const double available = PageWidth - 2 * Margin;
            var desired = new double[columns.Count];
            for (var i = 0; i < columns.Count; i++)
            {
                var longestWord = columns[i].Split(' ').Max(w => TextWidth(w, TableFont, true));
                var content = rows.Take(MeasureRows).Select(r => i < r.Count ? TextWidth(r[i], TableFont) : 0).DefaultIfEmpty(0).Max();
                desired[i] = Math.Clamp(Math.Max(longestWord, content) + 2 * CellPadding + 2, 34, 420);
            }

            var total = desired.Sum();
            if (total <= available)
            {
                // Give the spare room to the widest column (usually "Details").
                desired[Array.IndexOf(desired, desired.Max())] += available - total;
                return desired;
            }

            // Too wide: shrink the wide columns first, keeping narrow ones (dates, counts) readable.
            var narrow = desired.Where(d => d <= 80).Sum();
            var wide = total - narrow;
            var factor = Math.Max(0.1, (available - narrow) / wide);
            return desired.Select(d => d <= 80 ? d : d * factor).ToArray();
        }

        private static List<string> Wrap(string text, double width, double size, bool bold = false)
        {
            var lines = new List<string>();
            var line = new StringBuilder();
            foreach (var word in text.Split(' '))
            {
                var candidate = line.Length == 0 ? word : line + " " + word;
                if (TextWidth(candidate, size, bold) <= width)
                {
                    line.Clear().Append(candidate);
                    continue;
                }

                if (line.Length > 0)
                {
                    lines.Add(line.ToString());
                    line.Clear();
                }

                // A word longer than the column (paths, IDs) is broken where it no longer fits.
                var rest = word;
                while (TextWidth(rest, size, bold) > width && rest.Length > 1)
                {
                    var take = rest.Length - 1;
                    while (take > 1 && TextWidth(rest[..take], size, bold) > width)
                    {
                        take--;
                    }

                    lines.Add(rest[..take]);
                    rest = rest[take..];
                }

                line.Append(rest);
            }

            if (line.Length > 0 || lines.Count == 0)
            {
                lines.Add(line.ToString());
            }

            return lines;
        }
    }

    // ---------------------------------------------------------------- file structure

    private static byte[] Assemble(string title, List<string> pages)
    {
        var latin1 = Encoding.Latin1;
        using var output = new MemoryStream();
        var offsets = new List<long>();

        void Write(string s)
        {
            var bytes = latin1.GetBytes(s);
            output.Write(bytes);
        }

        void Object(int number, string body)
        {
            while (offsets.Count < number)
            {
                offsets.Add(0);
            }

            offsets[number - 1] = output.Position;
            Write($"{number} 0 obj\n{body}\nendobj\n");
        }

        Write("%PDF-1.4\n%âãÏÓ\n");
        const int fonts = 3;
        var firstPage = fonts + 2;
        var kids = string.Join(' ', Enumerable.Range(0, pages.Count).Select(i => $"{firstPage + 2 * i} 0 R"));
        Object(1, "<< /Type /Catalog /Pages 2 0 R >>");
        Object(2, string.Create(CultureInfo.InvariantCulture, $"<< /Type /Pages /Kids [{kids}] /Count {pages.Count} >>"));
        Object(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>");
        Object(4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>");
        for (var i = 0; i < pages.Count; i++)
        {
            var footer = string.Create(CultureInfo.InvariantCulture, $"BT /F1 7.5 Tf {PageWidth - Margin - 60:0.##} {Margin - 6:0.##} Td (Page {i + 1} of {pages.Count}) Tj ET\n");
            var content = pages[i] + footer;
            var number = firstPage + 2 * i;
            Object(number, string.Create(CultureInfo.InvariantCulture,
                $"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PageWidth} {PageHeight}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {number + 1} 0 R >>"));
            Object(number + 1, string.Create(CultureInfo.InvariantCulture, $"<< /Length {latin1.GetByteCount(content)} >>\nstream\n{content}endstream"));
        }

        var info = firstPage + 2 * pages.Count;
        Object(info, $"<< /Title ({Escape(ToFontText(title))}) /Producer (Office Security System) >>");

        var xref = output.Position;
        Write(string.Create(CultureInfo.InvariantCulture, $"xref\n0 {offsets.Count + 1}\n0000000000 65535 f \n"));
        foreach (var offset in offsets)
        {
            Write(string.Create(CultureInfo.InvariantCulture, $"{offset:D10} 00000 n \n"));
        }

        Write(string.Create(CultureInfo.InvariantCulture, $"trailer\n<< /Size {offsets.Count + 1} /Root 1 0 R /Info {info} 0 R >>\nstartxref\n{xref}\n%%EOF\n"));
        return output.ToArray();
    }

    private static string Escape(string text) =>
        text.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("(", "\\(", StringComparison.Ordinal).Replace(")", "\\)", StringComparison.Ordinal);
}

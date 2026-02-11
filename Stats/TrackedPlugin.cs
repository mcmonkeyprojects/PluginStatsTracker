using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FreneticUtilities.FreneticDataSyntax;
using FreneticUtilities.FreneticExtensions;
using FreneticUtilities.FreneticToolkit;
using LiteDB;
using Microsoft.AspNetCore.Html;
using PluginStatsTracker.Models;

namespace PluginStatsTracker.Stats
{
    public class TrackedPlugin
    {
        public string ID;

        public string Name;

        public string Description;

        public string LogoImage;

        public string InfoLink;

        public Dictionary<string, TrackedField> Fields = [];

        public CurrentPluginStats Current;

        public ILiteCollection<StatReport> DatabaseReports;

        public TrackedPlugin(string _id, ILiteCollection<StatReport> reports, FDSSection section)
        {
            ID = _id;
            DatabaseReports = reports;
            Name = section.GetString("name");
            Description = section.GetString("description");
            LogoImage = section.GetString("logo-image");
            InfoLink = section.GetString("info-link");
            FDSSection fieldSection = section.GetSection("fields");
            if (fieldSection is not null)
            {
                foreach (string fieldId in fieldSection.GetRootKeys())
                {
                    string field = fieldId.ToLowerFast();
                    Fields.Add(field, new TrackedField(field, fieldSection.GetSection(fieldId)));
                }
            }
            Current = new CurrentPluginStats() { ForPlugin = this };
        }

        public void MakeReport(int now)
        {
            if (DatabaseReports.FindById(now) is not null)
            {
                return;
            }
            Current.Clean();
            DatabaseReports.Insert(Current.Report());
        }

        public StatReport LastReport()
        {
            int now = StatsServer.GetCurrentTimeID();
            StatReport result = DatabaseReports.FindById(now);
            if (result is not null)
            {
                return result;
            }
            for (int i = 0; i < 48; i++)
            {
                result = DatabaseReports.FindById(StatsServer.DateToTimeID(DateTimeOffset.UtcNow.Subtract(TimeSpan.FromHours(i))));
                if (result is not null)
                {
                    return result;
                }
            }
            return new StatReport() { ForPluginID = ID, Fields = [] };
        }

        public LockObject PageGenLock = new();

        public List<StatReport> BuildReportList(DateTimeOffset now, TimeSpan jump, int count)
        {
            List<StatReport> reports = [];
            for (int i = count; i >= 0; i--)
            {
                int id = StatsServer.DateToTimeID(now.Subtract(jump * i));
                StatReport result = DatabaseReports.FindById(id);
                if (result is not null)
                {
                    reports.Add(result);
                }
            }
            return reports;
        }

        public PluginsModel LastModelBuilt;

        public int LastModelID = 0;

        public PluginsModel GetPageReportData()
        {
            Thread.MemoryBarrier();
            int cur = StatsServer.GetCurrentTimeID();
            if (LastModelID == cur && LastModelBuilt is not null)
            {
                return LastModelBuilt;
            }
            lock (PageGenLock)
            {
                Thread.MemoryBarrier();
                if (cur == LastModelID)
                {
                    return LastModelBuilt;
                }
                StatReport report = LastReport();
                if (report.StatID == LastModelID) // Backup in case a new stat report isn't generated yet
                {
                    return LastModelBuilt;
                }
                Console.WriteLine($"Generate page data for plugin {ID} because current {cur} does not match {LastModelID}");
                StringBuilder js = new();
                StringBuilder graphs = new();
                DateTimeOffset now = DateTimeOffset.UtcNow;
                List<StatReport> monthReports = Fields.Values.Any(f => f.TimeGraphMonth) ? BuildReportList(now, TimeSpan.FromHours(1), 30 * 24) : null,
                    longReports = Fields.Values.Any(f => f.TimeGraphLong) ? BuildReportList(now, TimeSpan.FromDays(1), 365 * 5) : null;
                foreach (StatReport.StatReportField field in report.Fields)
                {
                    if (Fields.TryGetValue(field.FieldID, out TrackedField tracked))
                    {
                        js.Append($"var data_{tracked.ID} = google.visualization.arrayToDataTable([\n['Value', 'Count'],\n");
                        int other = 0, otherTypes = 0;
                        foreach (StatReport.StatReportFieldValue value in field.Values)
                        {
                            if (value.Count >= tracked.Minimum)
                            {
                                js.Append($"['{HtmlJsClean(value.Value)}',{value.Count}],");
                            }
                            else
                            {
                                other += value.Count;
                                otherTypes++;
                            }
                        }
                        if (other > 0)
                        {
                            js.Append($"['Other ({otherTypes} unique values with less than {tracked.Minimum} each)',{other}],");
                        }
                        js.Append("\n]);\n");
                        graphs.Append($"<div class=\"datachart_box\"><h4>{HtmlJsClean(tracked.Display)}</h4>\n<ul class=\"nav nav-tabs\"><li class=\"nav-item\"><a class=\"nav-link active\" data-bs-toggle=\"tab\" href=\"#st_current_{tracked.ID}\">Current</a></li>");
                        if (tracked.TimeGraphMonth)
                        {
                            graphs.Append($"<li class=\"nav-item\"><a class=\"nav-link\" data-bs-toggle=\"tab\" href=\"#st_line_months_{tracked.ID}\">Last Month</a></li>");
                        }
                        if (tracked.TimeGraphLong)
                        {
                            graphs.Append($"<li class=\"nav-item\"><a class=\"nav-link\" data-bs-toggle=\"tab\" href=\"#st_line_long_{tracked.ID}\">Last 5 Years</a></li>");
                        }
                        graphs.Append($"</ul>\n<div class=\"tab-content\"><div class=\"tab-pane active show\" id=\"st_current_{tracked.ID}\">");
                        if (tracked.Type == TrackedFieldType.INTEGER)
                        {
                            graphs.Append($"Sum: {field.Total}<br>Average per all servers: {(field.Total / report.Total):0.##}<br>Average per counted entry: {field.Average:0.##}<br>");
                        }
                        js.Append($"var options_{tracked.ID} = {{\ntitle: '', {stylePie}\n}};\n");
                        js.Append($"var chart_{tracked.ID} = new google.visualization.PieChart(document.getElementById('chart_{tracked.ID}'));\nchart_{tracked.ID}.draw(data_{tracked.ID}, options_{tracked.ID});\n");
                        graphs.Append($"Counted: {field.Counted}/{report.Total} ({unchecked(field.Counted / (float)report.Total) * 100:0.#}%)\n<div id=\"chart_{tracked.ID}\" class=\"datachart piechart\"></div></div>\n");
                        if (tracked.TimeGraphMonth)
                        {
                            BuildTimeGraph(report, "line_months", field, tracked, monthReports, js, graphs);
                        }
                        if (tracked.TimeGraphLong)
                        {
                            BuildTimeGraph(report, "line_long", field, tracked, longReports, js, graphs);
                        }
                        graphs.Append("</div></div>");
                    }
                }
                LastModelBuilt = new PluginsModel() { Plugin = this, Report = report, JS = new HtmlString(js.ToString()), Graphs = new HtmlString(graphs.ToString()) };
                LastModelID = report.StatID;
                return LastModelBuilt;
            }
        }

        const string style = "backgroundColor: '#222222', titleTextStyle: { color: '#FFFFFF' }, legend: { textStyle: { color: '#FFFFFF' } }";
        const string stylePie = $"pieSliceBorderColor: '#222222', {style}";
        const string styleLine = $"width: 800, height: 500, {style}";

        public static string CleanID(int id)
        {
            string text = id.ToString();
            return $"{text[0..4]}/{text[4..6]}/{text[6..8]} {text[8..10]}:00";
        }

        public void BuildTimeGraph(StatReport report, string id, StatReport.StatReportField currentField, TrackedField tracked, List<StatReport> history, StringBuilder js, StringBuilder graphs)
        {
            HashSet<string> valueSet = [], excludeSet = [];
            List<(StatReport, StatReport.StatReportField)> fieldHistory = [.. history.Select(r => (r, r.Fields.FirstOrDefault(f => f.FieldID == tracked.ID))).Where(f => f.Item2 is not null)];
            foreach ((StatReport _, StatReport.StatReportField field) in fieldHistory)
            {
                foreach (StatReport.StatReportFieldValue subValue in field.Values)
                {
                    if (!excludeSet.Contains(subValue.Value))
                    {
                        excludeSet.Add(subValue.Value);
                        int sum = fieldHistory.Sum(p => p.Item2.Values.FirstOrDefault(v => v.Value == subValue.Value)?.Count ?? 0);
                        float average = sum / (float)fieldHistory.Count;
                        if (average >= tracked.Minimum)
                        {
                            valueSet.Add(subValue.Value);
                        }
                    }
                }
            }
            js.Append($"var data_{tracked.ID}_{id} = google.visualization.arrayToDataTable([\n['Time'");
            string[] values = [.. valueSet.OrderByDescending(val => currentField.Values.FirstOrDefault(sv => sv.Value == val)?.Count ?? 0)];
            foreach (string key in values)
            {
                js.Append($",'{HtmlJsClean(key)}'");
            }
            js.Append("],\n");
            foreach ((StatReport rep, StatReport.StatReportField field) in fieldHistory)
            {
                js.Append($"\n['{CleanID(rep.StatID)}'");
                foreach (string key in values)
                {
                    StatReport.StatReportFieldValue valueData = field.Values.FirstOrDefault(v => v.Value == key);
                    if (valueData is null)
                    {
                        js.Append(",0");
                    }
                    else
                    {
                        js.Append($",{valueData.Count}");
                    }
                }
                js.Append("],\n");
            }
            js.Append("\n]);\n");
            js.Append($"var options_{tracked.ID}_{id} = {{\ntitle: '', {styleLine}\n}};\n");
            js.Append($"var chart_{tracked.ID}_{id} = new google.visualization.LineChart(document.getElementById('chart_{tracked.ID}_{id}'));\nchart_{tracked.ID}_{id}.draw(data_{tracked.ID}_{id}, options_{tracked.ID}_{id});\n");
            graphs.Append($"<div class=\"tab-pane\" id=\"st_{id}_{tracked.ID}\"><div id=\"chart_{tracked.ID}_{id}\" class=\"datachart linechart\"></div></div>\n");
        }

        public static string HtmlJsClean(string input)
        {
            return input.Replace("&", "&amp;").Replace("'", "&#39;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("\\", "&#92;");
        }
    }
}

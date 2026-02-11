using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FreneticUtilities.FreneticDataSyntax;
using FreneticUtilities.FreneticExtensions;
using FreneticUtilities.FreneticToolkit;

namespace PluginStatsTracker.Stats
{
    public class TrackedField
    {
        public string ID;

        public TrackedFieldType Type;

        public string Display;

        public bool Any = false;

        public int Length;

        public int Minimum = 5;

        public List<TrackedFieldValue> Values;

        public bool TimeGraphMonth = false, TimeGraphLong = false;

        public TrackedField(string _id, FDSSection section)
        {
            ID = _id;
            Type = Enum.Parse<TrackedFieldType>(section.GetString("type"), true);
            Display = section.GetString("display");
            Any = section.GetBool("any", false).Value;
            Values = [.. section.GetString("values", "").SplitFast(',').Select(s => s.Replace(" ", "")).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => TrackedFieldValue.Parse(s))];
            Length = section.GetInt("length", 32).Value;
            TimeGraphMonth = section.GetBool("time_graph.month", false).Value;
            TimeGraphLong = section.GetBool("time_graph.long", false).Value;
            Minimum = section.GetInt("minimum", Any ? 5 : 1).Value;
        }

        public StatReport.StatReportField Report(StatSubmission[] stats)
        {
            Dictionary<string, int> counters = [];
            void bump(string name)
            {
                if (counters.TryGetValue(name, out int count))
                {
                    counters[name] = count + 1;
                }
                else
                {
                    counters[name] = 1;
                }
            }
            int counted = 0;
            double average = 0;
            float total = 0;
            foreach (StatSubmission stat in stats)
            {
                if (stat.Values.TryGetValue(ID, out StatSubmission.SubmittedValue val))
                {
                    if (Type == TrackedFieldType.LIST)
                    {
                        foreach (string bit in val.Raw.SplitFast('\n'))
                        {
                            if (!string.IsNullOrWhiteSpace(bit))
                            {
                                bump(bit);
                            }
                        }
                    }
                    else if (Type == TrackedFieldType.TEXT)
                    {
                        bump(val.Raw);
                    }
                    else if (Type == TrackedFieldType.INTEGER)
                    {
                        bump(val.Value.Text);
                        average += val.RawNumber;
                        total += val.RawNumber;
                    }
                    counted++;
                }
            }
            return new()
            {
                FieldID = ID,
                Values = [.. counters.Select(pair => new StatReport.StatReportFieldValue() { Value = pair.Key, Count = pair.Value }).OrderByDescending(v => v.Count)],
                Total = total,
                Counted = counted,
                Average = (counted == 0) ? 0 : (float)(average / counted)
            };
        }

        public StatSubmission.SubmittedValue? GetValueFor(string input)
        {
            StatSubmission.SubmittedValue value = new() { Field = this, Raw = input };
            switch (Type)
            {
                case TrackedFieldType.TEXT:
                    if (input.Length > Length)
                    {
                        Console.Error.WriteLine($"Submission to field {ID} ignored due to length: {input.Length} > {Length}");
                        return null;
                    }
                    break;
                case TrackedFieldType.LIST:
                    string[] parts = input.SplitFast('\n');
                    if (parts.Length > 1000 || parts.Any(p => p.Length > Length))
                    {
                        Console.Error.WriteLine($"Submission to field {ID} ignored due to length: {input.Length} > {Length} or {parts.Length} > 1000");
                        return null;
                    }
                    break;
            }
            if (Any)
            {
                return value;
            }
            switch (Type)
            {
                case TrackedFieldType.TEXT:
                case TrackedFieldType.LIST:
                    throw new NotImplementedException("'list' and 'text' types currently require 'any: true'");
                case TrackedFieldType.INTEGER:
                    if (!int.TryParse(input, out int intInput))
                    {
                        return null;
                    }
                    value.RawNumber = intInput;
                    foreach (TrackedFieldValue possible in Values)
                    {
                        if (possible.AppliesTo(intInput))
                        {
                            value.Value = possible;
                            return value;
                        }
                    }
                    return null;
            }
            return null;
        }
    }

    public class TrackedFieldValue
    {
        public string Text;

        public int Min, Max;

        public static TrackedFieldValue Parse(string text)
        {
            TrackedFieldValue toRet = new() { Text = text };
            if (text.EndsWith('+'))
            {
                toRet.Max = int.MaxValue;
                toRet.Min = int.Parse(text[..^1]);
            }
            else if (text.Contains('-'))
            {
                string before = text.BeforeAndAfter('-', out string after);
                toRet.Min = int.Parse(before);
                toRet.Max = int.Parse(after);
            }
            else
            {
                toRet.Min = int.Parse(text);
                toRet.Max = toRet.Min;
            }
            return toRet;
        }

        public bool AppliesTo(int value)
        {
            return value >= Min && value <= Max;
        }
    }
}

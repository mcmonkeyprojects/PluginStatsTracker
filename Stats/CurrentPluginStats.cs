using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FreneticUtilities.FreneticDataSyntax;
using FreneticUtilities.FreneticExtensions;
using FreneticUtilities.FreneticToolkit;

namespace PluginStatsTracker.Stats
{
    public class CurrentPluginStats
    {
        public TrackedPlugin ForPlugin;

        public ConcurrentDictionary<StatSubmitter, StatSubmission> Submissions = new();

        public void Submit(StatSubmission submission)
        {
            submission.TimeSubmitted = DateTimeOffset.UtcNow;
            Submissions[submission.Submitter] = submission;
        }

        public void Clean()
        {
            // Notes since concurrent types are weird:
            // Yes, the foreach is safe from CME's, because ConcurrentDictionary does that
            // Also yes 'TryRemove' will only remove if BOTH key AND value match, preventing mishaps with a submission happening during the Clean() call
            foreach (KeyValuePair<StatSubmitter, StatSubmission> pair in Submissions)
            {
                if (Math.Abs(DateTimeOffset.UtcNow.Subtract(pair.Value.TimeSubmitted).TotalMinutes) > 90)
                {
                    Submissions.TryRemove(pair);
                }
            }
        }

        public StatReport Report()
        {
            StatSubmission[] submissions = [.. Submissions.Values];
            return new()
            {
                StatID = StatsServer.GetCurrentTimeID(),
                ForPluginID = ForPlugin.ID,
                Total = submissions.Length,
                Fields = [.. ForPlugin.Fields.Values.Select(f => f.Report(submissions))]
            };
        }
    }
}

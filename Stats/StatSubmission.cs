using System;
using System.Collections.Generic;

namespace PluginStatsTracker.Stats
{
    public class StatSubmission
    {
        public StatSubmitter Submitter;

        public TrackedPlugin ForPlugin;

        public DateTimeOffset TimeSubmitted;

        public Dictionary<string, SubmittedValue> Values = [];

        public struct SubmittedValue
        {
            public TrackedField Field;

            public TrackedFieldValue Value;

            public string Raw;

            public int RawNumber;
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using FreneticUtilities.FreneticDataSyntax;
using FreneticUtilities.FreneticExtensions;
using FreneticUtilities.FreneticToolkit;
using LiteDB;

namespace PluginStatsTracker.Stats
{
    public class StatsServer
    {
        public static FDSSection Config;

        public static string URLBase;

        /// <summary>Whether X-Forwarded-For headers are trustworthy.</summary>
        public static bool TrustXForwardedFor;

        /// <summary>Forward addresses to exclude when trusting X-Forwarded-For headers.</summary>
        public static string[] ExcludeForwardAddresses;

        public static Dictionary<string, TrackedPlugin> TrackedPlugins = [];

        public static CancellationTokenSource CancelToken = new();

        public static LiteDatabase Database;

        public static void Load()
        {
            Console.WriteLine("Loading...");
            Directory.CreateDirectory("./data/");
            Database = new LiteDatabase("./data/database.ldb");
            Config = FDSUtility.ReadFile("./config/config.fds");
            URLBase = Config.GetString("url-base");
            TrustXForwardedFor = Config.GetBool("trust-x-forwarded-for", false).Value;
            ExcludeForwardAddresses = [.. (Config.GetStringList("exclude-forward-addresses") ?? [])];
            FDSSection pluginSection = Config.GetSection("plugins");
            foreach (string pluginId in pluginSection.GetRootKeys())
            {
                string id = pluginId.ToLowerFast();
                TrackedPlugins.Add(id, new TrackedPlugin(id, Database.GetCollection<StatReport>($"reports_plugin_{id}"), pluginSection.GetSection(pluginId)));
            }
            Task.Factory.StartNew(IdleLoop);
        }

        public static int DateToTimeID(DateTimeOffset date)
        {
            return int.Parse(date.ToString("yyyyMMddHH"));
        }

        public static int GetCurrentTimeID()
        {
            return DateToTimeID(DateTimeOffset.UtcNow);
        }

        public static void IdleLoop()
        {
            int lastRecorded = GetCurrentTimeID();
            Console.WriteLine($"Looping started at {lastRecorded}");
            while (!CancelToken.IsCancellationRequested)
            {
                try
                {
                    Task.Delay(TimeSpan.FromMinutes(10)).Wait(CancelToken.Token);
                    int now = GetCurrentTimeID();
                    if (now == lastRecorded)
                    {
                        continue;
                    }
                    if (CancelToken.IsCancellationRequested)
                    {
                        return;
                    }
                    lastRecorded = now;
                    foreach (TrackedPlugin plugin in TrackedPlugins.Values)
                    {
                        if (CancelToken.IsCancellationRequested)
                        {
                            return;
                        }
                        Console.WriteLine($"Doing stat gather for {plugin.ID} at {now}");
                        plugin.MakeReport(now);
                    }
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Idle loop errored: {ex}");
                }
            }
        }

        public static void Close()
        {
            CancelToken.Cancel();
            Console.WriteLine("Performing database shutdown...");
            Database.Dispose();
            Console.WriteLine("Database has been shutdown.");
        }
    }
}

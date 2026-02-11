using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using FreneticUtilities.FreneticDataSyntax;
using FreneticUtilities.FreneticExtensions;
using FreneticUtilities.FreneticToolkit;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using PluginStatsTracker.Stats;

namespace PluginStatsTracker.Controllers
{
    public class StatsController : Controller
    {
        public IActionResult Submit()
        {
            if (Request.Method != "POST")
            {
                return Redirect("/Error/Error404");
            }
            if (!Request.Form.TryGetValue("postid", out StringValues postIdValue) || postIdValue.Count != 1 || postIdValue[0] != "pluginstats"
                || !Request.Form.TryGetValue("plugin", out StringValues pluginId) || pluginId.Count != 1
                || !Request.Form.TryGetValue("differentiator", out StringValues differentiatorValue) || differentiatorValue.Count != 1)
            {
                return StatusCode(400, "Invalid post request\n");
            }
            if (!StatsServer.TrackedPlugins.TryGetValue(pluginId[0].ToLowerFast(), out TrackedPlugin plugin))
            {
                return StatusCode(400, "Unknown plugin id\n");
            }
            string ip = FixIP(Request.HttpContext.Connection.RemoteIpAddress.ToString());
            if (StatsServer.TrustXForwardedFor && Request.Headers.TryGetValue("X-Forwarded-For", out StringValues forwardHeader))
            {
                string[] forwards = [.. forwardHeader.Select(FixIP).SelectMany(f => f.Split(',')).Select(f => f.Trim()).Where(f => !CheckExclusion(StatsServer.ExcludeForwardAddresses, f))];
                if (forwards.Length > 0)
                {
                    ip += "/X-Forwarded-For: " + string.Join(" / ", forwardHeader);
                }
            }
            StatSubmission submission = new()
            {
                Submitter = new StatSubmitter(ip, differentiatorValue[0]),
                ForPlugin = plugin
            };
            foreach (string field in Request.Form.Keys.Where(f => f.StartsWith("pl_")))
            {
                string fieldId = field.ToLowerFast()["pl_".Length..];
                if (plugin.Fields.TryGetValue(fieldId, out TrackedField tracked))
                {
                    string rawVal = Request.Form[field];
                    if (!string.IsNullOrWhiteSpace(rawVal))
                    {
                        StatSubmission.SubmittedValue? val = tracked.GetValueFor(rawVal);
                        if (val.HasValue)
                        {
                            submission.Values[tracked.ID] = val.Value;
                        }
                    }
                }
            }
            plugin.Current.Submit(submission);
            return Ok("Submitted\n");
        }

        public static HashSet<string> IgnoredOrigins = ["127.0.0.1", "::1", "[::1]"];

        [NonAction]
        public string FixIP(string ip)
        {
            if (ip.StartsWith("::ffff:"))
            {
                return ip["::ffff:".Length..];
            }
            // Trim v6 to the first half block
            if (ip.Contains(':'))
            {
                string[] bits = ip.Split(':');
                if (bits.Length == 8)
                {
                    return $"{bits[0]}:{bits[1]}:{bits[2]}:{bits[3]}::0";
                }
            }
            return ip;
        }


        [NonAction]
        public static bool CheckExclusion(string[] set, string realIp)
        {
            try
            {
                foreach (string compare in set)
                {
                    if (CheckContains(realIp, compare))
                    {
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error checking IP exclusion for `{realIp}`: {ex}");
            }
            return false;
        }

        [NonAction]
        public static bool CheckContains(string realIp, string compare)
        {
            if (compare.Contains('/') && !realIp.Contains(':'))
            {
                return IsIpInRange(realIp, compare);
            }
            return realIp == compare;
        }

        [NonAction]
        public static bool IsIpInRange(string ipAddress, string cidrRange)
        {
            string[] parts = cidrRange.Split('/');
            string rangeIp = parts[0];
            int prefixLength = int.Parse(parts[1]);
            uint ipInt = IpToUInt(ipAddress);
            uint rangeIpInt = IpToUInt(rangeIp);
            uint mask = 0xFFFFFFFF << (32 - prefixLength);
            return (ipInt & mask) == (rangeIpInt & mask);
        }

        [NonAction]
        public static uint IpToUInt(string ipAddress)
        {
            IPAddress ip = IPAddress.Parse(ipAddress);
            byte[] bytes = ip.GetAddressBytes();
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }
            return BitConverter.ToUInt32(bytes, 0);
        }
    }
}

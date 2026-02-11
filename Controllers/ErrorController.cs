using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace PluginStatsTracker.Controllers
{
    public class ErrorController : Controller
    {
        public IActionResult Any()
        {
            if (Response.StatusCode == 200 && !Response.HasStarted)
            {
                Response.StatusCode = 400;
            }
            return View();
        }

        public IActionResult Error404()
        {
            if (Response.StatusCode == 200 && !Response.HasStarted)
            {
                Response.StatusCode = 404;
            }
            return View();
        }
    }
}

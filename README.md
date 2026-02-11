PluginStatsTracker
------------------

Simple plugin statistics tracker & website display server.

"Plugin" in this context refers to Minecraft Spigot plugins ([Denizen](https://github.com/DenizenScript/Denizen) and [Sentinel](https://github.com/mcmonkeyprojects/Sentinel) in particular are my own use cases), but theoretically can be used for anything.

### State

Current project status: functional but incomplete. Some features not needed for my own case exist as placeholders only. You can view [my own instance of this server here](https://stats.mcmonkey.org/).

### How To Install/Run

Designed for and tested on a Debian Linux server.

Usage on other Linux distros is likely very similar. Usage outside Linux may require independent research regarding how to install DotNet 8, and how to run a generic executable service perpetually.

- Make sure you have `dotnet-8-sdk` available
- Add a user for the service (via `adduser` generally, then `su` to that user)
- Clone the git repo (`git clone https://github.com/mcmonkeyprojects/PluginStatsTracker`) and enter the folder
- Make a folder labeled `config`, inside it make a text file labeled `config.fds`, and fill it with the config sample below (and change values to fit your configuration needs).
- `git pull`
- Will by default open on port 8131. To change this, edit `start.sh`
- It is strongly recommended you run this webserver behind a reverse proxy like Apache2 or Nginx.

For testing on Windows, `start.ps1` is also available to run via powershell.

### From Plugins

Must connect approximately once an hour to `(URL-BASE)/Stats/Submit` and send form-encoded content with `postid=pluginstats`, `plugin=(PLUGIN_NAME)`, `differentiator=(SOME_UNIQUE_VALUE)` (differentiate can be any semi-text, doesn't not need guaranteed uniqueness), and `pl_(FIELD_NAME)=(FIELD_VALUE)` for each field.

Connections that vary by up to 30 minutes from the hour mark will be persisted (duplication prevented via the differentiator value).

Fields can be numbers, text, or newline-separated lists

View example implementations [in Sentinel](https://github.com/mcmonkeyprojects/Sentinel/blob/master/src/main/java/org/mcmonkey/sentinel/metrics/StatsRecord.java) or [in Denizen](https://github.com/DenizenScript/Denizen/blob/dev/plugin/src/main/java/com/denizenscript/denizen/utilities/debugging/StatsRecord.java).

### Configuration

```yml
# Whether to test the "X-Forwarded-For" web header.
# Set to 'true' if running behind a reverse-proxy (like Apache2 or Nginx), 'false' if directly exposed.
trust-x-forwarded-for: true
# X-Forwarded-For addresses to ignore when above trust is true. You can do CIDR ranges.
exclude-forward-addresses:
- 127.0.0.1
# Set to the base URL for the webserver.
url-base: https://example.com
# List plugins to track stats for here
plugins:
    # Plugin ID as the key
    # Note: IDs should be 'a-z' and '_' only
    denizen:
        # The 'proper display name' of this plugin
        name: Denizen
        # Description, text
        description: Denizen is a scripting engine for Spigot servers!
        # Logo-image, URL to a .png or .gif
        logo-image: https://denizenscript.com/images/denizen_logo_embed.png
        # Relevant info link to send viewers to
        info-link: https://denizenscript.com/
        # Set of tracked fields
        fields:
            # Field ID as the key
            # Note: ID should be 'a-z' and '_' only
            player_count:
                # Type: 'integer', 'text', or 'list'
                type: integer
                # Display text about it
                display: Online Players (Excluding Zeros)
                # For numbers, you can list value ranges.
                # Must be in format like '1' (exact number), or '11-15' (number range), 1001+ (overflow)
                # Numbers that don't match the options will be ignored (so in this example, '0' values get dropped)
                values: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11-15, 16-20, 21-30, 31-40, 41-50, 50-75, 76-100, 101-150, 151-200, 201-300, 301-400, 401-500, 501-1000, 1001+
            server_version:
                type: text
                # 'text' and 'list' should define a maximum 'length' for strings
                length: 100
                display: Server Version
                # You can use 'any: true' for both text and number to just allow raw values through unfiltered
                any: true
                # Set the minimum number of occurrences to count a value - counts below get lumped into 'other'.
                minimum: 3
                # Enable time_graph to get a line graph of the value over time
                time_graph:
                    # 'Month': one tick for every hour in the past month
                    month: true
                    # 'Long': one tick for each day up to the past 5 years
                    long: true
```

### Licensing pre-note:

This is an open source project, provided entirely freely, for everyone to use and contribute to.

If you make any changes that could benefit the community as a whole, please contribute upstream.

### The short of the license is:

You can do basically whatever you want, except you may not hold any developer liable for what you do with the software.

### The long version of the license follows:

The MIT License (MIT)

Copyright (c) 2022-2026 Alex 'mcmonkey' Goodwin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Proof of concept [scrapy](https://scrapy.org/) based scraper for tracking CVEs, run from a GitHub Actions cron job. This is an experiment for scraper that periodically redownloads everything and runs inside GitHub Actions. My previous approach to this was "serverless" and redownloaded on demand: https://github.com/bburky/google-apps-scripts, this is a test to try something different.

The scraper's output is in the [security-scraper-output](https://github.com/defenseunicorns/security-scraper-output) repository. A separate repo is used to avoid clutter, because the vendor's advisories may be copyrighted, and to allow sensitive discussion of security issues in GitHub PRs. This [security-scraper](https://github.com/defenseunicorns/security-scraper-output) repo will have none of that and can be open sourced.

TODO: An RSS feed generator from the output

The scraper performs very minimal data extraction, mostly just vendor, title, summary, CVE and a URL. Ideally a "product" name would be extracted too to be used for filtering, but this is moderately difficult when vendors issue advisories affecting multiple products.

Data sources such as MITRE or NVD may lag. Usually the vendor's own advisory is published earliest and has the most detailed information about security issues.

Many vendors do not provide this information in an machine readable format. Sometimes an RSS feed is available, but often only HTML webpages exist with the info. Vendors often provide email notifications, but this scraper prefers a pull workflow (redownload everything periodically) instead of push (listen for vendor notifications).

Vendors may update their advisories after publication. By re-scraping periodically and writing the contents to git, the history may be tracked.

TODO: HTML to markdown conversion is really bad and may create malformed markdown. It's good enough if you want something plaintext to read or diff though.

TODO: add NVD API scrapers base on CPE (They do lag, but they may find things missing from other sources)

TODO: better configuration. Replace hardcoded scraper URLs with a config file. Probably config group scrapers by "product" too?

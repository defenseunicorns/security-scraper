import scrapy
from .. import utils


class MattermostSecurityUpdatesSpider(scrapy.Spider):
    name = "mattermost_security_updates"
    allowed_domains = ["mattermost.com"]
    start_urls = ["https://mattermost.com/security-updates/"]

    def parse(self, response):
        table = response.css("table")
        assert len(table) == 1
        headings = [utils.slug(th) for th in table.css("thead th::text").getall()]
        # Calculate an "advisory number" based on an index counted from the bottom of the table
        for i, row in enumerate(reversed(table[0].css("tbody tr"))):
            cves = (
                list(set(cve.upper() for cve in response.selector.re(utils.CVE_REGEX)))
                or None
            )
            # Convert table rows to dictionaries keyed by slugified table headers
            raw = {}
            for j, td in enumerate(row.css("td")):
                raw[headings[j]] = utils.to_plaintext(td)
            # some IDs have a comma followed by a CVE ID, strip it and keep the MMSA ID
            # To avoid duplicates, include an "advisory number" in the ID too
            id_ = f'{raw["issue_identifier"].split(",")[0].strip()}_{i}'
            yield {
                "spider": self.name,
                "href": response.url,
                "id": id_,
                "severity": raw["severity"],
                "affected_versions": raw["affected_versions"],
                "publish_date": raw["fix_release_date"],
                "fix_versions": raw["fix_versions"],
                "description": raw["issue_details"],
                "product": raw["issue_platform"],
                "cves": cves,
                "raw": raw,
            }

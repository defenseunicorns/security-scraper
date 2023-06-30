from .. import utils

import re

from html2text import HTML2Text

import scrapy
from scrapy import Request, Spider
from scrapy.linkextractors import LinkExtractor


class AtlassianSecurityAdvisoriesSpider(Spider):
    name = "atlassian_security_advisories"
    allowed_domains = ["atlassian.com"]
    start_urls = ["https://www.atlassian.com/trust/security/advisories"]

    # Skip these overview pages listing very old advisories
    previous_advisories = [
        re.escape(url)
        for url in [
            "http://confluence.atlassian.com/display/JIRA/Security+Advisories",
            "https://confluence.atlassian.com/display/DOC/Confluence+Security+Overview+and+Advisories",
            "https://confluence.atlassian.com/x/8ahMMQ",
            "https://confluence.atlassian.com/display/BAMBOO/Bamboo+security+advisories",
            "https://confluence.atlassian.com/bitbucketserver/bitbucket-server-security-advisories-776640597.html",
            "https://confluence.atlassian.com/sourcetreekb/security-advisories-900820352.html",
            "https://confluence.atlassian.com/display/FISHEYE/Security+advisories",
            "https://confluence.atlassian.com/display/CRUCIBLE/Security+advisories",
        ]
    ]

    def parse(self, response):
        link_extractor = LinkExtractor(
            deny=self.previous_advisories,
            restrict_css=".component--textblock",
        )
        for link in link_extractor.extract_links(response):
            if "advisories-overview" in link.url:
                yield Request(link.url, callback=self.parse_overview)
            else:
                yield Request(link.url, callback=self.parse_item)

    def parse_overview(self, response):
        link_extractor = LinkExtractor(
            restrict_css=".wiki-content table td:first-of-type",
        )
        for link in link_extractor.extract_links(response):
            yield Request(link.url, callback=self.parse_item)

    def parse_item(self, response):
        match = re.fullmatch(
            r"https://confluence.atlassian.com/([^/]+)/([^/.]+).html", response.url
        )
        if not match:
            raise ValueError("unexpected URL format")
        product = match.group(1)
        id_ = match.group(2)

        item = {
            "spider": self.name,
            "href": response.url,
            "product": product,
            "id": id_,
        }

        table = response.css(".wiki-content table")
        raw = {}
        if table:
            for row in table[0].css("tbody tr"):
                heading = row.css("th").xpath("normalize-space()").get()
                # Normalize headings for common keys we want to extract later
                match utils.RegexEqual(heading):
                    case r"(?i)Summary":
                        heading = "description"
                    case r"(?i)Advisory Release Date":
                        heading = "publish_date"
                    case r"(?i)CVE ID":
                        heading = "cves"
                    # There may be duplicate Affected Foo Versions an Affected Bar Versions headings in the same advisory, can't easily extract them
                ul = row.css("td ul")
                date = row.css("td time::attr(datetime)").get()
                if ul:
                    value = [utils.to_plaintext(x) for x in ul.css("li")]
                elif date:
                    value = date
                    # Not all Advisory Release Dates use a <time> element. The ones that don't also have inconsistent formatting of the date time.
                else:
                    value = utils.to_plaintext(row.css("td"))
                raw[heading] = value

        if cves := raw.get("cves", None):
            item["cves"] = (
                sorted(
                    re.findall(
                        utils.CVE_REGEX,
                        # raw['cves'] might be an array or a string
                        cves if isinstance(cves, str) else " ".join(cves),
                    )
                )
                or None
            )
        else:
            item["cves"] = (
                sorted(
                    list(
                        set(
                            cve.upper()
                            for cve in response.css(".wiki-content").re(utils.CVE_REGEX)
                        )
                    )
                )
                or None
            )
        item["title"] = (
            response.css("h1.page-title::text").get()
            or response.css("title::text").get()
        )
        item["description"] = raw.get("description", None)
        item["publish_date"] = raw.get("publish_date", None)
        item["raw"] = raw
        item["markdown"] = (
            HTML2Text(baseurl=response.url)
            .handle(response.css(".wiki-content").get())
            .strip()
        )

        return item

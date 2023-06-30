import re
from io import BytesIO
import time

from scrapy import Request, Selector, Spider
from .. import utils
from scrapy.utils.spider import iterate_spider_output
from html2text import HTML2Text

import feedparser


class FeedSpiderBase(Spider):
    def parse_entry(self, response, entry, item):
        """This method must be overridden with your custom spider functionality"""
        return item

    def _parse(self, response, **kwargs):
        d = feedparser.parse(
            # Wrap string in BytesIO to avoid parsing untrusted string as a URL
            # https://github.com/kurtmckee/feedparser/blob/d2d00088aa4c74351dc383e3af30750820494157/feedparser/api.py#L166-L169
            BytesIO(response.body),
            response_headers=response.headers,
        )

        ids = set()

        for entry in d.entries:
            # https://feedparser.readthedocs.io/en/latest/reference-entry-link.html
            # may be a GUID?
            href = entry.link

            id_ = utils.slug(entry.id or entry.link)
            if id_ in ids:
                raise ValueError(f"Duplicate ID in feed: {id_} {href}")
            ids.add(id)

            if "updated_parsed" in entry:
                updated = time.strftime("%Y-%m-%dT%H:%M:%SZ", entry.updated_parsed)
            elif "published_parsed" in entry:
                updated = time.strftime("%Y-%m-%dT%H:%M:%SZ", entry.published_parsed)
            else:
                updated = None

            if (
                entry.title_detail.type == "text/html"
                or entry.title_detail.type == "application/xhtml+xml"
            ):
                title = utils.to_plaintext(Selector(text=entry.title_detail.value))
            else:
                title = entry.title_detail.value

            if "content" in entry:
                content = entry.content[0]
            elif "summary_detail" in entry:
                content = entry.summary_detail
            else:
                content = None

            cve_search_locations = [href, title]

            if content:
                # Regex can be done on the raw HTML, that's fine and may discover CVEs in link URLs
                cve_search_locations.append(content.value)

                if content.type == "text/html" or c.type == "application/xhtml+xml":
                    description = (
                        HTML2Text(baseurl=response.url).handle(content.value).strip()
                    )
                else:
                    description = content.value
            else:
                description = None

            cves = (
                sorted(
                    list(
                        set(
                            cve.upper()
                            for cve in re.findall(
                                utils.CVE_REGEX, " ".join(cve_search_locations)
                            )
                        )
                    )
                )
                or None
            )

            raw = dict(entry)

            item = {
                "href": href,
                "id": id_,
                "updated": updated,
                "title": title,
                "description": description,
                "cves": cves,
                "raw": raw,
            }

            yield from iterate_spider_output(
                self.parse_entry(response, entry, item, **kwargs)
            )


class FeedSpider(FeedSpiderBase):
    name = "feeds"
    start_feeds = {
        "gitlab_security_releases": "https://about.gitlab.com/security-releases.xml",
        "palo_alto_security_advisories": "https://security.paloaltonetworks.com/rss.xml",
        "hashicorp_security_advisories": "https://discuss.hashicorp.com/c/security/52.rss",
        "elastic_security_advisories": "https://discuss.elastic.co/c/announcements/security-announcements/31.rss",
        "nifi_security_advisories": "https://github.com/apache/nifi-site/commits/main/src/pages/html/security.hbs.atom",
        "solr_security_advisories": "https://solr.apache.org/feeds/solr/security.atom.xml",
        "kiali_security_advisories": "https://kiali.io/news/security-bulletins/index.xml",
        "grafana_security_advisories": "https://grafana.com/security/security-advisories/index.xml",
        "grafana_announcements": "https://community.grafana.com/c/support/security-announcements/38.rss",
        # "https://grafana.com/tags/security/index.xml",
        # "https://blog.min.io/tag/security/rss/",
        # "https://istio.io/feed.xml",
        # "istio_blog": "https://github.com/istio/istio.io/commits/master/content/en/news/security.atom",
    }

    def start_requests(self):
        for feed_name, feed_url in self.start_feeds.items():
            yield Request(
                feed_url,
                cb_kwargs={"feed_name": feed_name},
            )

    def parse_entry(self, response, entry, item, feed_name):
        return {
            **item,
            "spider": "feeds",
            "product": feed_name,
        }

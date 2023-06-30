import re

import scrapy
from scrapy import Request, Spider

# https://docs.github.com/en/rest/security-advisories/repository-advisories?apiVersion=2022-11-28


class GithubSecurityAdvisoriesSpider(Spider):
    name = "github_security_advisories"
    allowed_domains = ["api.github.com"]
    start_repos = [
        "containers/buildah",
        "containers/podman",
        "containers/common",
        "containers/image",
        "containers/storage",
        "envoyproxy/envoy",
        "kyverno/kyverno",
        "rancher/rancher",
    ]

    def start_requests(self):
        for repo in self.start_repos:
            yield Request(
                f"https://api.github.com/repos/{repo}/security-advisories?sort=updated",
                cb_kwargs={"repo": repo},
            )

    def parse(self, response, repo):
        for advisory in response.json():
            yield {
                "spider": "github_security_advisories",
                "product": repo,
                "id": advisory["ghsa_id"],
                "href": advisory["html_url"],
                # cve_id may be null. Could use "identifiers" instead, not sure if multiple CVEs are possible
                "cves": [advisory["cve_id"]],
                "severity": advisory["severity"],
                "publish_date": advisory["published_at"],
                "severity": advisory["severity"],
                "title": advisory["summary"],
                "description": advisory["description"],
                "raw": advisory,
            }

        if "link" in response.headers:
            if rel_next := re.match(
                rb'<([^>]*)>; rel="next"', response.headers["link"]
            ):
                yield Request(
                    rel_next.group(1).decode("utf-8"), cb_kwargs={"repo": repo}
                )

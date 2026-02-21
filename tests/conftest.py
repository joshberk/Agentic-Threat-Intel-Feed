"""
Shared fixtures for the Agentic Threat Intel Feed test suite.
"""

import pytest


@pytest.fixture
def sample_item():
    return {
        "id": "https://example.com/article-1",
        "title": "Critical RCE in Apache Log4j",
        "url": "https://example.com/article-1",
        "source": "TheHackerNews",
        "published": "2024-01-15",
        "content": "A critical remote code execution vulnerability was found in Apache Log4j.",
    }


@pytest.fixture
def sample_items():
    return [
        {
            "id": f"https://example.com/article-{i}",
            "title": f"Test Article {i}",
            "url": f"https://example.com/article-{i}",
            "source": "TestSource",
            "published": "2024-01-15",
            "content": f"Content for article {i}",
        }
        for i in range(5)
    ]


@pytest.fixture
def enriched_item(sample_item):
    return {
        **sample_item,
        "summary": "Critical RCE vulnerability found in Apache Log4j affecting millions.",
        "severity": 9,
        "topics": ["CVE", "vulnerabilities", "exploit"],
    }


@pytest.fixture
def deep_dive_item(enriched_item):
    return {
        **enriched_item,
        "deep_dive": True,
        "deep_summary": "Detailed analysis of the Apache Log4j RCE vulnerability.",
        "iocs": ["1.2.3.4", "evil.com"],
        "affected_products": ["Apache Log4j 2.14.1"],
        "cve_ids": ["CVE-2021-44228"],
        "threat_actor": "APT41",
        "mitigations": ["Upgrade to Log4j 2.17.0", "Apply WAF rules"],
    }

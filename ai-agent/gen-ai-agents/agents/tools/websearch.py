import os
import requests
from typing import List, Dict

TAVILY_URL = os.getenv("TAVILY_URL", "https://api.tavily.com/search")
TAVILY_KEY = os.getenv("TAVILY_API_KEY")

def _format_result_item(item: Dict) -> str:
    title = item.get("title", "")
    snippet = item.get("content", "") or item.get("snippet", "")
    url = item.get("url", "")
    return f"- {title}\n  {snippet}\n  {url}"

def websearch(query: str, num_results: int = 5, timeout: int = 10) -> str:
    """
    Query the Tavily search endpoint and return a plain-text summary suitable for LLM input.
    """
    if not TAVILY_KEY:
        return "Error: TAVILY_API_KEY not set."

    headers = {
        "Authorization": f"Bearer {TAVILY_KEY}",
        "Content-Type": "application/json"
    }

    data = {
        "query": query,
        "max_results": num_results,
        "search_depth": "basic"
    }

    try:
        resp = requests.post(TAVILY_URL, json=data, headers=headers, timeout=timeout)
        resp.raise_for_status()
        payload = resp.json()
    except requests.RequestException as exc:
        return f"WebSearch error: {exc}"

    results = payload.get("results", [])
    if not results:
        return "WebSearch: no results found."

    formatted = [f"Result {i+1}:\n{_format_result_item(r)}" for i, r in enumerate(results[:num_results])]
    return "\n\n".join(formatted)

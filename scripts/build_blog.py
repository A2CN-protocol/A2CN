#!/usr/bin/env python3
"""Build static A2CN blog pages from markdown posts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from html import escape
from pathlib import Path
import json
import re
import shutil


ROOT = Path(__file__).resolve().parents[1]
POSTS_DIR = ROOT / "blog" / "posts"
BLOG_DIR = ROOT / "blog"
SITE_URL = "https://a2cn.io"
OG_IMAGE = f"{SITE_URL}/og-cover.png"


@dataclass(frozen=True)
class Post:
    title: str
    description: str
    date: str
    slug: str
    markdown: str
    html: str

    @property
    def url(self) -> str:
        return f"{SITE_URL}/blog/{self.slug}/"

    @property
    def display_date(self) -> str:
        parsed = date.fromisoformat(self.date)
        return parsed.strftime("%B %-d, %Y")


def parse_frontmatter(raw: str) -> tuple[dict[str, str], str]:
    if not raw.startswith("---\n"):
        raise ValueError("Post is missing frontmatter")
    _, frontmatter, body = raw.split("---\n", 2)
    metadata: dict[str, str] = {}
    for line in frontmatter.splitlines():
        if not line.strip():
            continue
        key, value = line.split(":", 1)
        metadata[key.strip()] = value.strip().strip('"')
    for required in ("title", "description", "date", "slug"):
        if required not in metadata:
            raise ValueError(f"Post frontmatter missing {required!r}")
    return metadata, body.lstrip("\n")


def render_inline(text: str) -> str:
    rendered = escape(text)
    rendered = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", rendered)
    rendered = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        lambda match: (
            f'<a href="{escape(match.group(2), quote=True)}">'
            f"{match.group(1)}</a>"
        ),
        rendered,
    )
    return rendered


def markdown_to_html(markdown: str) -> str:
    blocks: list[str] = []
    paragraph: list[str] = []

    def flush_paragraph() -> None:
        if paragraph:
            blocks.append(f"<p>{render_inline(' '.join(paragraph))}</p>")
            paragraph.clear()

    for line in markdown.splitlines():
        stripped = line.strip()
        if not stripped:
            flush_paragraph()
            continue
        if stripped.startswith("## "):
            flush_paragraph()
            blocks.append(f"<h2>{render_inline(stripped[3:])}</h2>")
            continue
        if stripped.startswith("# "):
            flush_paragraph()
            blocks.append(f"<h1>{render_inline(stripped[2:])}</h1>")
            continue
        paragraph.append(stripped)

    flush_paragraph()
    return "\n".join(blocks)


def read_posts() -> list[Post]:
    posts: list[Post] = []
    for path in sorted(POSTS_DIR.glob("*.md")):
        metadata, body = parse_frontmatter(path.read_text())
        posts.append(
            Post(
                title=metadata["title"],
                description=metadata["description"],
                date=metadata["date"],
                slug=metadata["slug"],
                markdown=body,
                html=markdown_to_html(body),
            )
        )
    return sorted(posts, key=lambda post: post.date, reverse=True)


def meta_tags(post: Post | None = None) -> str:
    if post is None:
        title = "A2CN Blog"
        description = (
            "Analysis and field notes on autonomous procurement, supplier "
            "negotiation, and agent-to-agent commercial protocols."
        )
        url = f"{SITE_URL}/blog/"
        og_type = "website"
    else:
        title = post.title
        description = post.description
        url = post.url
        og_type = "article"

    tags = f"""  <title>{escape(title)}</title>
  <meta name="description" content="{escape(description, quote=True)}">
  <link rel="canonical" href="{escape(url, quote=True)}">
  <meta property="og:type" content="{og_type}">
  <meta property="og:site_name" content="A2CN">
  <meta property="og:title" content="{escape(title, quote=True)}">
  <meta property="og:description" content="{escape(description, quote=True)}">
  <meta property="og:url" content="{escape(url, quote=True)}">
  <meta property="og:image" content="{OG_IMAGE}">
  <meta property="og:image:width" content="1200">
  <meta property="og:image:height" content="630">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="{escape(title, quote=True)}">
  <meta name="twitter:description" content="{escape(description, quote=True)}">
  <meta name="twitter:image" content="{OG_IMAGE}">"""

    if post is not None:
        tags += f"""
  <meta property="article:published_time" content="{post.date}">
  <script type="application/ld+json">{json.dumps(article_schema(post), separators=(',', ':'))}</script>"""

    return tags


def article_schema(post: Post) -> dict:
    return {
        "@context": "https://schema.org",
        "@type": "Article",
        "headline": post.title,
        "description": post.description,
        "datePublished": post.date,
        "dateModified": post.date,
        "url": post.url,
        "image": OG_IMAGE,
        "author": {"@type": "Organization", "name": "A2CN Protocol"},
        "publisher": {
            "@type": "Organization",
            "name": "A2CN",
            "logo": {"@type": "ImageObject", "url": f"{SITE_URL}/og-cover.png"},
        },
        "mainEntityOfPage": {"@type": "WebPage", "@id": post.url},
    }


def page_shell(meta: str, main: str, depth: int = 1) -> str:
    root = "../" * depth
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
{meta}
  <link rel="icon" href="{root}favicon.svg" type="image/svg+xml">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&amp;family=IBM+Plex+Sans:wght@400;500;600;700&amp;display=swap" rel="stylesheet">
  <script defer data-domain="a2cn.io" src="https://plausible.io/js/script.tagged-events.js"></script>
  <link rel="stylesheet" href="{root}blog/blog.css">
</head>
<body>
<nav>
  <div class="nav-inner">
    <a class="nav-logo" href="/"><span class="nav-logo-dot"></span>A2CN</a>
    <div class="nav-links">
      <a class="btn" href="/docs.html">Docs</a>
      <a class="btn" href="/blog/">Blog</a>
      <a class="btn plausible-event-name=GitHub+Click" href="https://github.com/A2CN-protocol/A2CN" target="_blank" rel="noopener">GitHub &rarr;</a>
    </div>
  </div>
</nav>
{main}
<footer>
  <div class="footer-inner">
    <span>A2CN Blog</span>
    <span>Open protocol for agent-to-agent commercial negotiation</span>
  </div>
</footer>
</body>
</html>
"""


def render_index(posts: list[Post]) -> str:
    cards = "\n".join(
        f"""    <article class="post-card">
      <time datetime="{post.date}">{post.display_date}</time>
      <h2><a href="/blog/{post.slug}/">{escape(post.title)}</a></h2>
      <p>{escape(post.description)}</p>
      <a class="read-link" href="/blog/{post.slug}/">Read the post &rarr;</a>
    </article>"""
        for post in posts
    )
    main = f"""<header class="blog-hero">
  <div class="container">
    <div class="eyebrow">Field notes</div>
    <h1>A2CN Blog</h1>
    <p>Analysis on autonomous procurement, supplier negotiation, and the protocol layer agents need when both sides of the table become software.</p>
  </div>
</header>
<main class="container post-list" aria-label="Blog posts">
{cards}
</main>"""
    return page_shell(meta_tags(), main, depth=1)


def render_post(post: Post) -> str:
    main = f"""<main class="article-shell">
  <article class="article">
    <a class="back-link" href="/blog/">&larr; Blog</a>
    <header class="article-header">
      <time datetime="{post.date}">{post.display_date}</time>
      <p>{escape(post.description)}</p>
    </header>
    <div class="article-body">
{post.html}
    </div>
  </article>
</main>"""
    return page_shell(meta_tags(post), main, depth=2)


def clean_generated_post_dirs(posts: list[Post]) -> None:
    keep = {post.slug for post in posts}
    for path in BLOG_DIR.iterdir():
        if path.is_dir() and path.name not in keep and path.name != "posts":
            shutil.rmtree(path)


def main() -> None:
    posts = read_posts()
    clean_generated_post_dirs(posts)
    (BLOG_DIR / "index.html").write_text(render_index(posts))
    for post in posts:
        post_dir = BLOG_DIR / post.slug
        post_dir.mkdir(parents=True, exist_ok=True)
        (post_dir / "index.html").write_text(render_post(post))


if __name__ == "__main__":
    main()

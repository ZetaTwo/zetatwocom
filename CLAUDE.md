# zeta-two.com

Personal blog of Calle "Zeta Two" Svensson at https://zeta-two.com. Built with **Hugo 0.161.1** (the standard build; no extended Hugo, Sass or Node needed). Migrated from Jekyll in May 2026; the `pre-hugo-migration` tag points at the final Jekyll commit on master.

## Local development

```
hugo server               # serve at http://localhost:1313, live reload
hugo --quiet              # one-shot build to public/
hugo new posts/<cat>/$(date +%Y-%m-%d)-my-slug.md
```

The theme's stylesheets are plain CSS in `themes/zetatwo/assets/css/`. Hugo's built-in `css.Build` (esbuild) bundles `main.css`'s `@import`s and minifies the result. The deploy workflow pins `HUGO_VERSION` (the version at the top of this file) in `.github/workflows/deploy.yml`. If you upgrade Hugo locally, update `HUGO_VERSION`, `HUGO_SHA256` (the `linux-amd64.deb` line of the release's `hugo_<version>_checksums.txt`) and `min_version` in `themes/zetatwo/theme.toml` to match.

## Deploy

Push to `master`. The workflow at `.github/workflows/deploy.yml` runs the Hugo version pinned in its `HUGO_VERSION` and publishes `public/` to GitHub Pages. Repo Settings → Pages source must be set to "GitHub Actions" (one-time).

`static/CNAME` keeps the `zeta-two.com` custom domain wired to the deployed site; DNS A/AAAA records must point at GitHub Pages (`185.199.108.153–156`).

## Repo layout

```
config.toml              site config: baseURL, [pagination], [params], [permalinks], Goldmark, RSS limit
archetypes/default.md    `hugo new` template
content/
  about.md services.md talks.md trainings.md challenges.md kodsport-challenge.md
  posts/_index.md          marks /posts/ as not rendered (categories live at /<cat>/)
  posts/<cat>/             50 posts across 8 categories
    _index.md              section marker — required (see "Gotchas")
    YYYY-MM-DD-<slug>.md
data/comments.json                   Disqus comment archive, keyed by post URL (see "Comments")
themes/zetatwo/
  layouts/_default/{baseof,single,list}.html
  layouts/_default/rss.xml           full-content, posts-only feed (see "Gotchas")
  layouts/_markup/render-passthrough.html   build-time KaTeX (see "Math")
  layouts/posts/single.html          post template with .post-meta date line
  layouts/{index,404}.html
  layouts/partials/{head,header,footer,comments,comment,katex,pagination}.html
  assets/css/main.css                entry point: @imports the files below, bundled by css.Build
  assets/css/{variables,base,layout,syntax-highlighting}.css   plain CSS; variables.css holds the custom properties
  static/img/                        theme images (banners, backgrounds)
static/
  assets/                            content images, PDFs, videos, downloads
  {CNAME, favicon.ico, robots.txt}
.github/workflows/deploy.yml         GH Pages deploy
```

## Conventions

### Post frontmatter

```yaml
---
title: "Post title"
date: 2020-04-05T23:30:00+02:00         # ISO + Europe/Stockholm offset (+02:00 DST, +01:00 winter)
slug: short-filename-slug                # derived from filename minus YYYY-MM-DD- prefix
categories: [software, exploit]          # first must match the directory name
aliases:
  - /software/exploit/2020/04/05/short-filename-slug.html   # the old Jekyll URL, preserved
math: true                               # only on posts that use \(..\) / \[..\]
---

First paragraph — shows up as the summary on the home and section lists.

<!--more-->

Rest of the post.
```

- **URL pattern**: posts get `/<category>/<YYYY>/<MM>/<DD>/<slug>/` from the `[permalinks]` block in `config.toml`. The category comes from the file's parent directory (via `:sections[1:]`), so a post under `content/posts/ctf/` is at `/ctf/...`. Per-post `slug:` is what `:slug` reads — without it, Hugo would default to a title-slug and break URL fidelity.
- **Aliases**: every post has an `aliases:` entry for its old Jekyll `.html` URL. Hugo emits a meta-refresh stub at that path so old links keep working. Jekyll built that URL as `/<all categories joined by />/<YYYY>/<MM>/<DD>/<filename slug>.html`, taking the date from front matter (not the filename) whenever `date:` was set. To double-check one, look at the post's front matter in `git show pre-hugo-migration:_posts/<cat>/<file>.md`.
- **Section pages**: each `content/posts/<cat>/_index.md` sets `url: /<cat>/` (with an alias for the short-lived `/posts/<cat>/`), so category listings live at `/<cat>/`. Hugo's taxonomy pages are disabled (`disableKinds`); `categories:` front matter only feeds the RSS `<category>` tags.
- **Summary**: `<!--more-->` after the first paragraph mirrors Jekyll's `post.excerpt` contract.

### Math

Inline math uses `\(..\)`, display math uses `\[..\]`. Goldmark's passthrough extension hands the contents over verbatim (no typographer, no `_` emphasis) to `themes/zetatwo/layouts/_markup/render-passthrough.html`, which renders it to HTML at build time with `transform.ToMath`. Invalid TeX fails the build. No KaTeX JavaScript ships to the browser; `math: true` in frontmatter only pulls in the KaTeX stylesheet via the `katex.html` partial.

### Comments

Comments are a read-only archive of the old Disqus threads (shortname `zetatwo`), imported once from a Disqus XML export into `data/comments.json`. Keys are post URL paths (`.RelPermalink`), and values are comment trees holding `name`, `date`, `message` (Disqus-sanitised HTML) and `replies`. `partials/comments.html` renders the tree for the current post; posts with no entry show nothing. If a post's URL ever changes, its key in the JSON has to change with it.

### Adding a new category

1. Create `content/posts/<newcat>/_index.md` with `title:` and `url: /<newcat>/` frontmatter.
2. Add an entry to the `[permalinks]` block in `config.toml` if the URL pattern should differ from the inherited `:sections[1:]/...` template.

## Gotchas

- **Each category subdirectory needs `_index.md`.** Without it, Hugo treats the directory as a plain folder under the `posts` section, `:sections` resolves to just `["posts"]`, and `:sections[1:]` is empty — URLs come out as `/<YYYY>/<MM>/<DD>/<slug>/` with no category prefix.
- **Date format matters.** Hugo's YAML parser only recognizes a date when it's in ISO form with seconds. Jekyll's `YYYY-MM-DD HH:MM` (no seconds) parses as a *string*, leaves `.Date` zero, and produces `/0001/01/01/...` URLs.
- **Don't use `$..$` math delimiters.** Passthrough applies site-wide, and `$` delimiters would swallow shell prompts like `$ nc ...` in blockquotes of non-math posts. A literal `\(` or `\[` outside code is now treated as math in every post, so put those in backticks.
- **The typographer also rewrites blockquotes.** Terminal output written as `>` blockquotes gets `--` turned into an en dash, `<<`/`>>` into guillemets and `...` into an ellipsis. Put command output in fenced code blocks instead.
- **Pagination uses the `[pagination]` block.** Set `pagerSize = 5` under `[pagination]` in `config.toml`. The legacy top-level `paginate = N` key was silently ignored starting somewhere between Hugo 0.123 and 0.161 — if a future build mysteriously shows 10 posts per page when the config says otherwise, this is what to check.
- **`outputFormats.RSS.baseName = "feed"`** means every RSS feed across the site is named `feed.xml` (not `index.xml`): `/feed.xml` for the site and `/<cat>/feed.xml` per category. The theme's `rss.xml` mirrors the old Jekyll feed: posts only, full content (root-relative links made absolute), capped by `[services.rss] limit` in `config.toml`.
- **`url()` in the theme CSS must point at an external path.** `css.Build` (esbuild) tries to bundle every `url()` it sees and fails with "Could not resolve". Theme images live in `themes/zetatwo/static/img/` and are listed as `externals: ["/img/*"]` in `partials/head.html`; a `url()` to any other path needs its own externals entry.
- **Bare URLs inside double quotes need `<..>`.** With the typographer on, Goldmark's linkify pulls the closing `"` into the link (`href="https://example.com/%22"`). Write `"<https://example.com>"` instead, or use backticks for URLs that are examples rather than links.
- **Don't add `[languages.<lang>]` to `config.toml`** unless you're ready to also touch every URL in content. As soon as that table exists, Hugo switches into multilingual mode and applies a built-in `_markup/render-link.html` hook that calls `urls.Parse` on every link. The 2015 djulkalendern writeup links to a tryapl.org URL using JavaScript-style `%uXXXX` escapes (not RFC-3986 `%XX`) and the parser refuses to build. We use `defaultContentLanguage = "en"` instead, which keeps the build single-language and lets the bad URL through. Side-effect: `<html lang>` and the RSS `<language>` tag are just `en` rather than `en-us`.

## Deferred follow-ups

See [TODO.md](TODO.md).

## Migration history

`git log master..hugo --oneline` (pre-cutover) walks through the migration step-by-step. The plan that drove it lived at `~/.claude/plans/this-is-my-personal-gleaming-sunset.md`. The `pre-hugo-migration` tag (created at cutover) points at the final Jekyll commit on master so `git diff pre-hugo-migration master -- <path>` can spot anything that got missed.

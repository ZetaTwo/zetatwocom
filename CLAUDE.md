# zeta-two.com

Personal blog of Calle "Zeta Two" Svensson at https://zeta-two.com. Built with **Hugo 0.161.1 extended**. Migrated from Jekyll in May 2026; the `pre-hugo-migration` tag points at the final Jekyll commit on master.

## Local development

```
hugo server               # serve at http://localhost:1313, live reload
hugo --quiet              # one-shot build to public/
hugo new posts/<cat>/$(date +%Y-%m-%d)-my-slug.md
```

Hugo **must be the extended distribution** because the theme pipes SCSS through `resources.Get | toCSS`. Check with `hugo version` — should say `+extended`. The deploy workflow pins to the exact version listed at the top of this file; if you upgrade locally, update `HUGO_VERSION` in `.github/workflows/deploy.yml` and `min_version` in `themes/zetatwo/theme.toml` to match.

## Deploy

Push to `master`. The workflow at `.github/workflows/deploy.yml` runs Hugo 0.123.7 extended and publishes `public/` to GitHub Pages. Repo Settings → Pages source must be set to "GitHub Actions" (one-time).

`static/CNAME` keeps the `zeta-two.com` custom domain wired to the deployed site; DNS A/AAAA records must point at GitHub Pages (`185.199.108.153–156`).

## Repo layout

```
config.toml              site config: baseURL, paginate=5, [params], [permalinks], Goldmark
archetypes/default.md    `hugo new` template
content/
  about.md services.md talks.md trainings.md
  challenges/{index.md, kodsport-challenge.md}
  posts/<cat>/             50 posts across 8 categories
    _index.md              section marker — required (see "Gotchas")
    YYYY-MM-DD-<slug>.md
themes/zetatwo/
  layouts/_default/{baseof,single,list}.html
  layouts/posts/single.html          post template with .post-meta date line
  layouts/{index,404}.html
  layouts/partials/{head,header,footer,comments,katex,pagination}.html
  assets/scss/{main,_base,_layout,_syntax-highlighting}.scss
  static/img/                        theme images (banners, backgrounds)
static/
  assets/                            content images, KaTeX JS, PDFs, videos
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
  - /software/2020/04/05/short-filename-slug.html   # the old Jekyll URL, preserved
math: true                               # only on posts that use $..$ / $$..$$
---

First paragraph — shows up as the summary on the home and section lists.

<!--more-->

Rest of the post.
```

- **URL pattern**: posts get `/<category>/<YYYY>/<MM>/<DD>/<slug>/` from the `[permalinks]` block in `config.toml`. The category comes from the file's parent directory (via `:sections[1:]`), so a post under `content/posts/ctf/` is at `/ctf/...`. Per-post `slug:` is what `:slug` reads — without it, Hugo would default to a title-slug and break URL fidelity.
- **Aliases**: every post has an `aliases:` entry for its old Jekyll `.html` URL. Hugo emits a meta-refresh stub at that path so old links keep working.
- **Summary**: `<!--more-->` after the first paragraph mirrors Jekyll's `post.excerpt` contract.

### Math

`math: true` in frontmatter triggers the `katex.html` partial. Inline math uses `$..$`, display math uses `$$..$$`. KaTeX auto-render is configured with those delimiters explicitly.

### Adding a new category

1. Create `content/posts/<newcat>/_index.md` with at least `title:` frontmatter.
2. Add an entry to the `[permalinks]` block in `config.toml` if the URL pattern should differ from the inherited `:sections[1:]/...` template.

## Gotchas

- **Each category subdirectory needs `_index.md`.** Without it, Hugo treats the directory as a plain folder under the `posts` section, `:sections` resolves to just `["posts"]`, and `:sections[1:]` is empty — URLs come out as `/<YYYY>/<MM>/<DD>/<slug>/` with no category prefix.
- **Date format matters.** Hugo's YAML parser only recognizes a date when it's in ISO form with seconds. Jekyll's `YYYY-MM-DD HH:MM` (no seconds) parses as a *string*, leaves `.Date` zero, and produces `/0001/01/01/...` URLs.
- **Goldmark typographer is off.** With it on, `m'` in `$m'_i$` gets smart-quoted to `m\rsquo;_i` and KaTeX can't parse it. Trade-off: body-text contractions like "let's" render with ASCII `'`. To revisit later, two options: a math shortcode that bypasses Goldmark, or setting `[markup.goldmark.extensions.typographer].apostrophe = "'"` (preserves primes, keeps quote/dash substitutions).
- **Stray `$` in non-math content of math posts.** KaTeX auto-render scans the whole body. Anything in a code block is skipped, but stray `$` in regular text or blockquotes will be misrendered. Wrap in backticks or move into a fenced block. Only the 5 `math: true` posts are affected.
- **Pagination uses the `[pagination]` block.** Set `pagerSize = 5` under `[pagination]` in `config.toml`. The legacy top-level `paginate = N` key was silently ignored starting somewhere between Hugo 0.123 and 0.161 — if a future build mysteriously shows 10 posts per page when the config says otherwise, this is what to check.
- **`outputFormats.RSS.baseName = "feed"`** means every RSS feed across the site is named `feed.xml` (not `index.xml`). Section feeds end up at `/posts/<cat>/feed.xml`, which is harmless.
- **`languageCode` config key emits a deprecation warning** in 0.158+ (replaced by per-language `locale`). The site still builds fine and the RSS `<language>` tag still works. Fix when bumping Hugo again: replace top-level `languageCode = "en-us"` with `defaultContentLanguage = "en"` + `[languages.en]\n  locale = "en-us"`, and swap `.Site.LanguageCode` → `.Site.Language.Locale` in `themes/zetatwo/layouts/_default/baseof.html`.

## Deferred follow-ups

- **Disqus comment archive.** The original site used `disqus_shortname: zetatwo`. Comments are currently disabled (`themes/zetatwo/layouts/partials/comments.html` is a stub). The plan is a separate project: scrape the Disqus thread for each post and bake the HTML into the page below the post body. The shortname is preserved as a comment in `config.toml` for the future scrape.
- **Section landing pages at `/<cat>/`.** Jekyll had category index pages at `/ctf/`, `/education/`, etc. Hugo's section pages live at `/posts/ctf/`, `/posts/education/`. To match Jekyll, add `url: /<cat>/` to each `content/posts/<cat>/_index.md`.
- **Draft branches.** Seven half-finished writeups live on their own branches (`draft-bdayctf2020`, `draft-djul2020`, `draft-ssm2016`, `draft-sstic21`, `draft-starcraft`, `injection-attacks-draft`, `page-achievments`). Rebase onto `master` (post-cutover) and finish individually.
- **DCTF finals writeup.** Noted in [TODO](TODO) as "Add writeups for DCTF finals" — write as a normal new post.

## Migration history

`git log master..hugo --oneline` (pre-cutover) walks through the migration step-by-step. The plan that drove it lived at `~/.claude/plans/this-is-my-personal-gleaming-sunset.md`. The `pre-hugo-migration` tag (created at cutover) points at the final Jekyll commit on master so `git diff pre-hugo-migration master -- <path>` can spot anything that got missed.

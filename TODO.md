# TODO

## New content
* Add writeup for DCTF finals

## Drafts to finish (each lives on its own branch)
* `draft-bdayctf2020`
* `draft-djul2020`
* `draft-ssm2016`
* `draft-sstic21`
* `draft-starcraft`
* `injection-attacks-draft`
* `page-achievments`

## Site / infra
* Bake historical Disqus comments as static HTML below each post (shortname: `zetatwo`); kept as a comment in `config.toml` for the future scrape
* Move Hugo section landing pages from `/posts/<cat>/` to `/<cat>/` to match the Jekyll URLs — add `url: /<cat>/` to each `content/posts/<cat>/_index.md`
* Bring back smart quotes for body text without breaking KaTeX primes — either set `apostrophe = "'"` under `[markup.goldmark.extensions.typographer]` (keeps quote/dash substitutions, leaves `'` alone) or wrap math in a shortcode that bypasses Goldmark, then re-enable the extension

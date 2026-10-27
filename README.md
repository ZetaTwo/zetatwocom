# zeta-two.com

My personal website and blog at <https://zeta-two.com>, built with [Hugo](https://gohugo.io/).

## Running it locally

Install [Hugo](https://github.com/gohugoio/hugo/releases) 0.161.1. The standard edition is enough; the exact version is pinned in `.github/workflows/deploy.yml`. Then:

```
hugo server        # serve at http://localhost:1313 with live reload; add -D to include drafts
hugo --minify      # build the site into public/
hugo new posts/ctf/2026-10-27-my-post.md   # start a new post (created as a draft)
```

Pushing to `master` builds and deploys the site to GitHub Pages.

## License

The code in this repository (the theme, templates, stylesheets, configuration and build workflow) is licensed under the [Apache License 2.0](LICENSE), Copyright Calle Svensson. Parts of the theme's stylesheets are derived from Jekyll's default site template, MIT License, Copyright (c) 2008-2015 Tom Preston-Werner.

The content is not covered by that license: the posts and pages in `content/` and the files in `static/assets/` are Copyright Calle Svensson, all rights reserved, unless stated otherwise. The archived comments in `data/comments.json` belong to their authors.

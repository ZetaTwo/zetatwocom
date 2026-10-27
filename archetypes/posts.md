{{- $slug := replaceRE `^\d{4}-\d{2}-\d{2}-` "" .File.ContentBaseName -}}
---
title: "{{ $slug | humanize | title }}"
date: {{ time.In "Europe/Stockholm" now | time.Format "2006-01-02T15:04:05-07:00" }}
slug: {{ $slug }}
categories: [{{ path.Base .File.Dir }}]
draft: true
---

First paragraph, shown as the summary on the home and category pages.

<!--more-->

Rest of the post.

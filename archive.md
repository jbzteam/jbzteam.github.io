---
layout: page
title: Archive
permalink: /archive/
---

<div class="archive">
  <ul class="post-list">
    {% for post in site.posts %}
      <li>
        <a href="{{ post.url | prepend: site.baseurl }}">{{ post.title }}</a>
        <span class="post-meta">{{ post.date | date: "%b %-d, %Y" }}</span>
      </li>
    {% endfor %}
  </ul>
</div>

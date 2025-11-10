---
layout: page
title: Home
hide_title: true
---

<section class="home-intro">
  <p>{{ site.description }}</p>
</section>

{% assign recent_posts = site.posts %}

<section class="post-list">
{% for post in recent_posts %}
  <article class="post-card">
    <h2><a href="{{ post.url | relative_url }}">{{ post.title }}</a></h2>
    <p class="post-excerpt">{{ post.excerpt | strip_html | truncatewords: 60 }}</p>
  </article>
{% endfor %}
</section>
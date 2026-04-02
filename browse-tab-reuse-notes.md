# browse tab reuse

Short answer: not with the current implementation alone.

Today `browse` only prepares arguments and launches `chrome.exe` with them. That can open URLs, but it does not give us a way to inspect existing tabs or tell Chrome "focus the tab whose URL matches this site".

There is no simple Chrome command-line flag that does that matching for us.

If you want this behavior, the practical approach is:

1. Run Chrome with a DevTools endpoint enabled, typically `--remote-debugging-port=9222`.
2. Have `browse` query `http://127.0.0.1:9222/json/list`.
3. Match the requested target against open tabs using a rule such as same origin, same host, or URL prefix.
4. If a match exists, activate that tab with `/json/activate/<target-id>`.
5. If no match exists, fall back to the current behavior and open the target normally.

Tradeoffs:

- This is feasible, but it adds logic and a dependency on Chrome being started with remote debugging enabled.
- If Chrome is already running without that port, `browse` cannot inspect existing tabs in that session.
- We would need to decide what "same site or subpage" means: same origin, same host, or path prefix.

So the answer is:

- No, not with plain `chrome.exe <url>` launching.
- Yes, if we add a control path through Chrome DevTools.
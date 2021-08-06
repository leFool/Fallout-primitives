# Fallout-primitives

An implementation of the 3 Fallout attack primitives based on the article https://mdsattacks.com/files/fallout.pdf

3.1: WTF - Write Transient Forwarding

Generates 1000 pages and fills them with random bytes (20 - 50 bytes each).
The program uses an attacker address to load the bytes from the TLB into the cache and read it from there using the Flush+Reload technique.

Command-line arguments:
*-d: debug information (shows raw statistics mostly).
*-noi: doesn't create invalid pages.
*-r[h, m, i, r]: will classify all pages into one expected result (hit, miss, invalid or random - the default).

3.2: Data bounce
3.3: Fetch+Bounce

Both are implemented together.
Generates 3000 pages and classifies them into 3 categories: TLB-hit, TLB-miss and invalid address.
The program will determine which of the 3 states are correct for each page through accessing the address with RTM and checking for the address in the cache.

Command-line arguments:
*-d: debug information (shows raw statistics mostly).
*-f: Fixes the bytes for each page to a readable string "This page has been compromised, you are not safe!".






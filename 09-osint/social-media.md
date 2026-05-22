# Social Media OSINT

## Trigger
Load when tracking a person or entity across social platforms, enumerating usernames, recovering deleted/historical social media content, investigating Twitter/X account history, analyzing BlueSky content, performing username correlation, or extracting data from gaming/fitness platforms.

## Attack Surface
Target characteristics: Twitter/X accounts (renamed or deleted), Tumblr blogs with hidden metadata, BlueSky public API accessible content, Discord server metadata (roles, emoji, embeds), username reuse across 741+ platforms, Strava/Garmin fitness routes leaking physical locations, gaming profiles with linked accounts, Unicode homoglyph steganography in social media posts.

## Decision Tree
1. Start with a known username or account URL from challenge context.
2. Check username availability across platforms via WhatsMyName/Sherlock/namechk.
3. Identify platform-specific flag hiding spots (Spotify playlist, Tumblr avatar, BlueSky post, Discord role name).
4. For deleted Twitter/X accounts: use Wayback CDX API to find archived pages with user ID.
5. For BlueSky: use the public API to search posts, actor profiles, and author feeds.
6. For Unicode stego: analyze post text character-by-character for non-ASCII homoglyphs.
7. Chain platforms: one account leads to another platform with different username.

## Techniques

### Username Enumeration
```bash
# WhatsMyName API (741+ sites)
curl -s "https://whatsmyname.app/api/lookup?username=targetuser" | jq '.sites[] | select(.status=="claimed") | .name'

# namechk.com (web interface)
# Osint Industries for fitness/niche platforms (paid)

# Manual search pattern
curl -s "https://t.me/targetuser" | grep -q "View" && echo "Exists" || echo "No profile"
# Telegram always returns 200; check for "View" vs "Contact" in title
```

### Twitter/X Account Tracking
```python
# Convert Snowflake ID to timestamp
# Every tweet/user ID encodes creation time
def snowflake_to_time(tweet_id):
    return (tweet_id >> 22) + 1288834974657  # Unix ms

# Access account by permanent numeric ID (works after rename)
# https://x.com/i/user/<numeric_id>

# Wayback CDX for historical Twitter data
import requests

# Find archived Twitter profile URLs
r = requests.get(
    "http://web.archive.org/cdx/search/cdx",
    params={
        "url": "twitter.com/TARGET_USERNAME*",
        "output": "json",
        "fl": "timestamp,original,statuscode"
    }
)

# Extract user ID from archived page JSON-LD
# Look for "author":{"identifier":"<numeric_id>"} in archived page content

# Check t.co shortlinks in archives for username rename evidence
# t.co redirects reveal the username at time of posting
```

### Alternative Twitter Data Sources
```bash
# Nitter instances (no login required)
curl -s "https://nitter.poast.org/TARGET_USERNAME" | grep -oP 'tweet-id-\d+'

# Syndication API
curl -s "https://syndication.twitter.com/srv/timeline-profile/screen-name/TARGET_USERNAME"

# memory.lol (username history tracking)
curl -s "https://memory.lol/tw/TARGET_USERNAME"

# Wayback CDX for profile images
curl "http://web.archive.org/cdx/search/cdx?url=pbs.twimg.com/profile_images/*&output=json"
```

### Tumblr Investigation
```bash
# Blog existence check (check x-tumblr-user header)
curl -sI "https://TARGET_USERNAME.tumblr.com" | grep -i x-tumblr-user

# Download avatar at max resolution
curl -o avatar.jpg "https://TARGET_USERNAME.tumblr.com/avatar/512"
# Available sizes: 16, 24, 30, 40, 48, 64, 96, 128, 512

# Extract post data from page HTML
curl -s "https://TARGET_USERNAME.tumblr.com" | grep -oP '"content":\[\K.*?(?=\])' | head -5

# API avatar endpoint
curl -s "https://api.tumblr.com/v2/blog/TARGET_USERNAME.tumblr.com/avatar/512"
```

### BlueSky Public API (No Auth Required)
```bash
# Search posts
curl -s "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?q=metactf+flag&sort=latest" | \
    jq '.posts[].record.text'

# Search actors
curl -s "https://public.api.bsky.app/xrpc/app.bsky.actor.searchActors?q=TARGET" | \
    jq '.actors[].handle'

# Get profile
curl -s "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=TARGET.bsky.social" | jq

# Get author feed (all posts)
curl -s "https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed?actor=TARGET.bsky.social&limit=50" | \
    jq '.feed[].post.record.text'

# Get post thread (including replies)
curl -s "https://public.api.bsky.app/xrpc/app.bsky.feed.getPostThread?uri=at://did:plc:.../app.bsky.feed.post/..." | jq
```

### Unicode Homoglyph Steganography Decoding
```python
def decode_homoglyph_stego(text):
    """ASCII=0, Unicode homoglyph=1. Group bits into bytes."""
    bits = []
    for ch in text:
        if ch in ('’',):  # Skip platform auto-inserted smart quotes
            continue
        if ord(ch) < 128:
            bits.append(0)
        else:
            bits.append(1)

    flag = ''
    for i in range(0, len(bits) - 7, 8):
        byte_val = 0
        for j in range(8):
            byte_val = (byte_val << 1) | bits[i + j]
        flag += chr(byte_val)
    return flag

# Common homoglyph pairs: a(ASCII)/а(Cyrillic), o/о, e/е, s/ѕ, t/𝚝, p/р
```

### Discord API Enumeration
```bash
# Requires user token (not bot token)
TOKEN="your_user_token"

# List roles (flags often hidden in role names)
curl -H "Authorization: $TOKEN" "https://discord.com/api/v10/guilds/GUILD_ID/roles"

# List emoji (check animated GIF for hidden frames)
curl -H "Authorization: $TOKEN" "https://discord.com/api/v10/guilds/GUILD_ID/emojis"

# Search messages
curl -H "Authorization: $TOKEN" \
    "https://discord.com/api/v10/guilds/GUILD_ID/messages/search?content=flag"

# Animated emoji: download GIF, extract frames
# Hidden data often in 2nd frame with tiny duration
```

### Strava Fitness Route OSINT
```bash
# Public athlete profile
curl -s "https://www.strava.com/athletes/<athlete_id>"

# Activity maps show GPS routes with start/end points
# Even "privacy zones" can be circumvented by analyzing route shapes
# Use segment leaderboards to find athlete locations without following
```

### Gaming Platform OSINT
```bash
# World of Warcraft: guild/character on raider.io or wowprogress
# Steam: steamcommunity.com/id/[username]
# Minecraft: namemc.com for skin, name history, servers
# Discord: discord.id for user/server lookups

# Cross-reference character names from guild rosters
# Gaming profiles contain rich metadata: play times, real names, linked accounts
```

### Username Metadata Mining
```
Pattern           Example              Signal
Trailing digits   LinXiayu35170        Zip/postal code, 35170 = Bruz, France
Birth year        jsmith1998           Born 1998
Area code         user212nyc           212 = Manhattan
Country code      player44uk           +44 = United Kingdom

Cross-reference extracted codes with postal databases, phone registries,
or geographic gazetteers to narrow location.
```

### Multi-Platform OSINT Chain
Common flow: Reddit username -> Spotify social link -> Base58-encoded string -> Spotify playlist descriptions (base64) -> first-letter acrostic from song titles. Always check bio-link services (linktr.ee, bio.link, about.me) for cross-platform references.

### Platform False Positive Detection
- Telegram: always returns 200; differentiate by "View" vs "Contact" in page title.
- TikTok: returns 200 with "Couldn't find this account" in body.
- Smule: returns 200 with "Not Found" in page content.
- linkin.bio: redirects to Later.com product page for unclaimed names.
- Instagram: always returns 200 (login wall); existence is ambiguous.

## Bypass
- If Twitter API is rate-limited, use Nitter instances or the syndication API (no auth).
- If a username is deleted, still try Wayback Machine -- archived pages contain JSON-LD with permanent user ID.
- If direct profile access is blocked, check t.co links in archived tweets from other users who replied.
- For Discord enumeration without a user token, check public invite links and guild widget endpoints.
- If EXIF is stripped (Twitter strips it), check visual features and image background clues instead.

## Verification
- Wayback CDX returns archived URLs with 200 status codes for the target account.
- BlueSky API returns posts containing expected keywords or flag format.
- Discord API response shows custom role names containing flag characters.
- Username returns "exists" on WhatsMyName across 3+ relevant platforms.
- Homoglyph decoding produces a valid text string (flag).

## Pitfalls
- Twitter strips EXIF on upload -- do not waste time on image stego for Twitter-served images.
- Tumblr preserves more metadata in avatars than in post images.
- Telegram always returns HTTP 200 -- never trust it as a profile existence check.
- Multiple Nitter instances may be blocked; rotate if one fails.
- Discord user tokens expire; they require periodic renewal.
- BlueSky search is not always comprehensive; check all replies to official posts, not just top-level.
- What3Words adjacent squares have completely different addresses (no spatial correlation).

# lc-mcp-server
leetcode mcp server written in golang.


# LeetCode Cookie Authentication 

This utility provides a robust way to extract your LeetCode authentication cookies (`LEETCODE_SESSION` and `csrftoken`) for use with scripts, bots, or custom clients. It launches a browser, helps you log in manually, and outputs environment variables you can export and use.

## Features

- **Cloudflare-aware:** Handles Cloudflare challenges and waits for human verification.
- **Anti-bot evasion:** Configures the browser to look less like a bot.
- **Manual login:** You log in using the real browser, ensuring security and compatibility.
- **Environment variable export:** Outputs `export LEETCODE_SESSION="..."` and `export CSRF_TOKEN="..."`.
- **Credential caching:** Saves credentials for reuse until they expire.
- **Debug output:** Shows extracted cookies for troubleshooting.

## Usage

1. **Install dependencies:**

   ```
   go get -u github.com/chromedp/chromedp
   ```

2. **Run the authentication script:**

   ```
   go run auth.go
   ```

   > This will launch a Chrome window. Complete any Cloudflare or LeetCode login steps manually.  
   > When you reach the main LeetCode page, **press Enter in the terminal**.

3. **Export environment variables:**

   You can either pipe and automatically export with:

   ```
   eval $(go run auth.go)
   ```

   Or save to a file and source it:

   ```
   go run auth.go > .leetcode.env
   source .leetcode.env
   ```

4. **Use in your client/server:**

   Your environment will now contain:

   - `LEETCODE_SESSION`
   - `CSRF_TOKEN`

   Example in Go:

   ```go
   session := os.Getenv("LEETCODE_SESSION")
   csrf := os.Getenv("CSRF_TOKEN")
   ```

## Troubleshooting

- **Cloudflare not passing:** Try waiting longer or ensure you interact with the page (mouse, scroll).
- **Missing cookies:** Make sure you have logged in and reached a non-login page.
- **2FA or Captcha:** Complete all verification steps before pressing Enter.
- **Windows users:** Ensure `chromedp` can launch Chrome (you may need to install Chrome).

## Security

Your session and csrf tokens **are sensitive**. Do not share or commit them.  
Session cookies expire and may require re-authentication.

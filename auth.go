package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

type LeetCodeAuth struct {
	Session   string    `json:"leetcode_session"`
	CSRFToken string    `json:"csrf_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func main() {
	// Randomize timing to appear more human-like
	rand.Seed(time.Now().UnixNano())

	// Enhanced anti-bot browser configuration
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		// Disable headless mode
		chromedp.Flag("headless", false),

		// Disable automation indicators
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("exclude-switches", "enable-automation"),
		chromedp.Flag("disable-extensions-except", ""),
		chromedp.Flag("disable-plugins-discovery", false),
		chromedp.Flag("disable-default-apps", false),

		// GPU and rendering
		chromedp.Flag("disable-gpu", false),
		chromedp.Flag("enable-webgl", true),
		chromedp.Flag("use-gl", "desktop"),

		// Network and security
		chromedp.Flag("disable-web-security", false),
		chromedp.Flag("allow-running-insecure-content", false),
		chromedp.Flag("disable-features", "VizDisplayCompositor"),

		// Language and locale
		chromedp.Flag("lang", "en-US,en"),
		chromedp.Flag("accept-lang", "en-US,en;q=0.9"),

		// Window size (common desktop resolution)
		chromedp.WindowSize(1920, 1080),

		// Realistic user agent
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Extended timeout for Cloudflare challenges
	ctx, cancel = context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()

	// Check for cached auth first
	authFilePath := filepath.Join(os.Getenv("HOME"), ".leetcode_auth.json")
	if auth, err := loadAuthFromFile(authFilePath); err == nil && time.Now().Before(auth.ExpiresAt) {
		fmt.Fprintf(os.Stderr, "Using cached credentials (valid until %s)\n", auth.ExpiresAt.Format(time.RFC3339))
		fmt.Printf("export LEETCODE_SESSION=\"%s\"\n", auth.Session)
		fmt.Printf("export CSRF_TOKEN=\"%s\"\n", auth.CSRFToken)
		return
	}

	fmt.Fprintln(os.Stderr, "Launching browser for LeetCode authentication...")

	// Enhanced anti-detection steps
	err := chromedp.Run(ctx,
		// Initial navigation with human-like behavior
		chromedp.ActionFunc(func(ctx context.Context) error {
			// Inject scripts to hide automation
			return chromedp.Evaluate(`
				// Remove webdriver property
				Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
				
				// Override chrome property
				window.chrome = {
					runtime: {}
				};
				
				// Override permissions
				Object.defineProperty(navigator, 'permissions', {
					get: () => ({
						query: () => Promise.resolve({state: 'granted'})
					})
				});
				
				// Override plugins
				Object.defineProperty(navigator, 'plugins', {
					get: () => [1, 2, 3, 4, 5]
				});
				
				// Override languages
				Object.defineProperty(navigator, 'languages', {
					get: () => ['en-US', 'en']
				});
			`, nil).Do(ctx)
		}),

		// Navigate to main page first
		chromedp.Navigate("https://leetcode.com"),
	)
	if err != nil {
		log.Fatalf("Failed to navigate to LeetCode: %v", err)
	}

	// Human-like wait with random timing
	humanWait(3, 7)

	// Check for and handle Cloudflare challenge
	err = chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			// Check if Cloudflare challenge is present
			var cfPresent bool
			if err := chromedp.Evaluate(`
				document.title.includes('Just a moment') || 
				document.title.includes('Checking your browser') ||
				document.body.textContent.includes('Cloudflare') ||
				document.querySelector('.cf-browser-verification') !== null
			`, &cfPresent).Do(ctx); err != nil {
				return err
			}

			if cfPresent {
				fmt.Fprintln(os.Stderr, "Cloudflare challenge detected. Please wait...")

				// Wait for challenge to complete with periodic checks
				for i := 0; i < 60; i++ { // Wait up to 60 seconds
					time.Sleep(1 * time.Second)

					var completed bool
					if err := chromedp.Evaluate(`
						!document.title.includes('Just a moment') && 
						!document.title.includes('Checking your browser') &&
						!document.body.textContent.includes('Ray ID')
					`, &completed).Do(ctx); err == nil && completed {
						fmt.Fprintln(os.Stderr, "Cloudflare challenge completed")
						break
					}

					if i == 59 {
						fmt.Fprintln(os.Stderr, "Warning: Cloudflare challenge timeout")
					}
				}
			}
			return nil
		}),
	)

	// Additional human-like behavior
	humanWait(2, 4)

	// Navigate to login page
	err = chromedp.Run(ctx,
		chromedp.Navigate("https://leetcode.com/accounts/login/"),
		chromedp.WaitVisible(`body`, chromedp.ByQuery),
	)
	if err != nil {
		log.Fatalf("Failed to navigate to login page: %v", err)
	}

	humanWait(1, 3)

	// Simulate human behavior on login page
	err = chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			// Simulate mouse movement and clicks
			return chromedp.Evaluate(`
				// Simulate mouse movement
				const event = new MouseEvent('mousemove', {
					clientX: Math.random() * window.innerWidth,
					clientY: Math.random() * window.innerHeight
				});
				document.dispatchEvent(event);
				
				// Add some random scrolling
				window.scrollTo(0, Math.random() * 100);
			`, nil).Do(ctx)
		}),
	)

	fmt.Fprintln(os.Stderr, "Please log in to LeetCode manually in the browser window...")
	fmt.Fprintln(os.Stderr, "Complete any verification steps (2FA, captcha, etc.)")
	fmt.Fprintln(os.Stderr, "Wait for the page to fully load and show the main LeetCode interface")
	fmt.Fprintln(os.Stderr, "Press Enter when login is complete...")
	fmt.Scanln()

	// Verify login by navigating to an authenticated page
	fmt.Fprintln(os.Stderr, "Verifying authentication...")
	err = chromedp.Run(ctx,
		chromedp.Navigate("https://leetcode.com/problemset/all/"),
		chromedp.WaitVisible(`body`, chromedp.ByQuery),
	)
	if err != nil {
		log.Fatalf("Failed to verify login: %v", err)
	}

	humanWait(2, 4)

	// Extract cookies with enhanced method
	var cookiesJSON string
	err = chromedp.Run(ctx,
		chromedp.Evaluate(`
			(function() {
				const cookies = {};
				const cookieArray = document.cookie.split(';');
				
				cookieArray.forEach(cookie => {
					const trimmed = cookie.trim();
					if (trimmed) {
						const [name, ...valueParts] = trimmed.split('=');
						const value = valueParts.join('='); // Handle values with = in them
						if (name && value) {
							cookies[name.trim()] = decodeURIComponent(value.trim());
						}
					}
				});
				
				// Log cookie names for debugging
				console.log('Found cookies:', Object.keys(cookies));
				
				return JSON.stringify(cookies, null, 2);
			})()
		`, &cookiesJSON),
	)

	if err != nil {
		log.Fatalf("Failed to extract cookies: %v", err)
	}

	fmt.Fprintf(os.Stderr, "Extracted cookies:\n%s\n", cookiesJSON)

	var cookiesMap map[string]string
	if err := json.Unmarshal([]byte(cookiesJSON), &cookiesMap); err != nil {
		log.Fatalf("Failed to parse cookies JSON: %v", err)
	}

	// Extract required cookies
	session := cookiesMap["LEETCODE_SESSION"]
	csrf := cookiesMap["csrftoken"]

	if session == "" || csrf == "" {
		fmt.Fprintf(os.Stderr, "Available cookie names: %v\n", getKeys(cookiesMap))

		// Try alternative cookie names
		if session == "" {
			for key, value := range cookiesMap {
				if strings.Contains(strings.ToLower(key), "session") {
					fmt.Fprintf(os.Stderr, "Found alternative session cookie: %s\n", key)
					session = value
					break
				}
			}
		}

		if csrf == "" {
			for key, value := range cookiesMap {
				if strings.Contains(strings.ToLower(key), "csrf") {
					fmt.Fprintf(os.Stderr, "Found alternative CSRF cookie: %s\n", key)
					csrf = value
					break
				}
			}
		}

		if session == "" || csrf == "" {
			log.Fatal("Failed to find LEETCODE_SESSION or csrftoken cookies. Ensure you're fully logged in.")
		}
	}

	// Clean up cookie values
	session = strings.Trim(session, `"' `)
	csrf = strings.Trim(csrf, `"' `)

	// Save authentication
	auth := LeetCodeAuth{
		Session:   session,
		CSRFToken: csrf,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}

	if err := saveAuthToFile(authFilePath, auth); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to save auth: %v\n", err)
	}

	fmt.Fprintf(os.Stderr, "Authentication successful! (valid until %s)\n", auth.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("export LEETCODE_SESSION=\"%s\"\n", session)
	fmt.Printf("export CSRF_TOKEN=\"%s\"\n", csrf)
}

func humanWait(minSec, maxSec int) {
	duration := time.Duration(rand.Intn(maxSec-minSec+1)+minSec) * time.Second
	time.Sleep(duration)
}

func getKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func loadAuthFromFile(path string) (LeetCodeAuth, error) {
	var auth LeetCodeAuth
	data, err := os.ReadFile(path)
	if err != nil {
		return auth, err
	}
	err = json.Unmarshal(data, &auth)
	return auth, err
}

func saveAuthToFile(path string, auth LeetCodeAuth) error {
	data, err := json.MarshalIndent(auth, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

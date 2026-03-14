package active

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
)

// TakeoverFingerprint defines a service and its CNAME indicators
type TakeoverFingerprint struct {
	Service     string
	CNames     []string
	Fingerprint string // string in HTTP response body if accessible
}

// TakeoverResult holds the result of a subdomain takeover check
type TakeoverResult struct {
	Subdomain string `json:"subdomain"`
	CNAME     string `json:"cname"`
	Service   string `json:"service"`
	Vulnerable bool  `json:"vulnerable"`
}

var takeoverFingerprints = []TakeoverFingerprint{
	{Service: "GitHub Pages", CNames: []string{"github.io"}, Fingerprint: "There isn't a GitHub Pages site here"},
	{Service: "Heroku", CNames: []string{"herokudns.com", "herokussl.com", "herokuapp.com"}, Fingerprint: "No such app"},
	{Service: "AWS S3", CNames: []string{"s3.amazonaws.com", "s3-website"}, Fingerprint: "NoSuchBucket"},
	{Service: "Azure", CNames: []string{"azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "blob.core.windows.net", "azure-api.net", "azurehdinsight.net", "azureedge.net", "azurecontainer.io", "database.windows.net", "azuredatalakestore.net"}, Fingerprint: ""},
	{Service: "Shopify", CNames: []string{"myshopify.com"}, Fingerprint: "Sorry, this shop is currently unavailable"},
	{Service: "Fastly", CNames: []string{"fastly.net"}, Fingerprint: "Fastly error: unknown domain"},
	{Service: "Pantheon", CNames: []string{"pantheonsite.io"}, Fingerprint: "404 error unknown site"},
	{Service: "Tumblr", CNames: []string{"domains.tumblr.com"}, Fingerprint: "Whatever you were looking for doesn't currently exist"},
	{Service: "Wordpress", CNames: []string{"wordpress.com"}, Fingerprint: "Do you want to register"},
	{Service: "TeamWork", CNames: []string{"teamwork.com"}, Fingerprint: "Oops - We didn't find your site"},
	{Service: "Helpjuice", CNames: []string{"helpjuice.com"}, Fingerprint: "We could not find what you're looking for"},
	{Service: "HelpScout", CNames: []string{"helpscoutdocs.com"}, Fingerprint: "No settings were found for this company"},
	{Service: "Cargo", CNames: []string{"cargocollective.com"}, Fingerprint: "404 Not Found"},
	{Service: "Statuspage", CNames: []string{"statuspage.io"}, Fingerprint: "You are being redirected"},
	{Service: "UserVoice", CNames: []string{"uservoice.com"}, Fingerprint: "This UserVoice subdomain is currently available"},
	{Service: "Surge.sh", CNames: []string{"surge.sh"}, Fingerprint: "project not found"},
	{Service: "Intercom", CNames: []string{"custom.intercom.help"}, Fingerprint: "This page is reserved for artistic dogs"},
	{Service: "Webflow", CNames: []string{"proxy.webflow.com", "proxy-ssl.webflow.com"}, Fingerprint: "The page you are looking for doesn't exist or has been moved"},
	{Service: "Kajabi", CNames: []string{"endpoints.kajabi.com"}, Fingerprint: ""},
	{Service: "Thinkific", CNames: []string{"thinkific.com"}, Fingerprint: "You may have mistyped the address"},
	{Service: "Tave", CNames: []string{"clientaccess.tave.com"}, Fingerprint: ""},
	{Service: "Wishpond", CNames: []string{"wishpond.com"}, Fingerprint: ""},
	{Service: "Aftership", CNames: []string{"aftership.com"}, Fingerprint: "Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist"},
	{Service: "Aha", CNames: []string{"ideas.aha.io"}, Fingerprint: "There is no portal here"},
	{Service: "Brightcove", CNames: []string{"bcvp0rtal.com", "brightcovegallery.com", "gallery.video"}, Fingerprint: ""},
	{Service: "Bigcartel", CNames: []string{"bigcartel.com"}, Fingerprint: ""},
	{Service: "ActiveCampaign", CNames: []string{"activehosted.com"}, Fingerprint: "alt=\"DEVELOPER_DEFAULT\""},
	{Service: "Campaign Monitor", CNames: []string{"createsend.com"}, Fingerprint: "Trying to access your account?"},
	{Service: "Acquia", CNames: []string{"acquia-test.co"}, Fingerprint: "The site you are looking for could not be found"},
	{Service: "Proposify", CNames: []string{"proposify.biz"}, Fingerprint: "If you need immediate assistance, please contact Proposify Support"},
	{Service: "Simplebooklet", CNames: []string{"simplebooklet.com"}, Fingerprint: "We can't find this <a"},
	{Service: "GetResponse", CNames: []string{".gr8.com"}, Fingerprint: "With GetResponse Landing Pages, lead generation has never been easier"},
	{Service: "Vend", CNames: []string{"vendecommerce.com"}, Fingerprint: "Looks like you've traveled too far into cyberspace"},
	{Service: "Netlify", CNames: []string{"netlify.app", "netlify.com"}, Fingerprint: "Not Found - Request ID:"},
	{Service: "Fly.io", CNames: []string{"fly.dev"}, Fingerprint: ""},
	{Service: "Vercel", CNames: []string{"vercel.app", "now.sh"}, Fingerprint: ""},
	{Service: "Render", CNames: []string{"onrender.com"}, Fingerprint: ""},
}

// CheckTakeover checks subdomains for potential subdomain takeover vulnerabilities
func CheckTakeover(ctx context.Context, subdomains []string, threads int) <-chan TakeoverResult {
	results := make(chan TakeoverResult)
	jobs := make(chan string, len(subdomains))

	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range jobs {
				result := checkSubdomain(ctx, sub)
				if result != nil {
					results <- *result
				}
			}
		}()
	}

	go func() {
		for _, sub := range subdomains {
			jobs <- sub
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

func checkSubdomain(ctx context.Context, subdomain string) *TakeoverResult {
	// Look up CNAME
	cname, err := net.DefaultResolver.LookupCNAME(ctx, subdomain)
	if err != nil || cname == "" || cname == subdomain+"." {
		return nil
	}

	cname = strings.TrimSuffix(cname, ".")
	cnameLower := strings.ToLower(cname)

	for _, fp := range takeoverFingerprints {
		for _, cn := range fp.CNames {
			if strings.Contains(cnameLower, cn) {
				// Check if CNAME target resolves (dangling = doesn't resolve)
				_, err := net.DefaultResolver.LookupHost(ctx, cname)
				isDangling := err != nil

				return &TakeoverResult{
					Subdomain:  subdomain,
					CNAME:      cname,
					Service:    fp.Service,
					Vulnerable: isDangling,
				}
			}
		}
	}

	return nil
}

func FormatTakeoverResult(r TakeoverResult) string {
	status := "POTENTIALLY VULNERABLE"
	if !r.Vulnerable {
		status = "CNAME EXISTS (verify manually)"
	}
	return fmt.Sprintf("[TAKEOVER] %s → %s (%s) [%s]", r.Subdomain, r.CNAME, r.Service, status)
}

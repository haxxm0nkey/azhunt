package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

const banner = `           
           _                 _   
  __ _ ___| |__  _   _ _ __ | |_ 
 / _' |_  / '_ \| | | | '_ \| __|
| (_| |/ /| | | | |_| | | | | |_ 
 \__,_/___|_| |_|\__,_|_| |_|\__|

            v.0.0.1
      by haxxm0nkey (haxx.it)
`

const usage = `
azhunt is a tool for enumerating Azure AD (Entra ID) domains and tenant information.

Usage:
  azhunt [flags]

INPUT:
   -d                  domain to find information about
   -l file             file containing list of domains

MODE:
   -domains            find related domains only
   -tenant             find tenant information only

OUTPUT:
   -silent             display only domain results in the output
   -j                  display output in JSON format
   -o file             file to write output

EXAMPLES:
   azhunt -d example.com
   azhunt -l /tmp/domains.txt -j
   echo "example.com" | azhunt -silent
`

// CombinedTenantInfo represents the structure for combined domain and tenant information output in JSON.
type CombinedTenantInfo struct {
	RootDomain        string   `json:"root_domain"`
	RelatedDomains    []string `json:"related_domains"`
	FederationBrand   string   `json:"tenant_brand_name"`
	TenantID          string   `json:"tenant_id"`
	TenantRegionScope string   `json:"tenant_region"`
	NameSpaceType     string   `json:"namespace_type"`
	AuthURL           string   `json:"auth_url"`
}

// DomainInfo represents the structure for domain information output in JSON.
type DomainInfo struct {
	RootDomain     string   `json:"root_domain"`
	RelatedDomains []string `json:"related_domains"`
}

// TenantInfo represents the structure for tenant information output in JSON.
type TenantInfo struct {
	RootDomain        string `json:"root_domain"`
	FederationBrand   string `json:"tenant_brand_name"`
	TenantID          string `json:"tenant_id"`
	TenantRegionScope string `json:"tenant_region"`
	NameSpaceType     string `json:"namespace_type"`
	AuthURL           string `json:"auth_url"`
}

type OpenIDConfig struct {
	TenantRegionScope string `json:"tenant_region_scope"`
	Issuer            string `json:"issuer"`
}

type UserRealmInfo struct {
	NameSpaceType       string `json:"NameSpaceType"`
	FederationBrandName string `json:"FederationBrandName"`
	AuthURL             string `json:"AuthURL"`
}

// FederationResponse represents the structure of the response from the Autodiscover service.
type FederationResponse struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		XMLName                                 xml.Name `xml:"Body"`
		GetFederationInformationResponseMessage struct {
			XMLName  xml.Name `xml:"GetFederationInformationResponseMessage"`
			Response struct {
				XMLName        xml.Name `xml:"Response"`
				ErrorCode      string   `xml:"ErrorCode"`
				ErrorMessage   string   `xml:"ErrorMessage"`
				ApplicationUri string   `xml:"ApplicationUri"`
				Domains        struct {
					XMLName xml.Name `xml:"Domains"`
					Domain  []string `xml:"Domain"`
				} `xml:"Domains"`
				TokenIssuers struct {
					XMLName     xml.Name `xml:"TokenIssuers"`
					TokenIssuer struct {
						Endpoint string `xml:"Endpoint"`
						Uri      string `xml:"Uri"`
					} `xml:"TokenIssuer"`
				} `xml:"TokenIssuers"`
			} `xml:"Response"`
		} `xml:"GetFederationInformationResponseMessage"`
	} `xml:"Body"`
}

// printBanner displays the banner when no input is provided
func printBanner() {
	fmt.Print(banner)
	fmt.Println("\nProgram exiting: no input provided.")
}

// customUseage displays custom help message
func customUsage() {
	fmt.Printf(banner)
	fmt.Println()
	fmt.Print(usage)
	fmt.Println()
}

// readDomainsFromStdin reads domain names from standard input.
func readDomainsFromStdin() ([]string, error) {
	var domains []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			domains = append(domains, domain)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}

// readDomainsFromFile reads domain names from a file.
func readDomainsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			domains = append(domains, domain)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}

// fetchTenantDomains makes a request to the Autodiscover service and returns the list of domains.
func fetchTenantDomains(domain string) ([]string, error) {
	body := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:a="http://www.w3.org/2005/08/addressing">
	<soap:Header>
		<a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
		<a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
		<a:ReplyTo>
			<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
		</a:ReplyTo>
	</soap:Header>
	<soap:Body>
		<GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
			<Request>
				<Domain>%s</Domain>
			</Request>
		</GetFederationInformationRequestMessage>
	</soap:Body>
</soap:Envelope>`, domain)

	headers := map[string]string{
		"Content-Type": "text/xml; charset=utf-8",
		"SOAPAction":   `"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"`,
		"User-Agent":   "AutodiscoverClient",
	}

	req, err := http.NewRequest("POST", "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc", bytes.NewBufferString(body))
	if err != nil {
		return nil, err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status %d", resp.StatusCode)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var response FederationResponse
	err = xml.Unmarshal(respBody, &response)
	if err != nil {
		return nil, err
	}

	return response.Body.GetFederationInformationResponseMessage.Response.Domains.Domain, nil
}

func fetchOpenIDConfig(domain string) (OpenIDConfig, string, error) {
	// Construct the OpenID configuration URL
	openIDURL := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration", domain)

	// Perform the HTTP request to fetch the OpenID configuration
	resp, err := http.Get(openIDURL)
	if err != nil {
		return OpenIDConfig{}, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return OpenIDConfig{}, "", fmt.Errorf("failed to fetch OpenID configuration, status: %d", resp.StatusCode)
	}

	// Parse the response body
	var config OpenIDConfig
	err = json.NewDecoder(resp.Body).Decode(&config)
	if err != nil {
		return OpenIDConfig{}, "", err
	}

	// Extract the tenant ID from the issuer field in the JSON response
	issuerParts := strings.Split(config.Issuer, "/")
	tenantID := issuerParts[3] // Tenant ID (UUID)

	return config, tenantID, nil
}

// fetchUserRealmInfo calls the getuserrealm.srf API to fetch NameSpaceType, FederationBrandName, and AuthURL
func fetchUserRealmInfo(domain string) (UserRealmInfo, error) {
	apiURL := fmt.Sprintf("https://login.microsoftonline.com/getuserrealm.srf?login=%s&json=1", domain)
	resp, err := http.Get(apiURL)
	if err != nil {
		return UserRealmInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return UserRealmInfo{}, fmt.Errorf("request to getuserrealm.srf failed with status %d", resp.StatusCode)
	}

	// Parse the response
	var realmInfo UserRealmInfo
	err = json.NewDecoder(resp.Body).Decode(&realmInfo)
	if err != nil {
		return UserRealmInfo{}, err
	}

	// Set AuthURL to "N/A" if it is empty
	if realmInfo.AuthURL == "" {
		realmInfo.AuthURL = "N/A"
	}

	return realmInfo, nil
}

// fetchAndPrintDomainInfo fetches related domains and prints them
func fetchAndPrintDomainInfo(domain string, silent bool, outputFile string, jsonOutput bool) error {
	relatedDomains, err := fetchTenantDomains(domain)
	if err != nil {
		return fmt.Errorf("error fetching tenant domains for %s: %v", domain, err)
	}

	// Prepare output data
	outputData := DomainInfo{
		RootDomain:     domain,
		RelatedDomains: relatedDomains,
	}

	if silent {
		if outputFile != "" {
			// Write each related domain to file in append mode
			for _, relDomain := range relatedDomains {
				// Append domain to file
				if err := writeToFile(outputFile, []byte(relDomain)); err != nil {
					return fmt.Errorf("error writing related domains to file in silent mode: %v", err)
				}
			}
		} else {
			// Print each related domain in silent mode
			for _, relDomain := range relatedDomains {
				fmt.Println(relDomain)
			}
		}
		return nil
	}

	if jsonOutput {
		// Serialize output data to JSON
		jsonData, err := json.Marshal(outputData)
		if err != nil {
			return fmt.Errorf("error marshaling output to JSON: %v", err)
		}

		if outputFile != "" {
			// Write to file
			err := writeToFile(outputFile, jsonData)
			if err != nil {
				return fmt.Errorf("error writing to file: %v", err)
			}
		} else {
			// Print JSON to console
			fmt.Println(string(jsonData))
		}

	} else {
		if !silent {
			fmt.Printf("[*] Domains related to %s:\n", domain)
			// Print each related domain
			for _, relDomain := range relatedDomains {
				fmt.Println(relDomain)
			}
		}

		// Handle output to file if required
		if outputFile != "" {
			for _, relDomain := range relatedDomains {
				if err := writeToFile(outputFile, []byte(relDomain)); err != nil {
					return fmt.Errorf("error writing to file: %v", err)
				}
			}
		}

	}
	return nil
}

// fetchAndPrintTenantInfo fetches tenant information and prints it
func fetchAndPrintTenantInfo(domain string, outputFile string, jsonOutput bool) error {
	// Fetch OpenID config
	openIDConfig, tenantID, err := fetchOpenIDConfig(domain)
	if err != nil {
		return fmt.Errorf("error fetching OpenID configuration for %s: %v", domain, err)
	}

	// Fetch User Realm info
	realmInfo, err := fetchUserRealmInfo(domain)
	if err != nil {
		return fmt.Errorf("error fetching user realm info for %s: %v", domain, err)
	}

	// Prepare output data
	tenantInfo := TenantInfo{
		RootDomain:        domain,
		FederationBrand:   realmInfo.FederationBrandName,
		TenantID:          tenantID,
		TenantRegionScope: openIDConfig.TenantRegionScope,
		NameSpaceType:     realmInfo.NameSpaceType,
		AuthURL:           realmInfo.AuthURL,
	}

	// Handle JSON output
	if jsonOutput {
		// Convert the data to JSON
		jsonData, err := json.Marshal(tenantInfo)
		if err != nil {
			return fmt.Errorf("error marshaling tenant info to JSON: %v", err)
		}

		if outputFile != "" {
			// Write JSON data to the output file
			err := writeToFile(outputFile, jsonData)
			if err != nil {
				return fmt.Errorf("error writing to file: %v", err)
			}
		} else {
			// Print JSON to console
			fmt.Println(string(jsonData))
		}

	} else {
		// Print tenant information
		fmt.Printf("[*] Tenant information for domain %s:\n", tenantInfo.RootDomain)
		fmt.Printf("Tenant Brand Name: %s\n", tenantInfo.FederationBrand)
		fmt.Printf("Tenant ID: %s\n", tenantInfo.TenantID)
		fmt.Printf("Tenant Region: %s\n", tenantInfo.TenantRegionScope)
		fmt.Printf("Namespace Type: %s\n", tenantInfo.NameSpaceType)
		fmt.Printf("Auth URL (SSO): %s\n", tenantInfo.AuthURL)
		fmt.Println()

		// Write tenant information to the output file if required
		if outputFile != "" {
			tenantData := fmt.Sprintf("Tenant Brand Name: %s\nTenant ID: %s\nTenant Region: %s\nNamespace Type: %s\nAuth URL (SSO): %s\n",
				tenantInfo.FederationBrand, tenantInfo.TenantID, tenantInfo.TenantRegionScope, tenantInfo.NameSpaceType, tenantInfo.AuthURL)

			if err := writeToFile(outputFile, []byte(tenantData)); err != nil {
				return fmt.Errorf("error writing to file: %v", err)
			}
		}

	}

	return nil

}

func fetchAndPrintCombinedInfo(domain string, outputFile string, jsonOutput bool) error {

	// Fetch domains
	relatedDomains, err := fetchTenantDomains(domain)
	if err != nil {
		return fmt.Errorf("error fetching tenant domains for %s: %v", domain, err)
	}

	// Fetch OpenID config
	openIDConfig, tenantID, err := fetchOpenIDConfig(domain)
	if err != nil {
		return fmt.Errorf("error fetching OpenID configuration for %s: %v", domain, err)
	}

	// Fetch User Realm info
	realmInfo, err := fetchUserRealmInfo(domain)
	if err != nil {
		return fmt.Errorf("error fetching user realm info for %s: %v", domain, err)
	}

	// Prepare output data
	combinedTenantInfo := CombinedTenantInfo{
		RootDomain:        domain,
		TenantID:          tenantID,
		TenantRegionScope: openIDConfig.TenantRegionScope,
		NameSpaceType:     realmInfo.NameSpaceType,
		FederationBrand:   realmInfo.FederationBrandName,
		AuthURL:           realmInfo.AuthURL,
		RelatedDomains:    relatedDomains,
	}

	// Handle JSON output
	if jsonOutput {
		// Convert the data to JSON
		jsonData, err := json.Marshal(combinedTenantInfo)
		if err != nil {
			return fmt.Errorf("error marshaling tenant info to JSON: %v", err)
		}

		if outputFile != "" {
			// Write JSON data to the output file
			err := writeToFile(outputFile, jsonData)
			if err != nil {
				return fmt.Errorf("error writing to file: %v", err)
			}
		} else {
			// Print JSON to console
			fmt.Println(string(jsonData))
		}

	} else {
		// Print combined tenant information
		fmt.Printf("[*] Tenant information for domain %s:\n", combinedTenantInfo.RootDomain)
		fmt.Printf("Tenant Brand Name: %s\n", combinedTenantInfo.FederationBrand)
		fmt.Printf("Tenant ID: %s\n", combinedTenantInfo.TenantID)
		fmt.Printf("Tenant Region: %s\n", combinedTenantInfo.TenantRegionScope)
		fmt.Printf("Namespace Type: %s\n", combinedTenantInfo.NameSpaceType)
		fmt.Printf("Auth URL (SSO): %s\n", combinedTenantInfo.AuthURL)
		fmt.Println()

		fmt.Printf("[*] Domains related to %s:\n", combinedTenantInfo.RootDomain)
		for _, relDomain := range combinedTenantInfo.RelatedDomains {
			fmt.Println(relDomain)
		}

		// Write combined information to the output file if required
		if outputFile != "" {
			combinedData := fmt.Sprintf("Tenant Brand Name: %s\nTenant ID: %s\nTenant Region: %s\nNamespace Type: %s\nAuth URL (SSO): %s\n",
				combinedTenantInfo.FederationBrand, combinedTenantInfo.TenantID, combinedTenantInfo.TenantRegionScope, combinedTenantInfo.NameSpaceType, combinedTenantInfo.AuthURL)

			// Append related domains to the file
			for _, relDomain := range combinedTenantInfo.RelatedDomains {
				combinedData += fmt.Sprintf(relDomain + "\n")
			}

			if err := writeToFile(outputFile, []byte(combinedData)); err != nil {
				return fmt.Errorf("error writing to file: %v", err)
			}
		}

	}

	return nil

}

// writeToFile writes the provided data to the specified file safely in append mode.
func writeToFile(outputFile string, data []byte) error {
	// Open file in append mode, create if it doesn't exist
	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write the data with a newline at the end
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}

	return nil
}

// handleCheck performs the checks based on the provided flags
func handleCheck(domain string, domainsOnly bool, tenantOnly bool, silent bool, outputFile string, jsonOutput bool) {
	if silent {
		// Always suppress output in silent mode
		_ = fetchAndPrintDomainInfo(domain, silent, outputFile, jsonOutput)
		return
	}

	if domainsOnly {
		// Handle domain-only check
		err := fetchAndPrintDomainInfo(domain, silent, outputFile, jsonOutput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		}
		return
	}

	if tenantOnly {
		// Handle tenant-only check
		err := fetchAndPrintTenantInfo(domain, outputFile, jsonOutput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		}
		return
	}

	// Default behavior: Perform both domain and tenant checks
	err := fetchAndPrintCombinedInfo(domain, outputFile, jsonOutput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return
	}

}

func main() {
	// Override the default usage function with the custom one
	flag.Usage = customUsage

	// Define flags
	var domain string
	var domainsList string
	var outputFile string
	var jsonOutput bool
	var silent bool
	var domainsOnly bool
	var tenantOnly bool

	// Parse flags
	flag.StringVar(&domain, "d", "", "Domain to find information about")
	flag.StringVar(&domainsList, "l", "", "File containing list of domains")
	flag.StringVar(&outputFile, "o", "", "File to write output")
	flag.BoolVar(&jsonOutput, "j", false, "Display output in JSON format")
	flag.BoolVar(&silent, "silent", false, "Display only domain results in the output")
	flag.BoolVar(&domainsOnly, "domains", false, "Find related domains only")
	flag.BoolVar(&tenantOnly, "tenant", false, "Find tenant information only")

	flag.Parse()

	// Check for input via stdin
	var stdinDomains []string
	stdinInfo, _ := os.Stdin.Stat()
	if stdinInfo.Mode()&os.ModeCharDevice == 0 {
		// Input is being piped via stdin (echo "example.com" | ...)
		stdinDomains, _ = readDomainsFromStdin()
	}

	// Handle stdin input with -domains or -tenant flags
	if len(stdinDomains) > 0 {
		for _, domain := range stdinDomains {
			handleCheck(domain, domainsOnly, tenantOnly, silent, outputFile, jsonOutput)
		}
		return
	}

	// Handle domain specified via -d
	if domain != "" {

		handleCheck(domain, domainsOnly, tenantOnly, silent, outputFile, jsonOutput)
		return
	}

	// Handle domains from a file specified via -l
	if domainsList != "" {
		domains, err := readDomainsFromFile(domainsList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading domains from file: %v\n", err)
			os.Exit(1)
		}

		for _, domain := range domains {
			handleCheck(domain, domainsOnly, tenantOnly, silent, outputFile, jsonOutput)
		}
		return
	}

	// No valid input or flags provided, show banner
	printBanner()
	os.Exit(1)
}

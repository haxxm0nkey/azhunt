# azhunt

Azure AD (Entra ID) enumeration tool. Find related domains and tenant information in a simple way.


## Features
- Unauthenticated recon against Azure tenants
- Discover related domains associated with given domain
- Retrieve Azure tenant information such as:
  - Tenant Name
  - Tenant ID
  - Tenant Region
  - Namespace Type (Federated / Managed / Unknown)
  - Authentication URL (SSO)
- Cross-platform (Golang static binary)
- Designed to be easily used in recon pipelines (STDIN/STDOUT support)
- Muliple output formats (domains-only, JSON, file)
- No external dependencies (built with pure Golang standard library)


## Install

If you have Go installed and configured (i.e. with $GOPATH/bin in your $PATH):
```bash
go install -v github.com/haxxm0nkey/azhunt@latest
```

OR clone this repository and build it:

```bash
git clone https://github.com/haxxm0nkey/azhunt.git
cd azhunt
go build
mv azhunt /usr/local/bin/
azhunt 
```

### Usage
```bash
./azhunt -h
```
The command above will display this help banner.

```yaml
           _                 _
  __ _ ___| |__  _   _ _ __ | |_
 / _' |_  / '_ \| | | | '_ \| __|
| (_| |/ /| | | | |_| | | | | |_
 \__,_/___|_| |_|\__,_|_| |_|\__|

            v.0.0.1
      by haxxm0nkey (haxx.it)

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
```
## Examples 
#### Default mode
In default mode (without -domains or -tenant flags) all recon information will be printed.
```bash
azhunt -d example.com

[*] Tenant information for domain example.com:
Tenant Brand Name: test_test_06102020MM
Tenant ID: c7c08208-4f4d-45f1-83cd-5e2f491ab786
Tenant Region: NA
Namespace Type: Federated
Auth URL (SSO): https://sts.microsoftonline.com/Trust/2005/UsernameMixed?username=example.com&wa=wsignin1.0&wtrealm=urn%3afederation%3aMicrosoftOnline&wctx=

[*] Domains related to example.com:
Example.com
testtest06102020MM.onmicrosoft.com
```


#### Silent mode (domains-only)
In silent mode domains-only information will be printed. Designed to be used in recon pipelines.
```bash
azhunt -d amazon.com -silent

amazoncan.onmicrosoft.com
amazonfra.onmicrosoft.com
groups.amazon.com
amazon.cl
amazon.fr
amazonindi.onmicrosoft.com
amazondeu.onmicrosoft.com
[...]
amazonnor.onmicrosoft.com
```

Recon pipeline example
```bash
azhunt -d example.com -silent | subfinder | httpx -sc
```

#### JSON output
Display recon data as a JSON

```bash
azhunt -d hackerone.com -j

{"root_domain":"hackerone.com","related_domains":["hackerone.com","hackerone.mail.onmicrosoft.com","hackerone.onmicrosoft.com"],"tenant_brand_name":"HackerOne Inc.","tenant_id":"5555ff90-251c-4730-bbbb-1c2181fbd63d","tenant_region":"NA","namespace_type":"Federated","auth_url":"https://hackerone.okta.com/app/office365/exkmrijq1uG4p0alo2p6/sso/wsfed/passive?username=hackerone.com\u0026wa=wsignin1.0\u0026wtrealm=urn%3afederation%3aMicrosoftOnline\u0026wctx="}
```


### Acknowledgements
Kudos and huge thanks for the inspiration to Dr Nestori Syynimaa (author of AADInternals).


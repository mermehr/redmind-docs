# Fingerprinting - Web Services

**Curl - Service Redirects:**

`curl -I https://inlanefreight.com`

**wafw00f - The Web Application Firewall Fingerprinting Toolkit:**

`pip3 install git+https://github.com/EnableSecurity/wafw00f`

`wafw00f inlanefreight.com`

**Nikto:**

`nikto -h inlanefreight.com -Tuning b`

>Nikto will then initiate a series of tests, attempting to identify outdated software, insecure files or configurations, and other potential security risks.

# Data dictionary

## Raw indicators

Thirty UCI indicators with values -1, 0 or 1, where -1 generally means phishing-like, 0 means suspicious and 1 means legitimate. Groups:

- **URL:** having_IP_Address, URL_Length, Shortining_Service, having_At_Symbol, double_slash_redirecting, Prefix_Suffix
- **Domain:** having_Sub_Domain, SSLfinal_State, Domain_registeration_length, Favicon, port, HTTPS_token
- **Content:** Request_URL, URL_of_Anchor, Links_in_tags, SFH, Submitting_to_email, Abnormal_URL
- **Trust:** Redirect, on_mouseover, RightClick, popUpWidnow, Iframe, age_of_domain, DNSRecord, web_traffic, Page_Rank, Google_Index, Links_pointing_to_page, Statistical_report

## Derived audit columns

| Column | Description |
| --- | --- |
| risk_band | 0-5, 6-10, 11-15, 16-20 or 21-30 phishing-like indicators |
| ssl_state | Valid, Suspicious or Phishing-like based on SSLfinal_State |

## Engineered features

| Column | Description |
| --- | --- |
| risk_count | Number of indicators equal to -1 |
| suspicious_count | Number equal to 0 |
| safe_count | Number equal to 1 |
| risk_ratio | `(risk_count + 0.5 * suspicious_count) / 30` |
| url_risk_count | Phishing-like indicators in the URL group |
| domain_risk_count | Phishing-like indicators in the domain group |
| content_risk_count | Phishing-like indicators in the content group |
| trust_risk_count | Phishing-like indicators in the trust group |

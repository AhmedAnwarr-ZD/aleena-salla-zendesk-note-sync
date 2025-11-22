Salla ↔ Zendesk: Private Note → Salla Order History Sync internal notes
from Zendesk tickets directly into Salla order history using OAuth.​
Whenever a private note contains a Salla order reference (such as
21xxxxxx), the script: 1.​ Detects the order number from the private note
2.​ Fetches the latest internal note from the Zendesk ticket 3.​ Resolves
the Salla order via the Admin API 4.​ Appends a formatted, timestamped
history entry to the order inside Salla This gives operations, customer
support, and finance a single, unified history of actions on any order.

Features ●​ ●​ ●​ ●​ ●​ ●​

Automatic sync of private notes from Zendesk to Salla OAuth-based
authentication with secure token refresh Automatic order detection from
private notes Appends structured history logs inside Salla Agent
attribution and date stamping Supports manual testing through built-in
tester functions​

Architecture Platform: Google Apps Script​ APIs used:​ • Zendesk Support
API​ • Salla Admin API (OAuth2) Flow:​ • Zendesk Trigger → Webhook → Apps
Script Web App​ • Script extracts ticket_id​ • Script fetches private note
and agent details​ • Script detects order reference​

• Script refreshes OAuth token​ • Script appends note to Salla order
history

Script Properties (Configuration) These keys must be added in Apps
Script → Project Settings: Mandatory ●​ ●​ ●​ ●​ ●​ ●​ ●​

ZD_SUBDOMAIN ZD_EMAIL ZD_API_TOKEN SHARED_KEY SALLA_CLIENT_ID
SALLA_CLIENT_SECRET SALLA_REFRESH_TOKEN​

Optional ●​ TZ (default: Asia/Riyadh) ●​ ORDER_REGEX (default: pattern for
21xxxxxx)​

The script automatically stores and refreshes the OAuth access token and
its expiry time.

Webhook Setup Deploy the script as a Web App: ●​ Execute as: Me ●​ Access:
Anyone with the link​

Append your SHARED_KEY to the webhook URL for security. Zendesk sends a
payload containing at least: ●​ ticket_id​

The script then retrieves the latest private note using the ticket ID.

Order Number Extraction The script detects Salla order numbers based on:
●​ Customizable regex for numbers starting with 21XXX ●​ Fallback
detection for any long numeric sequence starting with 21XXX​

Examples: ●​ 21012345 ●​ 21987654​

Salla API Integrations The script uses the following Salla Admin API
operations: ●​ OAuth token refresh ●​ Get order by reference ●​ Append
order history entry​

The history entry follows a structured format:

JavaScript #TICKET_ID \| Agent Name \| YYYY-MM-DD​ Followed by the
private note content.

Example Output (in Salla order history)

JavaScript #123456 \| Asim \| 2025-11-22 ‫تم تحديث تفاصيل الطلب بناءً على
مالحظة الوكيل‬

Testing and Validation Inside Apps Script: ●​ testSallaToken: Verifies
OAuth credentials​ ●​ syncNoteTester: Prompts for a ticket ID and manually
syncs its note​

Inside Zendesk: ●​ Add a private note containing a valid order reference
●​ Trigger fires ●​ History appears in the Salla order panel​

Security ●​ Uses SHARED_KEY to authenticate incoming webhook calls ●​ No
API tokens stored in code; all stored in Script Properties ●​ OAuth
tokens automatically refreshed and rotated​

Limitations ●​ Only supports Salla order numbers starting with 21 ●​ Only
supports one Salla store per deployment ●​ One history entry per
execution​

License Internal use for Aleena / TGC-KSA.​ Add an open-source license if
publishing externally.



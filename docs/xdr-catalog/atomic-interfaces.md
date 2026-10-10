# Atomic interfaces read from the org

Inputs, outputs and API calls of 80 Cisco-managed atomics, read from exports of copies made in the org on
2026-10-10. The public catalog does not publish these. Workflow IDs of the Cisco-managed atomics are in
[catalog.json](catalog.json); everything here is also there under `interface`.

**The variable IDs of a copy are not the IDs of the Cisco-managed atomic.** Copying an atomic gives the copy and
every variable a new ID. Names, types, defaults and request shapes are the same. `catalog.json` keeps the copy IDs
as `copy_workflow_id` and `copy_variable_id`.

No script body is copied here. Requests show literal text only; `{var}` stands for a value computed at run time.

## Cisco Meraki

### Cisco Meraki - Appliance - Get L3 Outbound Firewall Rules

Gets a list of L3 outbound firewall rules for a Cisco Meraki MX network.

- Kind: read. Cisco workflow ID: `definition_workflow_01PP78X6Z62P94QhzA05iog6dqFsGVo4XnR`.
- Target: Meraki integration target or HTTP Endpoint for "api.meraki.com" with a path of "/api"
- Account key: None if using an integration-provided target, API token if using an HTTP Endpoint target
- Request: `GET v1/networks/{var}/appliance/firewall/l3FirewallRules`, content type application/json, custom headers: {var}
- Reads from the response: `$.rules`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Network ID | string | yes |  | The ID of the network to manage firewall rules for (ex: L_472348923894789232) |
| API Key | secure_string |  |  | If you are using an integration-provided Meraki target, this is not required. If you are using your own HTTP Endpoint target, this should be an API token generated in your Meraki dashboard |

| Output | Type | Description |
|---|---|---|
| Rule List | string | The list of firewall rules for the given network |

### Cisco Meraki - Appliance - Update L3 Outbound Firewall Rule

Updates the L3 outbound firewall rules for a Cisco Meraki MX network.

- Kind: write. Cisco workflow ID: `definition_workflow_01PP74UJ76SS13pAJukA3R2XP7nxxnIHLZZ`.
- Target: Meraki integration target or HTTP Endpoint for "api.meraki.com" with a path of "/api"
- Account key: None if using an integration-provided target, API token if using an HTTP Endpoint target
- Request: `PUT v1/networks/{var}/appliance/firewall/l3FirewallRules`, content type application/json, custom headers: {var}
- Reads from the response: `$.rules`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Firewall Rules | string | yes |  | A JSON-formatted list of firewall rules. Note that you must include ALL of your firewall rules. Rules that are not included will be removed |
| Network ID | string | yes |  | The ID of the network to manage firewall rules for (ex: L_472348923894789232) |
| API Key | secure_string |  |  | If you are using an integration-provided Meraki target, this is not required. If you are using your own HTTP Endpoint target, this should be an API token generated in your Meraki dashboard |

| Output | Type | Description |
|---|---|---|
| Updated Rule List | string | The updated list of firewall rules for the given network |

### Cisco Meraki - Get Networks by Organization

Gets a list of networks for a given Cisco Meraki organization.

- Kind: read. Cisco workflow ID: `definition_workflow_01PP77O6ZSWPP2qZ7F9djlfhYkp4gC6tOsj`.
- Target: Meraki integration target or HTTP Endpoint for "api.meraki.com" with a path of "/api"
- Account key: None if using an integration-provided target, API token if using an HTTP Endpoint target
- Request: `GET v1/organizations/{var}/networks`, content type application/json, custom headers: {var}

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Organization ID | string | yes |  | The ID of the organization to get networks for |
| API Key | secure_string |  |  | If you are using an integration-provided Meraki target, this is not required. If you are using your own HTTP Endpoint target, this should be an API token generated in your Meraki dashboard |

| Output | Type | Description |
|---|---|---|
| Network List | string | The list of networks for the given organization |

### Cisco Meraki - Get Organizations

Gets a list of Cisco Meraki organizations that the API key provided has access to.

- Kind: read. Cisco workflow ID: `definition_workflow_01PP75VKKHI0M7L1KhzORCEGNLR0y54Vaz8`.
- Target: Meraki integration target or HTTP Endpoint for "api.meraki.com" with a path of "/api"
- Account key: None if using an integration-provided target, API token if using an HTTP Endpoint target
- Request: `GET v1/organizations`, content type application/json, custom headers: {var}

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| API Key | secure_string |  |  | If you are using an integration-provided Meraki target, this is not required. If you are using your own HTTP Endpoint target, this should be an API token generated in your Meraki dashboard |

| Output | Type | Description |
|---|---|---|
| Organization List | string | The list of organizations the API key provided has access to |

### Cisco Meraki - Get Top Appliances by Utilization for Org.

Gets a summary of top appliances by utilization for a Cisco Meraki organization.

- Kind: read. Cisco workflow ID: `definition_workflow_02LZ9L765EJFJ0J3p6igEqXYrw8oBBA17XS`.
- Target: Meraki integration target
- Account key: not stated
- Request: `GET /v1/organizations/{var}/summary/top/appliances/byUtilization{var}`, content type application/json, custom headers: none

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Organization ID | string | yes |  | The ID of the organization to get a usage summary for. |
| Device Tag | string |  |  | A device tag to fetch usage information for. |
| End Time | date |  | `0001-01-01T00:00:00+00:00` | When to stop fetching data. The maximum time period between Start Time and End Time is 168 days. If you provide a Start Time and End Time, do not provide a Timespan. |
| Network Tag | string |  |  | A network tag to fetch usage information for. |
| Quantity | integer |  | `10` | The number of results to return. |
| SSID Name | string |  |  | An SSID name to fetch usage information for. |
| Start Time | date |  | `0001-01-01T00:00:00+00:00` | When to start fetching data. The maximum time period between Start Time and End Time is 168 days. If you provide a Start Time and End Time, do not provide a Timespan. |
| Timespan | integer |  | `86400` | The timespan, in seconds, into the past that information will be fetched. The value must be in seconds and be greater than or equal to 8 hours and less than or equal to 186 days. The default is 1 day. If you specify a Timespan, do not specify a Start Time or End Time. |
| Usage Uplink | string |  |  | A usage uplink to fetch usage information for. |

| Output | Type | Description |
|---|---|---|
| Organization Summary | string |  |

### Cisco Meraki - Get Top Clients by Usage for Organization

Gets a summary of top clients by usage for a given Cisco Meraki organization.

- Kind: read. Cisco workflow ID: `definition_workflow_02MB1XZZD4HVX2mOrWXD27ol7iBbtcXqpzj`.
- Target: Meraki integration target
- Account key: not stated
- Request: `GET /v1/organizations/{var}/summary/top/clients/byUsage{var}`, content type application/json, custom headers: none

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Organization ID | string | yes |  | The ID of the organization to get a usage summary for. |
| Device Tag | string |  |  | A device tag to fetch usage information for. |
| End Time | date |  | `0001-01-01T00:00:00+00:00` | When to stop fetching data. The maximum time period between Start Time and End Time is 168 days. If you provide a Start Time and End Time, do not provide a Timespan. |
| Network Tag | string |  |  | A network tag to fetch usage information for. |
| Quantity | integer |  | `10` | The number of results to return. |
| SSID Name | string |  |  | An SSID name to fetch usage information for. |
| Start Time | date |  | `0001-01-01T00:00:00+00:00` | When to start fetching data. The maximum time period between Start Time and End Time is 168 days. If you provide a Start Time and End Time, do not provide a Timespan. |
| Timespan | integer |  | `86400` | The timespan, in seconds, into the past that information will be fetched. The value must be in seconds and be greater than or equal to 8 hours and less than or equal to 186 days. The default is 1 day. If you specify a Timespan, do not specify a Start Time or End Time. |
| Usage Uplink | string |  |  | A usage uplink to fetch usage information for. |

| Output | Type | Description |
|---|---|---|
| Organization Summary | string |  |

### Cisco Meraki - Network - Get Appliance Content Filtering

Gets the content filtering configuration from a Cisco Meraki appliance.

- Kind: read. Cisco workflow ID: `definition_workflow_02M456Z6O4QDQ6WhxR3GjkX88GW4urT95wQ`.
- Target: Cisco Meraki integration target
- Account key: not stated
- Request: `GET /v1/networks/{var}/appliance/contentFiltering`, content type application/json, custom headers: none

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Network ID | string | yes |  | The ID of the Meraki network to get the content filtering configuration for. |

| Output | Type | Description |
|---|---|---|
| Allowed URL Patterns | string |  |
| Blocked URL Categories | string |  |
| Blocked URL Patterns | string |  |
| URL Category List Size | string |  |

### Cisco Meraki - Network - Get Clients

Gets a list of network clients from Cisco Meraki.

- Kind: read. Cisco workflow ID: `definition_workflow_02L0DPKFLNGKA0qxdmCaWGPdy9ymTapi8Ef`.
- Target: Meraki integration target
- Account key: not stated
- Request: `GET /v1/networks/{var}/clients`, content type application/json, custom headers: none

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Network ID | string | yes |  | The ID of the Meraki network to fetch clients from |
| IP Address | string |  |  | Filters clients based on a partial or full match of the IP address |
| IPv6 Address | string |  |  | Filters clients based on a partial or full match of the IPv6 address |
| MAC Address | string |  |  | Filters clients based on a partial or full match of the MAC address |
| Page Token | string |  |  | The token for the next page of results. If there are more results than are allowed on a single page, you can run this atomic again and pass the Next Page Token from the previous run to this input to get the next page of results |
| Per Page | integer |  | `25` | The number of clients to return per page. This must be a number between 3 and 5,000 |

| Output | Type | Description |
|---|---|---|
| Clients | string |  |
| Next Page Token | string | The token for the next page of results |

### Cisco Meraki - Network - Get Splash Login Attempts

Gets a list of splash login attempts for a network from Cisco Meraki.

- Kind: read. Cisco workflow ID: `definition_workflow_02LZ4FNQ1B2GQ2lkJ9o5t8f0k64Y1DouRHp`.
- Target: Meraki integration target
- Account key: not stated
- Request: `GET /v1/networks/{var}/splashLoginAttempts{var}`, content type application/json, custom headers: none

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Network ID | string | yes |  | The ID of the network to fetch login attempts for. |
| Login Identifier | string |  |  | An optional username, email, or phone number used during login. |
| SSID Number | integer |  | `-1` | An optional SSID number to filter the results with. Leave this set to -1 to ignore the field. |
| Timespan | integer |  | `86400` | The timespan, in seconds, into the past that information will be fetched. The maximum timespan is 3 months (7776000 seconds). |

| Output | Type | Description |
|---|---|---|
| Attempt List | string |  |

### Cisco Meraki - Network - Update Appliance Content Filtering

Updates the content filtering configuration for a Cisco Meraki appliance.

- Kind: write. Cisco workflow ID: `definition_workflow_02M535H54ECZ46o1bc8JhHkyIfGxNhkBifg`.
- Target: Cisco Meraki integration target
- Account key: not stated
- Request: `PUT /v1/networks/{var}/appliance/contentFiltering`, content type application/json, custom headers: none

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Network ID | string | yes |  | The ID of the Meraki network to update content filtering for. |
| Allowed URL Patterns | string |  |  | A JSON-formatted list of allowed URL patterns. For example: [ "http://www.example.org", "http://anotherexample.com" ]  To remove all existing allowed URL patterns, set this to an empty list: [] |
| Blocked URL Categories | string |  |  | A JSON-formatted list of URL categories to block. For example: [ "meraki:contentFiltering/category/C49", "meraki:contentFiltering/category/A12" ]  To remove all existing blocked URL categories, set this to an empty list: [] |
| Blocked URL Patterns | string |  |  | A JSON-formatted list of blocked URL patterns. For example: [ "http://www.example.com", "http://www.betting.com" ]   To remove all existing blocked URL patterns, set this to an empty list: [] |
| URL Category List Size | string |  |  | The URL category list size. Valid values include: topSites, fullList. |

| Output | Type | Description |
|---|---|---|
| Updated Allowed URL Patterns | string |  |
| Updated Blocked URL Categories | string |  |
| Updated Blocked URL Patterns | string |  |
| Updated URL Category List Size | string |  |

### Cisco Meraki - Network - Update Client Policy

Updates the policy assigned to a client connected to a Cisco Meraki network.

- Kind: write. Cisco workflow ID: `definition_workflow_02L0EH79R9PIU1NGX8j4hLjBKDPQslLqHOq`.
- Target: Meraki integration target
- Account key: not stated
- Request: `PUT /v1/networks/{var}/clients/{var}/policy`, content type application/json, custom headers: none

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Client ID | string | yes |  | A unique identifier for the client device within the network |
| Device Policy | string | yes |  | The policy to assign to the client. Valid values include: Whitelisted, Blocked, Normal, Group policy |
| Network ID | string | yes |  | A unique identifier for the network where the client is connected. This ID is used to specify which network the policy update should be applied to |
| Group Policy ID | string |  |  | The ID of the group policy to apply to the client. This is only required if the "Device Policy" is set to "Group policy" |

| Output | Type | Description |
|---|---|---|
| MAC Address | string |  |
| Updated Device Policy | string |  |
| Updated Group Policy ID | string |  |

## Cisco Meraki: Systems Manager

### Cisco Meraki - SM - Get Devices

Gets a list of devices from Cisco Meraki Systems Manager.

- Kind: read. Cisco workflow ID: `definition_workflow_02GI13P4DLIKH5CcGbnemg7GZoqlpavNM7Z`.
- Target: Meraki
- Account key: not stated
- Request: `GET /v1/networks/{var}/sm/devices`, content type application/json, custom headers: none

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Network ID | string | yes |  | The ID of the network to fetch devices from |
| Device IDs | string |  |  | An optional list of device IDs to fetch. If providing multiple device IDs, provide a comma-separated list |
| Fields | string |  |  | An optional comma-separated list of fields that will be returned for each device. The default fields returned are: id, name, tags, ssid, wifiMac, osName, systemModel, uuid, and serialNumber.  The additional fields available are: ip, systemType, availableDeviceCapacity, kioskAppName, biosVersion, lastConnected, missingAppsCount, userSuppliedAddress, location, lastUser, ownerEmail, ownerUsername, osBuild, publicIp, phoneNumber, diskInfoJson, deviceCapacity, isManaged, hadMdm, isSupervised, meid, imei, iccid, simCarrierNetwork, cellularDataUsed, isHotspotEnabled, createdAt, batteryEstCharge, quarantined, avName, avRunning, asName, fwName, isRooted, loginRequired, screenLockEnabled, screenLockDelay, autoLoginDisabled, autoTags, hasMdm, hasDesktopAgent, diskEncryptionEnabled, hardwareEncryptionCaps, passCodeLock, usesHardwareKeystore, androidSecurityPatchVersion, cellular, and url |
| Page Token | string |  |  | The token for the next page of results. If there are more results than are allowed on a single page, you can run this atomic again and pass the Next Page Token from the previous run to this input to get the next page of results |
| Per Page | integer |  | `100` | The number of devices to return per page. This must be a number between 3 and 1,000 |
| Serial Numbers | string |  |  | An optional list of serial numbers to fetch. If providing multiple serial numbers, provide a comma-separated list |
| UUIDs | string |  |  | An optional list of UUIDs to fetch. If providing multiple UUIDs, provide a comma-separated list |
| WiFi MAC Addresses | string |  |  | An optional list of WiFi MAC addresses to fetch. If providing multiple WiFi MAC addresses, provide a comma-separated list |

| Output | Type | Description |
|---|---|---|
| Devices | string |  |
| Next Page Token | string | The token for the next page of results |

### Cisco Meraki - SM - Lock Devices

Locks one or more devices in Cisco Meraki Systems Manager.

- Kind: write. Cisco workflow ID: `definition_workflow_02HMJZ3CGDJZQ1APnDAJTuwHfXIX1cCO6g8`.
- Target: Meraki
- Account key: not stated
- Request: `POST /v1/networks/{var}/sm/devices/lock`, content type application/json, custom headers: none

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Network ID | string | yes |  | The ID of the network to manage devices in |
| Device IDs | string |  |  | One or more device IDs of devices to lock. If providing multiple device IDs, provide a comma-separated list. You must provide at least one device ID or serial number |
| PIN | string |  | `0` | The PIN for locking macOS devices (a six digit value that can't start with zero as a first number). This is only required for macOS devices |
| Serial Numbers | string |  |  | One or more serial numbers of devices to lock. If providing multiple serial numbers, provide a comma-separated list. You must provide at least one device ID or serial number |

### Cisco Meraki - SM - Update Device Tags

Updates a device's tags in Cisco Meraki Systems Manager.

- Kind: write. Cisco workflow ID: `definition_workflow_02HMJ0IUA09UZ1CL5PYPBnlQzzpwOF9nQEg`.
- Target: Meraki
- Account key: not stated
- Request: `POST /v1/networks/{var}/sm/devices/modifyTags`, content type application/json, custom headers: none

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Action | string | yes |  | The action to take. Valid values include: add, delete, update |
| Network ID | string | yes |  | The ID of the network to manage devices in |
| Tags | string | yes |  | One or more tags to add, remove, or update. If providing more than one tag, provide a comma-separated list |
| Device IDs | string |  |  | One or more device IDs of devices to update tags for. If providing multiple device IDs, provide a comma-separated list. You must provide at least one device ID or serial number |
| Serial Numbers | string |  |  | One or more serial numbers of devices to update tags for. If providing multiple serial numbers, provide a comma-separated list. You must provide at least one device ID or serial number |

### Cisco Meraki - SM - Wipe Device

Wipes a device managed by Cisco Meraki Systems Manager.

- Kind: write. Cisco workflow ID: `definition_workflow_02HMNJLSXKTS13ytQPzLABuxhEQo3kiQY5p`.
- Target: Meraki
- Account key: not stated
- Request: `POST /v1/networks/{var}/sm/devices/wipe`, content type application/json, custom headers: none

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Network ID | string | yes |  | The ID of the network to manage devices in |
| Device ID | string |  |  | The ID of the device to wipe. You must provide a device ID or a serial number |
| PIN | integer |  | `0` | The PIN for wiping macOS devices (a six digit value that can't start with zero as a first number). This is only required for macOS devices |
| Serial Number | string |  |  | The serial number of the device to wipe. You must provide a device ID or serial number |

## Cisco Secure Email Threat Defense

### Cisco Secure Email Threat Defense - Get Access Token

Retrieves an access token for Cisco Secure Email Threat Defense. This token can then be used with other atomics for Email Threat Defense.

- Kind: read. Cisco workflow ID: `definition_workflow_02A0IFQ3GZR1C6VnczhxCXM411zg7XS3gMl`.
- Target: HTTP Endpoint for "api.<region>.etd.cisco.com" with a path of "/v1"
- Account key: HTTP Basic Authentication with your client ID as the username and secret as the password
- Request: `POST /oauth/token`, content type application/json, custom headers: {var}
- Reads from the response: `$.accessToken`, `$.expiresIn`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| API Key | secure_string | yes |  | An API key generated in your Email Threat Defense portal. More information about this can be found in the documentation: https://developer.cisco.com/docs/message-search-api/#!rate-limiting |

| Output | Type | Description |
|---|---|---|
| Access Token | secure_string |  |
| Expires In (Seconds) | integer |  |

### Cisco Secure Email Threat Defense - Get Message Status

Fetches information about a message after an action has been taken against it using Cisco Secure Email Threat Defense.

- Kind: read. Cisco workflow ID: `definition_workflow_02A2AIKFY391Z2c1y4pMk54nmgQPimxHSkw`.
- Target: HTTP Endpoint for "api.<region>.etd.cisco.com" with a path of "/v1"
- Account key: None (uses a token)
- Request: `POST /messages/status`, content type application/json, custom headers: {var}, {var}
- Reads from the response: `$.data`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| API Key | secure_string | yes |  | An API key generated in your Email Threat Defense portal. More information about this can be found in the documentation: https://developer.cisco.com/docs/message-search-api/#!rate-limiting |
| Access Token | secure_string | yes |  | Access token generated using the "Cisco Secure Email Threat Defense - Get Access Token" atomic |
| Message ID | string | yes |  | ID of the message to fetch action status for. This should be a single message ID |

| Output | Type | Description |
|---|---|---|
| Results | string |  |

### Cisco Secure Email Threat Defense - Move or Reclassify Messages

Moves messages and/or updates message verdicts in Cisco Secure Email Threat Defense.

- Kind: write. Cisco workflow ID: `definition_workflow_02A2C8I33CA6Q7Tz8uer11go5fLxEljPoEi`.
- Target: HTTP Endpoint for "api.<region>.etd.cisco.com" with a path of "/v1"
- Account key: None (uses a token)
- Request: `POST /messages/move`, content type application/json, custom headers: {var}, {var}
- Reads from the response: `$.data`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| API Key | secure_string | yes |  | An API key generated in your Email Threat Defense portal. More information about this can be found in the documentation: https://developer.cisco.com/docs/message-search-api/#!rate-limiting |
| Access Token | secure_string | yes |  | Access token generated using the "Cisco Secure Email Threat Defense - Get Access Token" atomic |
| Message IDs | string | yes |  | IDs of the messages to move and/or change the verdict for. This can be a single message ID or a comma-separated list of IDs. A maximum of 100 IDs are allowed |
| Folder | string |  |  | An optional folder to move messages to. A folder to move messages to, a verdict to apply, or both must be provided. Valid values include: trash, quarantine, inbox, junk, delete |
| Verdict | string |  |  | An optional verdict to assign to the messages. A folder to move messages to, a verdict to apply, or both must be provided. Valid values include: spam, malicious, phishing, neutral, graymail, bec, scam, noVerdict |

| Output | Type | Description |
|---|---|---|
| Results | string |  |

### Cisco Secure Email Threat Defense - Search Messages

Searches for messages processed by Cisco Secure Email Threat Defense.

- Kind: read. Cisco workflow ID: `definition_workflow_02A0KYVYQOEN556ZxAFfb9x7AUlXzS9NZg0`.
- Target: HTTP Endpoint for "api.<region>.etd.cisco.com" with a path of "/v1"
- Account key: None (uses a token)
- Request: `POST /messages/search`, content type application/json, custom headers: {var}, {var}
- Reads from the response: `$.data.messages`, `$.totalSize`, `$.nextPageToken`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| API Key | secure_string | yes |  | An API key generated in your Email Threat Defense portal. More information about this can be found in the documentation: https://developer.cisco.com/docs/message-search-api/#!rate-limiting |
| Access Token | secure_string | yes |  | Access token generated using the "Cisco Secure Email Threat Defense - Get Access Token" atomic |
| Attachment File Hash | string |  |  | SHA-256 file hash of the attachment to search for |
| Attachment File Name | string |  |  | File name of the attachment to search for |
| Attachments and Links | string |  |  | Filters messages based on whether they have attachments, links, a combination of both, or neither. This is optional and if provided should be one or more comma-separated values. Valid values include: attachments, links, none |
| Directions | string |  |  | Which direction to filter messages by. Valid values include: incoming, outgoing, internal, mixed. If you want to specify multiple directions, separate them with a comma |
| End Date | date |  | `0001-01-01T00:00:00+00:00` | The date and time at which to stop searching for messages |
| Last Actions | string |  |  | Filters messages based on the last actions taken for the message. This is optional and if provided should be one or more comma-separated values. Valid values include: junk, trash, inbox, quarantine, none, delete |
| Message ID | string |  |  | The ID of the message to search for. This "internetMessageId" is assigned by Microsoft 365 or an external agent |
| Page Size | integer |  | `100` | Number of search results to return. This should be between 1 and 100 |
| Page Token | string |  |  | If you're fetching an additional page of results, provide the Next Page Token from the previous run of this atomic |
| Recipient | string |  |  | Email address of the message's recipient |
| Retrospective Verdict | boolean |  | `False` | Filters messages based on whether there is a retrospective verdict |
| Sender | string |  |  | Email or IP address of the message sender |
| Start Date | date |  | `0001-01-01T00:00:00+00:00` | The date and time at which to start searching for messages |
| Subject | string |  |  | Subject of the message |
| URL | string |  |  | URL contained in the message to search for |
| Verdicts | string |  |  | Verdicts to fetch messages for. Valid values include: spam, malicious, phishing, neutral, graymail, bec, scam, noVerdict. If you want to specify multiple verdicts, separate them with a comma |

| Output | Type | Description |
|---|---|---|
| Messages | string |  |
| Next Page Token | string | A token that can be used to fetch another page of results. This token being populated does not always mean another page exists. We recommend using the "Record Count" and "Page Size" to determine if there are multiple pages |
| Result Count | integer | Total number of search results. Note that this is not always the same as the number of results returned by this atomic if there are multiple pages of results |

## Cisco Secure Endpoint

### Cisco Secure Endpoint - Add File Hash to Application Block List

Adds a SHA-256 file hash to an application block list.

- Kind: write. Cisco workflow ID: `definition_workflow_021CU0J3F0FAX0lzNKFCUFDcRUXklGFTBHh`.
- Target: Secure Endpoint - v1 or an HTTP Endpoint for "api.amp.cisco.com" with a path of "/v1"
- Account key: None for Secure Endpoint - v1 or HTTP Basic Authentication for an HTTP Endpoint
- Request: `GET file_lists/application_blocking`, content type not set, custom headers: none
- Request: `POST file_lists/{var}/files/{var}`, content type application/json, custom headers: none
- Reads from the response: `$.data.*.[?(@.name=='$workflow.definition_workflow_02Z4CAQL5LD1Q65q8GebtASaOXwpCJPYyhf.input.variable_workflow_02Z4CAQLN8MTK3VspuMT4ZzybAeaW6tGmrk$')].guid`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Application Block List Name | string | yes | `Blocked Application List` | The name of the application block list to add hashes to. The default list name is "Blocked Application List" |
| SHA-256 File Hash | string | yes |  | The SHA256 file hash to add to the block list |

| Output | Type | Description |
|---|---|---|
| Results | string |  |

### Cisco Secure Endpoint - Add File Hash to File List

Adds a SHA-256 file hash to a file list in Cisco Secure Endpoint.

- Kind: write. Cisco workflow ID: `definition_workflow_02A40BBOF65CK0fUBRyTA4lN2caiNvEEVKt`.
- Target: Secure Endpoint - v1 or an HTTP Endpoint for "api.amp.cisco.com" with a path of "/v1"
- Account key: None for Secure Endpoint - v1 or HTTP Basic Authentication for an HTTP Endpoint
- Request: `POST file_lists/{var}/files/{var}`, content type application/json, custom headers: none

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| File List ID | string | yes |  | ID of the file list to add the hash to |
| SHA-256 File Hash | string | yes |  | The SHA256 file hash to add to the list |

| Output | Type | Description |
|---|---|---|
| Result | string |  |

### Cisco Secure Endpoint - Add Hash to Simple Custom Detection List

Adds a SHA-256 file hash to a simple custom detection list.

- Kind: write. Cisco workflow ID: `definition_workflow_024F6AWO1LVYA4hj5G4YkLpbXDnlDPICnNY`.
- Target: Secure Endpoint - v1 or an HTTP Endpoint for "api.amp.cisco.com" with a path of "/v1"
- Account key: None for Secure Endpoint - v1 or HTTP Basic Authentication for an HTTP Endpoint
- Request: `GET file_lists/simple_custom_detections`, content type application/json, custom headers: none
- Request: `POST file_lists/{var}/files/{var}`, content type application/json, custom headers: none
- Reads from the response: `$.data.*.[?(@.name=='$workflow.definition_workflow_02Z4CAP2HYK1T7PgqXJjMJRei8UfKXyS8EN.input.variable_workflow_02Z4CAP30POP67l5oSm0XS7Fu0Mfh2FyLmk$')].guid`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| SHA-256 File Hash | string | yes |  | The SHA256 file hash to add to the list |
| Simple Custom Detection List Name | string | yes | `Simple Custom Detection List` | The name of the simple custom detection list to add hashes to. The default list name is: "Simple Custom Detection List" |

| Output | Type | Description |
|---|---|---|
| Results | string |  |

### Cisco Secure Endpoint - Get Computer by GUID

Fetches a computer object from Cisco Secure Endpoint using its GUID.

- Kind: read. Cisco workflow ID: `definition_workflow_01PP74IORHVRJ71OWWlueKVb5v2LMDNBZw1`.
- Target: Secure Endpoint - v1 or an HTTP Endpoint for "api.amp.cisco.com" with a path of "/v1"
- Account key: None for Secure Endpoint - v1 or HTTP Basic Authentication for an HTTP Endpoint
- Request: `GET computers/{var}`, content type application/json, custom headers: none
- Reads from the response: `$.data`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Connector GUID | string | yes |  | Connector GUID of the computer to fetch |

| Output | Type | Description |
|---|---|---|
| Computer Object | string |  |

### Cisco Secure Endpoint - Get Connector GUID

Searches Cisco Secure Endpoint for the given IP address or hostname and returns the endpoint's connector GUID.

- Kind: read. Cisco workflow ID: `definition_workflow_01PP77C57P1EP5HkNX8Xjvr4GtJceSq4xxX`.
- Target: Secure Endpoint - v1 or an HTTP Endpoint for "api.amp.cisco.com" with a path of "/v1"
- Account key: None for Secure Endpoint - v1 or HTTP Basic Authentication for an HTTP Endpoint
- Request: `GET computers?{var}&limit=1`, content type application/json, custom headers: none
- Reads from the response: `$.data[0].connector_guid`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Hostname | string |  |  | Hostname of the endpoint to search for |
| IP Address | string |  |  | IP address of the endpoint to search for |

| Output | Type | Description |
|---|---|---|
| Connector GUID | string |  |

### Cisco Secure Endpoint - Get Events

Fetches events from Cisco Secure Endpoint based on various criteria.

- Kind: read. Cisco workflow ID: `definition_workflow_01PP76FTQKEYW2dg8RXriNAf2EkkZ4Agqg9`.
- Target: Secure Endpoint - v1 or an HTTP Endpoint for "api.amp.cisco.com" with a path of "/v1"
- Account key: None for Secure Endpoint - v1 or HTTP Basic Authentication for an HTTP Endpoint
- Request: `GET events?limit={var}&offset={var}&start_date={var}{var}`, content type application/json, custom headers: none

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Connector GUIDs | string |  |  | A comma-separated list of endpoint connector GUIDs to get events for. This is optional and all endpoints will be searched if this is left blank |
| Event Types | string |  |  | Zero or more event type IDs to fetch. These can be obtained from the "/v1/event_types" API endpoint. To search for all events, leave this blank. To search for one event type, include a single ID. To search for multiple event types, provide the IDs as a comma-separated list |
| Group GUIDs | string |  |  | A comma-separated list of group GUIDs to get events for. This is optional and all endpoints will be searched if this is left blank |
| Page Offset | integer |  | `0` | The index of the record to start fetching results from |
| Record Limit | integer |  | `100` | How many records to fetch per page |
| Start Date | date |  | `0001-01-01T00:00:00+00:00` | The date to start fetching events from |

| Output | Type | Description |
|---|---|---|
| Event List | string | The list of matching events |

### Cisco Secure Endpoint - Get File List Items

Gets a list of items for a specific file list in Cisco Secure Endpoint.

- Kind: read. Cisco workflow ID: `definition_workflow_029PNJNZB4USW4pcsevhAqRRM8YDu5t3vdN`.
- Target: Secure Endpoint - v1 or an HTTP Endpoint for "api.amp.cisco.com" with a path of "/v1"
- Account key: None for Secure Endpoint - v1 or HTTP Basic Authentication for an HTTP Endpoint
- Request: `GET /file_lists/{var}/files?limit={var}&offset={var}`, content type application/json, custom headers: none
- Reads from the response: `$.data.items`, `$.metadata.results.total`, `$.metadata.results.current_item_count`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| File List GUID | string | yes |  | ID of the file list to fetch items for. For example: "472c7c35-d32a-4d06-be5c-4f8e9b427ce0" |
| Limit | integer |  | `500` | The number of records to return per page |
| Offset | integer |  | `0` | Offset from which to start returning list items |

| Output | Type | Description |
|---|---|---|
| List Items | string |  |
| Result Count (This Page) | integer |  |
| Total Results | integer |  |

### Cisco Secure Endpoint - Get Group by Name

Searches Cisco Secure Endpoint for the given group and returns its attributes.

- Kind: read. Cisco workflow ID: `definition_workflow_01PP76KUZHVDE1gUGxreX9ZVwWysIR5STCI`.
- Target: Secure Endpoint - v1 or an HTTP Endpoint for "api.amp.cisco.com" with a path of "/v1"
- Account key: None for Secure Endpoint - v1 or HTTP Basic Authentication for an HTTP Endpoint
- Request: `GET groups?name={var}&limit=1`, content type application/json, custom headers: none
- Reads from the response: `$.data[0].guid`, `$.data[0]`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Group Name | string | yes |  | Name of the group to search for |

| Output | Type | Description |
|---|---|---|
| Group Attributes | string |  |
| Group GUID | string |  |

### Cisco Secure Endpoint - Get Simple Custom Detections File Lists

Gets a list of simple custom detections file list from Cisco Secure Endpoint.

- Kind: read. Cisco workflow ID: `definition_workflow_02GABUAEF1V9P781YeI8EznugeEegv3PQjC`.
- Target: Secure Endpoint - v1 or an HTTP Endpoint for "api.amp.cisco.com" with a path of "/v1"
- Account key: None for Secure Endpoint - v1 or HTTP Basic Authentication for an HTTP Endpoint
- Request: `GET /file_lists/simple_custom_detections?limit={var}&offset={var}{var}`, content type application/json, custom headers: none
- Reads from the response: `$.data`, `$.metadata.results.total`, `$.metadata.results.current_item_count`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Limit | integer |  | `50` | The number of records to return per page |
| List Name | string |  |  | An optional name of a specific file list to fetch |
| Offset | integer |  | `0` | Offset from which to start returning list items |

| Output | Type | Description |
|---|---|---|
| File Lists | string |  |
| Result Count (This Page) | integer |  |
| Total Results | integer |  |

### Cisco Secure Endpoint - Isolate Host

Enables isolation for a given computer by its connector GUID.

- Kind: write. Cisco workflow ID: `definition_workflow_01PP77UWMZGOK7EpAqljGObzskFeYlPRah5`.
- Target: Secure Endpoint - v1 or an HTTP Endpoint for "api.amp.cisco.com" with a path of "/v1"
- Account key: None for Secure Endpoint - v1 or HTTP Basic Authentication for an HTTP Endpoint
- Request: `GET computers/{var}/isolation`, content type application/json, custom headers: none
- Request: `PUT computers/{var}/isolation`, content type application/json, custom headers: none
- Reads from the response: `$.data.available`, `$.data.status`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Connector GUID | string | yes |  | Connector GUID of the computer to enable isolation for |

### Cisco Secure Endpoint - Move Computer to Group

Moves a computer identified by a given connector GUID to a group.

- Kind: write. Cisco workflow ID: `definition_workflow_01PP77736E3Z84p2rYcNQJTutcGMh9QaXet`.
- Target: Secure Endpoint - v1 or an HTTP Endpoint for "api.amp.cisco.com" with a path of "/v1"
- Account key: None for Secure Endpoint - v1 or HTTP Basic Authentication for an HTTP Endpoint
- Request: `PATCH computers/{var}`, content type application/json, custom headers: none

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Connector GUID | string | yes |  | Connector GUID of the computer to move |
| Group GUID | string | yes |  | GUID of the group to add the computer to |

### Cisco Secure Endpoint - Remove File Hash from File List

Removes a SHA-256 file hash from a file list in Cisco Secure Endpoint.

- Kind: write. Cisco workflow ID: `definition_workflow_029PNCK63HMV556owpKJaB94nWS42duY176`.
- Target: Secure Endpoint - v1 or an HTTP Endpoint for "api.amp.cisco.com" with a path of "/v1"
- Account key: None for Secure Endpoint - v1 or HTTP Basic Authentication for an HTTP Endpoint
- Request: `DELETE /file_lists/{var}/files/{var}`, content type application/json, custom headers: none

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| File List GUID | string | yes |  | The unique ID of the file list to remove hashes from. For example: "472c7c35-d32a-4d06-be5c-4f8e9b427ce0" |
| SHA-256 File Hash | string | yes |  | The SHA256 file hash to remove from the list |

### Cisco Secure Endpoint - Search Computers

Searches Cisco Secure Endpoint for computers. If no search options are provided, all computers will be returned.

- Kind: read. Cisco workflow ID: `definition_workflow_029RF4ECMT6IN5hzePe2M7aCeBRdDum9huC`.
- Target: Secure Endpoint - v1 or an HTTP Endpoint for "api.amp.cisco.com" with a path of "/v1"
- Account key: None for Secure Endpoint - v1 or HTTP Basic Authentication for an HTTP Endpoint
- Request: `GET {var}`, content type application/json, custom headers: none
- Reads from the response: `$.data`, `$.metadata.results.total`, `$.metadata.results.current_item_count`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Group GUID | string |  |  | GUID of the group to fetch computers for |
| Hostname | string |  |  | Hostname of the computers to search for |
| Internal IP Address | string |  |  | Internal IP address of the computer to search for |
| Last Seen Over | integer |  | `0` | Filters the search results to only include computers that were last seen over this many days ago |
| Last Seen Within | integer |  | `0` | Filters the search results to only include computers that were last seen within this many days |
| Limit | integer |  | `100` | The maximum number of computers to return per page |
| Offset | integer |  | `0` | The index at which to start returning computers. The first result is at offset 0 |

| Output | Type | Description |
|---|---|---|
| Computers | string |  |
| Results This Page | integer | The number of computers returned on this page of results |
| Total Results | integer | The total number of computers matching the search. These may be spread over multiple pages |

### Cisco Secure Endpoint - Un-Isolate Host

Disables isolation for a given computer in Cisco Secure Endpoint using its connector GUID.

- Kind: write. Cisco workflow ID: `definition_workflow_01PP74GYYFGQU7ctqUcwmWbpgkPFh1I8J4z`.
- Target: Secure Endpoint - v1 or an HTTP Endpoint for "api.amp.cisco.com" with a path of "/v1"
- Account key: None for Secure Endpoint - v1 or HTTP Basic Authentication for an HTTP Endpoint
- Request: `GET computers/{var}/isolation`, content type application/json, custom headers: none
- Request: `DELETE computers/{var}/isolation`, content type application/json, custom headers: none
- Reads from the response: `$.data.available`, `$.data.status`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Connector GUID | string | yes |  | Connector GUID of the computer to disable isolation for |

## Cisco Secure Malware Analytics

### Cisco Secure Malware Analytics - Get Sample Analysis

Gets the analysis results of a sample that was previously submitted to Cisco Secure Malware Analytics.

- Kind: read. Cisco workflow ID: `definition_workflow_01PP7889QZ7LW3KC8jCPnHzO2hKwjeNWPMi`.
- Target: Secure Malware Analytics integration target or an HTTP Endpoint for "panacea.threatgrid.com"
- Account key: None if using an integration target, API key if using an HTTP endpoint
- Request: `GET {var}/v2/samples/{var}/analysis.json{var}{var}`, content type application/json, custom headers: none
- Reads from the response: `$.threat.threat_score`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Sample ID | string | yes |  | The ID returned by Secure Malware Analytics when the sample was submitted for analysis. |
| API Key | secure_string |  |  | If you are using an integration target, you can leave this blank. If you are using an HTTP endpoint target, provide your Secure Malware Analytics API key. This can be obtained from your "My Account" page in Secure Malware Analytics under the "API" section. |

| Output | Type | Description |
|---|---|---|
| Sample Analysis | string | Detailed analysis results for the sample. |
| Threat Score | integer | The sample's threat score based on the analysis conducted |

### Cisco Secure Malware Analytics - Get Sample Status

Gets the status of a sample that was previously submitted to Cisco Secure Malware Analytics for analysis.

- Kind: read. Cisco workflow ID: `definition_workflow_01PP77Y9IHEJ40dqCNBi6yWBFZajjrwAKrG`.
- Target: Secure Malware Analytics integration target or an HTTP Endpoint for "panacea.threatgrid.com"
- Account key: None if using an integration target, API key if using an HTTP endpoint
- Request: `GET {var}/v2/samples/{var}{var}{var}`, content type application/json, custom headers: none
- Reads from the response: `$.data.state`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Sample ID | string | yes |  | The ID returned by Secure Malware Analytics when the sample was submitted for analysis. |
| API Key | secure_string |  |  | If you are using an integration target, you can leave this blank. If you are using an HTTP endpoint target, provide your Secure Malware Analytics API key. This can be obtained from your "My Account" page in Secure Malware Analytics under the "API" section. |

| Output | Type | Description |
|---|---|---|
| Job Status | string | The current status of the job. |
| Sample Status | string | The full status of the sample's analysis (not just the status code). |

### Cisco Secure Malware Analytics - Get Samples by File Hash

Gets a list of sample submissions from Cisco Secure Malware Analytics for a given file hash.

- Kind: read. Cisco workflow ID: `definition_workflow_01PP75MV62DWN0raRr4mKAGgLjQhLnPVlFJ`.
- Target: Secure Malware Analytics integration target or an HTTP Endpoint for "panacea.threatgrid.com"
- Account key: None if using an integration target, API key if using an HTTP endpoint
- Request: `GET {var}/v2/search/submissions?q={var}{var}{var}&sort_by={var}&sort_order={var}&offset={var}&limit={var}&{var}`, content type application/json, custom headers: none
- Reads from the response: `$.data.total`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| File Hash | string | yes |  | The file hash to get sample data for. This can be one of the following hash types: sha256, sha1, or md5. |
| Sort By | string | yes | `submitted_at` | Which field to sort the results by. By default, the submission date is used. |
| Sort Direction | string | yes | `desc` | Which direction to sort the results. For example, if sorting by submitted_at: "desc" means the most recent samples are first and "asc" means the oldest samples are first. |
| API Key | secure_string |  |  | If you are using an integration target, you can leave this blank. If you are using an HTTP endpoint target, provide your Secure Malware Analytics API key. This can be obtained from your "My Account" page in Secure Malware Analytics under the "API" section. |
| Extra Parameters | string |  |  | Additional query parameters you want appended to the search string. For example: state=succ&somefield=somevalue |
| Page Offset | integer |  | `0` | Which record to start fetching results from. |
| Record Limit | integer |  | `20` | How many records to return per page. |

| Output | Type | Description |
|---|---|---|
| Sample Count | integer | How many sample submissions matched the file hash provided. |
| Sample Data | string | Sample data for the file hash provided. |

### Cisco Secure Malware Analytics - Submit File

Submits a file to Cisco Secure Malware Analytics for analysis. If wait for results is false, the atomic submits the sample and returns the sample ID without waiting for analysis to complete. If wait for results is true, the atomic waits until analysis is complete and returns the full results.

- Kind: write. Cisco workflow ID: `definition_workflow_01PP74NMCSJYN5DYHJIh4d3TYHAG7jqguRU`.
- Target: Secure Malware Analytics integration target or an HTTP Endpoint for "panacea.threatgrid.com"
- Account key: None if using an integration target, API key if using an HTTP endpoint
- Request: `GET {var}/v2/samples/{var}{var}{var}`, content type application/json, custom headers: none
- Request: `GET {var}/v2/samples/{var}/analysis.json{var}{var}`, content type application/json, custom headers: none
- Reads from the response: `$.data.id`, `$.data.state`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| API Key | secure_string |  |  | If you are using an integration target, you can leave this blank. If you are using an HTTP endpoint target, provide your Secure Malware Analytics API key. This can be obtained from your "My Account" page in Secure Malware Analytics under the "API" section. |
| Playbook Name | string |  | `default` | The name of the playbook to execute on the sample file. A list of valid playbooks can be obtained from the Secure Malware Analytics API (see: https://panacea.threatgrid.com/mask/api-doc/api/v3/configuration/playbooks). |
| Private Sample | boolean |  | `True` | If true, the sample will be marked private. If false, the sample will be public. |
| Sample File | file |  |  | The file to be submitted. |
| Tags | string |  |  | Tags to add to the submission to make it easier to identify within the Secure Malware Analytics console. |
| Virtual Machine Name | string |  |  | The name of the virtual machine to use when analyzing the sample. If this value isn't provided, the best VM will be chosen based on the playbook. A list of valid VMs can be obtained from the Secure Malware Analytics API (see: https://panacea.threatgrid.com/mask/api-doc/api/v3/configuration/vms). |
| Virtual Machine Runtime | integer |  | `5` | How long the virtual machine will run while analyzing the sample file. |
| Wait for Results | boolean |  | `False` | If this is true, the atomic will continue running until analysis is complete and then return the full results. If this is false, the atomic will submit the file to Secure Malware Analytics and return the sample ID immediately (without waiting for the analysis to complete). |

| Output | Type | Description |
|---|---|---|
| Analysis Results | string | The analysis results for the sample. Note that this is only populated if "Wait for Results" is set to true. |
| Sample Details | string | Information about the sample that was created when the file was submitted. |
| Sample ID | string | The ID of the sample within Secure Malware Analytics after submission. This ID can be used to check analysis status and get results. |

### Cisco Secure Malware Analytics - Submit URL

Submits a URL to Cisco Secure Malware Analytics for analysis. If wait for results is false, the atomic submits the sample and returns the sample ID without waiting for analysis to complete. If wait for results is true, the atomic waits until analysis is complete and returns the full results.

- Kind: write. Cisco workflow ID: `definition_workflow_01PP78YVWMXKI3jcrOGYocGMM3VaophGkkJ`.
- Target: Secure Malware Analytics integration target or an HTTP Endpoint for "panacea.threatgrid.com"
- Account key: None if using an integration target, API key if using an HTTP endpoint
- Request: `POST {var}/v2/samples{var}{var}`, content type not set, custom headers: Content-Type
- Request: `GET {var}/v2/samples/{var}{var}{var}`, content type application/json, custom headers: none
- Request: `GET {var}/v2/samples/{var}/analysis.json{var}{var}`, content type application/json, custom headers: none
- Reads from the response: `$.data.id`, `$.data.state`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Sample URL | string | yes |  | The URL to submit for detonation. |
| API Key | secure_string |  |  | If you are using an integration target, you can leave this blank. If you are using an HTTP endpoint target, provide your Secure Malware Analytics API key. This can be obtained from your "My Account" page in Secure Malware Analytics under the "API" section. |
| Playbook Name | string |  | `default` | The name of the playbook to execute on the sample file. A list of valid playbooks can be obtained from the Secure Malware Analytics API (see: https://panacea.threatgrid.com/mask/api-doc/api/v3/configuration/playbooks). |
| Private Sample | boolean |  | `True` | If true, the sample will be marked private. If false, the sample will be public. |
| Tags | string |  |  | Tags to add to the submission to make it easier to identify within the Secure Malware Analytics console. |
| Virtual Machine Name | string |  |  | The name of the virtual machine to use when analyzing the sample. If this value isn't provided, the best VM will be chosen based on the playbook. A list of valid VMs can be obtained from the Secure Malware Analytics API (see: https://panacea.threatgrid.com/mask/api-doc/api/v3/configuration/vms). |
| Virtual Machine Runtime | integer |  | `5` | How long the virtual machine will run while analyzing the sample file. Valid values include: 2, 5. |
| Wait for Results | boolean |  | `False` | If this is true, the atomic will continue running until analysis is complete and then return the full results. If this is false, the atomic will submit the file to Secure Malware Analytics and return the sample ID immediately (without waiting for the analysis to complete). |

| Output | Type | Description |
|---|---|---|
| Analysis Results | string | The analysis results for the sample. Note that this is only populated if "Wait for Results" is set to true. |
| Sample Details | string | Information about the sample that was created when the file was submitted. |
| Sample ID | string | The ID of the sample within Secure Malware Analytics after submission. This ID can be used to check analysis status and get results. |

## Cisco Umbrella

### Cisco Umbrella - Investigate - Categorize Multiple Domains

Uses the Cisco Umbrella Investigate API to get information about a list of domains. The input should be a JSON-formatted list of fully qualified domain names. This atomic requires read permission to the "Investigate / Bulk" API scope.

- Kind: read. Cisco workflow ID: `definition_workflow_01PP77T9C9XTR3P8cRkyYr4lXCL5znB5HbB`.
- Target: HTTP Endpoint for "investigate.api.umbrella.com"
- Account key: None (uses an API token)
- Request: `POST /domains/categorization/?showLabels`, content type application/json, custom headers: Authorization

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Domain List | string | yes |  | A JSON-formatted list of fully qualified domain names. For example: ["cisco.com","google.com"] |
| Investigate API Token | secure_string | yes |  | Your token for the Umbrella Investigate API |

| Output | Type | Description |
|---|---|---|
| Investigation Results | string |  |

### Cisco Umbrella - Investigate - Categorize Single Domain

Uses the Cisco Umbrella Investigate API to get information about a domain. This atomic requires read permission to the "Investigate / Investigate" API scope.

- Kind: read. Cisco workflow ID: `definition_workflow_01PP77ZX5WIF206cXjgKQ1HL4etBbWJd4Jl`.
- Target: HTTP Endpoint for "investigate.api.umbrella.com"
- Account key: None (uses an API token)
- Request: `GET /domains/categorization/{var}?showLabels`, content type application/json, custom headers: Authorization

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Domain Name | string | yes |  | This should be a fully qualified domain name, for example: cisco.com |
| Investigate API Token | secure_string | yes |  | Your token for the Umbrella Investigate API |

| Output | Type | Description |
|---|---|---|
| Investigation Results | string |  |

### Cisco Umbrella - Management - Add Record to Destination List

Adds a new domain or IP address to a destination list in Cisco Umbrella. This atomic requires read/write permission to the "Policies / Destinations" API scope.

- Kind: write. Cisco workflow ID: `definition_workflow_01PR38PRIL1R04x7je59e5UtYqDQ0B1NHet`.
- Target: HTTP Endpoint for "management.api.umbrella.com"
- Account key: HTTP Basic Authentication with an Umbrella Management API client ID and seceret
- Request: `POST v1/organizations/{var}/destinationlists/{var}/destinations`, content type application/json, custom headers: none
- Reads from the response: `$.data`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Destination List ID | string | yes |  | ID of the destination list to add the record to |
| New Destination | string | yes |  | Fully qualified domain name or IP address you want to add to the destination list |
| Organization ID | string | yes |  | Your Umbrella organization ID. This can be found in the URL of your Umbrella dashboard. For example, in this URL the organization ID is "1234567": https://dashboard.umbrella.com/o/1234567/#/overview |
| Comment | string |  |  | An optional comment to add to the destination |

### Cisco Umbrella - Management - Get Destination List Entries

Gets a list of destinations for a given destination list ID from Cisco Umbrella. This atomic requires read permission to the "Policies / Destinations" API scope.

- Kind: read. Cisco workflow ID: `definition_workflow_01PP74LX9CFL65B7W3iLtsAPkLLUupAzd6Q`.
- Target: HTTP Endpoint for "management.api.umbrella.com"
- Account key: HTTP Basic Authentication with an Umbrella Management API client ID and seceret
- Request: `GET v1/organizations/{var}/destinationlists/{var}/destinations?page={var}&limit={var}`, content type application/json, custom headers: none
- Reads from the response: `$.data`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Destination List ID | string | yes |  | ID of the destination list to get entries for |
| Organization ID | string | yes |  | Your Umbrella organization ID. This can be found in the URL of your Umbrella dashboard. For example, in this URL the organization ID is "1234567": https://dashboard.umbrella.com/o/1234567/#/overview |
| Limit | integer |  | `100` | How many records to return |
| Page | integer |  | `1` | Which page of records to fetch |

| Output | Type | Description |
|---|---|---|
| Destination List Entries | string |  |

### Cisco Umbrella - Management - Get Destination Lists

Gets a list of destination lists for a given organization ID from Cisco Umbrella. This atomic requires read permission to the "Policies / Destination Lists" API scope.

- Kind: read. Cisco workflow ID: `definition_workflow_01PP76E2PZZDF6jy3jVpYnYp5STVy3zReDB`.
- Target: HTTP Endpoint for "management.api.umbrella.com"
- Account key: HTTP Basic Authentication with an Umbrella Management API client ID and seceret
- Request: `GET v1/organizations/{var}/destinationlists?limit={var}&page={var}`, content type application/json, custom headers: none
- Reads from the response: `$.data[*]`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Organization ID | string | yes |  | Your Umbrella organization ID. This can be found in the URL of your Umbrella dashboard. For example, in this URL the organization ID is "1234567": https://dashboard.umbrella.com/o/1234567/#/overview |
| Limit | integer |  | `100` | How many records to return |
| Page | integer |  | `1` | Which page of records to fetch |

| Output | Type | Description |
|---|---|---|
| Destination Lists | string |  |

### Cisco Umbrella - Management - Get Organizations

Gets a list of organizations the current API client has access to in Cisco Umbrella. This atomic requires read permission to the "Admin / Organizations" API scope.

- Kind: read. Cisco workflow ID: `definition_workflow_01PP74SP0EFRX2emieJygHSoJzkc3fJQVcv`.
- Target: HTTP Endpoint for "management.api.umbrella.com"
- Account key: HTTP Basic Authentication with an Umbrella Network and Devices API client ID and seceret
- Request: `GET v1/organizations`, content type not set, custom headers: none
- Reads from the response: `$.[0].organizationId`, `$.[0].name`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|

| Output | Type | Description |
|---|---|---|
| Organization ID | string |  |
| Organization List | string |  |
| Organization Name | string |  |

### Cisco Umbrella - Management - Remove Record from Dest. List

Removes a destination from a destination list by its ID in Cisco Umbrella. This atomic requires read/write permission to the "Policies / Destination Lists" API scope.

- Kind: write. Cisco workflow ID: `definition_workflow_01PP770D29JYI33zWqiLXaTzQvBWWm7Hc2F`.
- Target: HTTP Endpoint for "management.api.umbrella.com"
- Account key: HTTP Basic Authentication with an Umbrella Management API client ID and seceret
- Request: `DELETE v1/organizations/{var}/destinationlists/{var}/destinations/remove`, content type application/json, custom headers: none
- Reads from the response: `$.data`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Destination ID | string | yes |  | The ID of the destination to be removed. This can be obtained by getting a destination list's destinations and looking for the record you want to remove |
| Destination List ID | string | yes |  | ID of the destination list to remove the record from |
| Organization ID | string | yes |  | Your Umbrella organization ID. This can be found in the URL of your Umbrella dashboard. For example, in this URL the organization ID is "1234567": https://dashboard.umbrella.com/o/1234567/#/overview |

### Cisco Umbrella - Reporting - Get Security Activity Report

Gets security activity report events from Umbrella. This atomic can only return up to the first 500 events within the timeframe provided.

- Kind: read. Cisco workflow ID: `definition_workflow_01PP7720TL3J45qKv34GB8H2ZPTkNBf84xe`.
- Target: HTTP Endpoint for "reports.api.umbrella.com"
- Account key: HTTP Basic Authentication with an Umbrella Reporting API client ID and secret
- Request: `GET v1/organizations/{var}/security-activity?start={var}&stop={var}&limit={var}`, content type application/json, custom headers: none
- Reads from the response: `$.requests`, `$.requests.length()`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Organization ID | string | yes |  | Your Umbrella organization ID. This can be found in the URL of your Umbrella dashboard. For example, in this URL the organization ID is "1234567": https://dashboard.umbrella.com/o/1234567/#/overview |
| Limit | integer |  | `100` | The maximum number of entries to retrieve. Cannot be greater than 500 |
| Start Time | date |  | `0001-01-01T00:00:00+00:00` | The time at which to start fetching records |
| Stop Time | date |  | `0001-01-01T00:00:00+00:00` | The time at which to stop fetching records |

| Output | Type | Description |
|---|---|---|
| Entry Count | integer |  |
| Report Data | string |  |

### Cisco Umbrella - Reporting v2 - Get Activity

Gets a list of activity entries from within the given timeframe. If no activity type is provided, all event types will be included. See the "Activity Type" input variable for more information about supported filters. The "Additional Parameters" input variable can be used to provide additional query string parameters which will be passed through to Umbrella. This atomic requires read permission to the "Reports / Aggregations" API scope.

- Kind: read. Cisco workflow ID: `definition_workflow_01PP78365JEEM2gdXOowzJ3HK8aoZatY0jf`.
- Target: HTTP Endpoint for "reports.api.umbrella.com"
- Account key: None (uses an access token)
- Request: `GET v2/organizations/{var}/activity{var}?from={var}&to={var}&limit={var}&offset={var}&{var}`, content type not set, custom headers: Authorization
- Reads from the response: `$.data.length()`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Access Token | secure_string | yes |  | Bearer token retrieved using the "Umbrella - Reporting v2 - Get Token" atomic action |
| From Time | string | yes |  | Timestamp to start getting entries from. This should be either a timestamp in milliseconds or a relative time such as "-1days" |
| Organization ID | string | yes |  | Your Umbrella organization ID. This can be found in the URL of your Umbrella dashboard. For example, in this URL the organization ID is "1234567": https://dashboard.umbrella.com/o/1234567/#/overview |
| To Time | string | yes |  | Timestamp to stop getting entries at. This should be either a timestamp in milliseconds or a relative time such as "now" |
| Activity Type | string |  |  | The subset of activity to report on. If this is left blank, all activity will be included. Possible values (besides blank) include: dns, proxy, firewall, ip, or amp-retrospective |
| Additional Parameters | string |  |  | Extra parameters that should be appended to the report request. These should be formatted as a query string. For example: "domains=test.com&ports=443&verdict=blocked" |
| Limit | integer |  | `100` | The maximum number of entries to retrieve |
| Offset | integer |  | `0` | The index of the initial entry to retrieve "limit" entries from |

| Output | Type | Description |
|---|---|---|
| Entry Count | integer | The number of entries returned by Umbrella |
| Report Data | string |  |

### Cisco Umbrella - Reporting v2 - Get Categories

Gets a list of categories from Umbrella. This atomic requires read permission to the "Reports / Utilities" API scope.

- Kind: read. Cisco workflow ID: `definition_workflow_01PR1QP0ESOVB3AbJDFvc9Dt2X8n9krra8t`.
- Target: HTTP Endpoint for "reports.api.umbrella.com"
- Account key: None (uses an access token)
- Request: `GET v2/organizations/{var}/categories`, content type not set, custom headers: Authorization

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Access Token | secure_string | yes |  | Bearer token retrieved using the "Umbrella - Reporting v2 - Get Token" atomic action |
| Organization ID | string | yes |  | Your Umbrella organization ID. This can be found in the URL of your Umbrella dashboard. For example, in this URL the organization ID is "1234567": https://dashboard.umbrella.com/o/1234567/#/overview |

| Output | Type | Description |
|---|---|---|
| Category Results | string | List of categories returned by Umbrella |

### Cisco Umbrella - Reporting v2 - Get Token

Gets an OAuth2 token for the Umbrella v2 API using a client ID and secret.

- Kind: read. Cisco workflow ID: `definition_workflow_01PP75D6GJ0002MvUF1kmECjGTE8Ps6WiaC`.
- Target: HTTP Endpoint for "management.api.umbrella.com"
- Account key: HTTP Basic Authentication with an Umbrella Reporting API client ID and secret
- Request: `GET auth/v2/oauth2/token`, content type not set, custom headers: none
- Reads from the response: `$.access_token`, `$.expires_in`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|

| Output | Type | Description |
|---|---|---|
| Access Token | secure_string | The bearer token for subsequent API requests |
| Expires In (Seconds) | integer | How many seconds until the access token expires |

### Cisco Umbrella - Reporting v2 - Get Top Internal IPs

Gets a list of the top internal IPs from within the given timeframe. The "Additional Parameters" input variable can be used to provide additional query string parameters which will be passed through to Umbrella. This atomic requires read permission to the "Reports / Aggregations" API scope.

- Kind: read. Cisco workflow ID: `definition_workflow_01PP74W600RG63sZJj9CFeOsfmfX46hKfdi`.
- Target: HTTP Endpoint for "reports.api.umbrella.com"
- Account key: None (uses an access token)
- Request: `GET v2/organizations/{var}/top-ips/internal?from={var}&to={var}&limit={var}&offset={var}&{var}`, content type not set, custom headers: Authorization
- Reads from the response: `$.data.length()`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Access Token | secure_string | yes |  | Bearer token retrieved using the "Umbrella - Reporting v2 - Get Token" atomic action |
| From Time | string | yes |  | Timestamp to start getting entries from. This should be either a timestamp in milliseconds or a relative time such as "-1days" |
| Organization ID | string | yes |  | Your Umbrella organization ID. This can be found in the URL of your Umbrella dashboard. For example, in this URL the organization ID is "1234567": https://dashboard.umbrella.com/o/1234567/#/overview |
| To Time | string | yes |  | Timestamp to stop getting entries at. This should be either a timestamp in milliseconds or a relative time such as "now" |
| Additional Parameters | string |  |  | Extra parameters that should be appended to the report request. These should be formatted as a query string. For example: "domains=test.com&ports=443&verdict=blocked" |
| Limit | integer |  | `100` | The maximum number of entries to retrieve |
| Offset | integer |  | `0` | The index of the initial entry to retrieve "limit" entries from |

| Output | Type | Description |
|---|---|---|
| Entry Count | integer | The number of entries returned by Umbrella |
| Report Data | string |  |

### Cisco Umbrella - Reporting v2 - Get Top Threats

Gets a list of top threats from within the given timeframe. If no threat type is provided, all threats will be included. See the "Threat Type" input variable for more information about supported filters. The "Additional Parameters" input variable can be used to provide additional query string parameters which will be passed through to Umbrella. This atomic requires read permission to the "Reports / Aggregations" API scope.

- Kind: read. Cisco workflow ID: `definition_workflow_01PP77AH8F8WY2W1ZzWO2liXUY1Tcms3f1t`.
- Target: HTTP Endpoint for "reports.api.umbrella.com"
- Account key: None (uses an access token)
- Request: `GET v2/organizations/{var}/top-threats{var}?from={var}&to={var}&limit={var}&offset={var}&{var}`, content type not set, custom headers: Authorization
- Reads from the response: `$.data.length()`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Access Token | secure_string | yes |  | Bearer token retrieved using the "Umbrella - Reporting v2 - Get Token" atomic action |
| From Time | string | yes |  | Timestamp to start getting entries from. This should be either a timestamp in milliseconds or a relative time such as "-1days" |
| Organization ID | string | yes |  | Your Umbrella organization ID. This can be found in the URL of your Umbrella dashboard. For example, in this URL the organization ID is "1234567": https://dashboard.umbrella.com/o/1234567/#/overview |
| To Time | string | yes |  | Timestamp to stop getting entries at. This should be either a timestamp in milliseconds or a relative time such as "now" |
| Additional Parameters | string |  |  | Extra parameters that should be appended to the report request. These should be formatted as a query string. For example: "domains=test.com&ports=443&verdict=blocked" |
| Limit | integer |  | `100` | The maximum number of entries to retrieve |
| Offset | integer |  | `0` | The index of the initial entry to retrieve "limit" entries from |
| Threat Type | string |  |  | The subset of threats to report on. If this is left blank, all threats will be included. Possible values (besides blank) include: dns, proxy, or firewall |

| Output | Type | Description |
|---|---|---|
| Entry Count | integer | The number of entries returned by Umbrella |
| Report Data | string |  |

## Cisco Umbrella (v2)

### Cisco Umbrella - Add Records to Destination List

Adds one or more URLs, domains, or IP addresses to a destination list in Cisco Umbrella. Note: DNS policies accept URLs or domains while web policies accept IP addresses, URLs, or domains. This atomic requires read/write permission to the "Policies / Destination Lists" API scope.

- Kind: write. Cisco workflow ID: `definition_workflow_021G2KC6PPBCJ20BEMz0DqluDASOx7lI2pe`.
- Target: Umbrella integration target or HTTP Endpoint for "api.umbrella.com" with no path
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `POST /policies/v2/destinationlists/{var}/destinations`, content type application/json, custom headers: {var}
- Reads from the response: `$.status.code`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Destination List ID | string | yes |  | The ID of the destination list to add the records to |
| New Destinations | string | yes |  | Comma-separated list of fully qualified domain names, IP addresses, or URLs you want to add to the destination list |
| Access Token | secure_string |  |  | If you are using an integration-provided Umbrella target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated using the "Umbrella - Get Access Token" activity |
| Comment | string |  |  | An optional comment to add to the destination list entries |

### Cisco Umbrella - Create Destination List

Creates a new destination list in Cisco Umbrella. This atomic requires read/write permission to the "Policies / Destination Lists" API scope.

- Kind: write. Cisco workflow ID: `definition_workflow_0292PB3I5ILJI0BvJG9fBEXLHgrnn4zVzpL`.
- Target: Umbrella integration target or HTTP Endpoint for "api.umbrella.com" with no path
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `POST /policies/v2/destinationlists`, content type application/json, custom headers: {var}
- Reads from the response: `$.id`, `$.meta.destinationCount`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Access Type | string | yes |  | The type of access for the destination list. Valid values include: allow, block |
| Name | string | yes |  | The name of the new destination list |
| Access Token | secure_string |  |  | If you are using an integration-provided Umbrella target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated using the "Umbrella - Get Access Token" activity |
| Bundle Type ID | integer |  | `1` | The type of the Umbrella policy associated with the destination list. Set "1" for DNS policy or "2" for Web policy |
| Destinations | string |  |  | A JSON-formatted list of destinations to add to the new list. See the API documentation for more information. For example: [{   "destination": "somedomain.com",   "type": "domain",   "comment": "Added by Cisco XDR automation" }] |
| Is Global | boolean |  | `False` | Whether the destination list is a global destination list. There is only one default destination list of type "allow" or "block" for each organization. As in, you can only have one "allow" global destination list and one "block" global destination list |

| Output | Type | Description |
|---|---|---|
| Destination Count | integer |  |
| Destination List ID | string |  |
| Results | string |  |

### Cisco Umbrella - Delete Destination List

Deletes a destination list by its ID in Cisco Umbrella. This atomic requires read/write permission to the "Policies / Destination Lists" API scope.

- Kind: write. Cisco workflow ID: `definition_workflow_0292LXCA6EQLC6V7E6gnopDSojkshNrtZEE`.
- Target: Umbrella integration target or HTTP Endpoint for "api.umbrella.com" with no path
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `DELETE /policies/v2/destinationlists/{var}`, content type application/json, custom headers: {var}

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Destination List ID | string | yes |  | The ID of the destination list to delete |
| Access Token | secure_string |  |  | If you are using an integration-provided Umbrella target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated using the "Umbrella - Get Access Token" activity |

### Cisco Umbrella - Get Access Token

Fetches an OAuth2 authorization token for the Cisco Umbrella API. If you are using an integration-provided Umbrella target, you do not need to use this atomic as an access token will be generated by the target for you.

- Kind: read. Cisco workflow ID: `definition_workflow_024M6RS4HT54477xX1zmIK4Sl2Wxa9GpNsS`.
- Target: HTTP Endpoint for "api.umbrella.com"
- Account key: HTTP Basic Authentication with a Cisco Umbrella API client ID and secret
- Request: `POST /auth/v2/token`, content type application/json, custom headers: none
- Reads from the response: `$.access_token`, `$.expires_in`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|

| Output | Type | Description |
|---|---|---|
| Access Token | secure_string | The bearer token for subsequent API requests |
| Expires In (Seconds) | integer | How many seconds until the access token expires |

### Cisco Umbrella - Get Activity

Gets a list of activity from within the given timeframe from Cisco Umbrella. If no activity type is provided, all types will be included. See the "Activity Type" input variable for more information about supported filters. The "Additional Parameters" input variable can be used to provide additional query string parameters which will be passed through to Umbrella. This atomic requires read permission to the "Reports / Aggregations" API scope.

- Kind: read. Cisco workflow ID: `definition_workflow_02925VFY6KIE72kUMTaohz3o6nXWTO0qoYz`.
- Target: Umbrella integration target or HTTP Endpoint for "api.umbrella.com" with no path
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `GET /reports/v2/activity{var}?from={var}&to={var}&limit={var}&offset={var}&{var}`, content type not set, custom headers: {var}
- Reads from the response: `$.data.length()`, `$.data`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| From Time | string | yes |  | Timestamp to start getting entries from. This should be either a timestamp in milliseconds or a relative time such as "-1days" |
| To Time | string | yes |  | Timestamp to stop getting entries at. This should be either a timestamp in milliseconds or a relative time such as "now" |
| Access Token | secure_string |  |  | If you are using an integration-provided Umbrella target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated using the "Umbrella - Get Access Token" activity |
| Activity Type | string |  |  | The subset of activity to report on. If this is left blank, all activity will be included. Possible values (besides blank) include: dns, proxy, firewall, intrusion, ip, or amp-retrospective |
| Additional Parameters | string |  |  | Extra parameters that should be appended to the report request. These should be formatted as a query string. For example: "domains=test.com&ports=443&verdict=blocked" |
| Limit | integer |  | `100` | The maximum number of records to return |
| Offset | integer |  | `0` | The index of the initial entry to retrieve "limit" entries from. Offsets start at 0 |

| Output | Type | Description |
|---|---|---|
| Entry Count | integer | The number of entries returned by Umbrella |
| Report Data | string |  |

### Cisco Umbrella - Get Destination List Entries

Gets a list of entries for a given destination list in Cisco Umbrella. This atomic requires read permission to the "Policies / Destination Lists" API scope.

- Kind: read. Cisco workflow ID: `definition_workflow_0204H5ZVN0ZN256UTZ86ZRCflW6pqrVR62m`.
- Target: Umbrella integration target or HTTP Endpoint for "api.umbrella.com" with no path
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `GET /policies/v2/destinationlists/{var}/destinations?page={var}&limit={var}`, content type application/json, custom headers: {var}
- Reads from the response: `$.data`, `$.meta.total`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Destination List ID | string | yes |  | ID of the destination list to get entries for |
| Access Token | secure_string |  |  | If you are using an integration-provided Umbrella target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated using the "Umbrella - Get Access Token" activity |
| Limit | integer |  | `100` | The maximum number of records to return. The maximum records per page is 100 |
| Page | integer |  | `1` | Which page of records to fetch |

| Output | Type | Description |
|---|---|---|
| Destination List Entries | string |  |
| Total Records | integer | The total number of entries in the destination list |

### Cisco Umbrella - Get Destination List by ID

Gets a specific destination list's details from Cisco Umbrella. The list's details are available as output variables or the raw object's JSON is available in the Results output variable. This atomic requires read permission to the "Policies / Destination Lists" API scope.

- Kind: read. Cisco workflow ID: `definition_workflow_0291QVQ2NYC0A40HfV8CWY96Qp0AZKidPld`.
- Target: Umbrella integration target or HTTP Endpoint for "api.umbrella.com" with no path
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `GET /policies/v2/destinationlists/{var}`, content type application/json, custom headers: {var}
- Reads from the response: `$.data`, `$.data.organizationId`, `$.data.access`, `$.data.isGlobal`, `$.data.name`, `$.data.createdAt`, `$.data.modifiedAt`, `$.data.markedForDeletion`, `$.data.bundleTypeId`, `$.data.id`, `$.data.meta.destinationCount`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Destination List ID | string | yes |  | The ID of the destination list to fetch details for |
| Access Token | secure_string |  |  | If you are using an integration-provided Umbrella target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated using the "Umbrella - Get Access Token" activity |

| Output | Type | Description |
|---|---|---|
| Access Type | string | The type of access for the destination list. Valid values include: allow, block |
| Bundle Type ID | integer | The type of the Umbrella policy associated with the destination list. Set "1" for DNS policy or "2" for Web policy |
| Created At | integer | The timestamp of when the destination list was created |
| Destination Count | integer | How many destinations are in the list |
| Is Global | boolean | Whether the destination list is a global destination list. There is only one default destination list of type "allow" or "block" for each organization. As in, you can only have one "allow" global destination list and one "block" global destination list |
| Is Marked For Deletion | boolean | Whether the destination list is marked for deletion |
| List ID | string | ID of the destination list |
| Modified At | integer | The timestamp of when the destination list was last modified |
| Name | string | Name of the destination list |
| Organization ID | integer | Organization ID the destination list belongs to |
| Results | string |  |

### Cisco Umbrella - Get Destination Lists

Gets a list of destination lists from Cisco Umbrella. This atomic requires read permission to the "Policies / Destination Lists" API scope.

- Kind: read. Cisco workflow ID: `definition_workflow_021G2JXSFP4MX6uVCNN9ZBjhcjk8KvFt4D3`.
- Target: Umbrella integration target or HTTP Endpoint for "api.umbrella.com" with no path
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `GET /policies/v2/destinationlists?limit={var}&page={var}`, content type application/json, custom headers: {var}
- Reads from the response: `$.data`, `$.meta.total`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Access Token | secure_string |  |  | If you are using an integration-provided Umbrella target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated using the "Umbrella - Get Access Token" activity |
| Limit | integer |  | `100` | The maximum number of records to return |
| Page | integer |  | `1` | Which page of records to fetch |

| Output | Type | Description |
|---|---|---|
| Destination Lists | string |  |
| Total Records | integer | The total number of destination lists |

### Cisco Umbrella - Remove Destination from Destination List

Removes a destination from a destination list by its ID in Cisco Umbrella. This atomic requires read/write permission to the "Policies / Destination Lists" API scope.

- Kind: write. Cisco workflow ID: `definition_workflow_0204HD3DO3TP02NRrgTC7Uo5oVnHhlHXTd6`.
- Target: Umbrella integration target or HTTP Endpoint for "api.umbrella.com" with no path
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `DELETE /policies/v2/destinationlists/{var}/destinations/remove`, content type application/json, custom headers: {var}

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Destination ID | string | yes |  | The ID of the destination to be removed. This can be obtained by getting a destination list's destinations and looking for the record you want to remove |
| Destination List ID | string | yes |  | ID of the destination list to remove the record from |
| Access Token | secure_string |  |  | If you are using an integration-provided Umbrella target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated using the "Umbrella - Get Access Token" activity |

## Microsoft Defender for Endpoint

### Microsoft Defender for Endpoint - Add Tag to Machine

Adds a tag to a machine in Microsoft Defender for Endpoint. This atomic requires the following API permission: Machine.ReadWrite.All.

- Kind: write. Cisco workflow ID: `definition_workflow_029M5N00VETA63hIGXcIMRyuJPNiQfAdoQW`.
- Target: Microsoft Defender for Endpoint (Commercial or GCC) integration target or HTTP Endpoint for "api.securitycenter.microsoft.com" with no path
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `POST /machines/{var}/tags`, content type application/json, custom headers: {var}

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Machine ID | string | yes |  | ID of the machine to add the tag to |
| Tag Name | string | yes |  | Name of the tag to add to the machine |
| Access Token | secure_string |  |  | If you are using an integration-provided Microsoft Defender for Endpoint target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated with "Microsoft Security Center - Get Access Token" |

| Output | Type | Description |
|---|---|---|
| Result | string |  |

### Microsoft Defender for Endpoint - Block IOC

Submits an IOC to Microsoft Defender for Endpoint to be blocked, alerted, or allowed. This atomic requires the following API permission: Ti.ReadWrite.All.

- Kind: write. Cisco workflow ID: `definition_workflow_0262SI258TKRZ5tjZxEsZuO4DgsVJILOVzl`.
- Target: Microsoft Defender for Endpoint (Commercial or GCC) integration target or HTTP Endpoint for "api.securitycenter.microsoft.com" with no path
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `POST /indicators`, content type application/json, custom headers: {var}, Accept-Encoding

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Action | string | yes | `Block` | The action to take when the IOC is detected. Valid values include: Alert, Warn, Block, Audit, BlockAndRemediate, AlertAndBlock, and Allowed  Note: The "Generate Alert" variable must be set to "True" when creating an action with an "Audit" action |
| Access Token | secure_string |  |  | If you are using an integration-provided Microsoft Defender for Endpoint target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated with "Microsoft Security Center - Get Access Token" |
| Certificate Thumbprint | string |  |  | The thumbprint of the certificate to block |
| Description | string |  |  | A description of the indicator |
| Domain Name | string |  |  | The domain name to block |
| Generate Alert | boolean |  | `False` | Whether to generate an alert if the indicator is detected |
| IP Address | string |  |  | The single IP address (ipv4 or ipv6) to block |
| MD5 File Hash | string |  |  | The MD5 file hash to block |
| SHA1 File Hash | string |  |  | The SHA1 file hash to block |
| SHA256 File Hash | string |  |  | The SHA256 file hash to block |
| Title | string |  |  | Title for indicator alerts |
| URL | string |  |  | The URL to block |

| Output | Type | Description |
|---|---|---|
| Results | string | The results of the attempt to block the indicator |

### Microsoft Defender for Endpoint - Get List of IOCs

Fetches a list of indicators of compromise from Microsoft Defender for Endpoint. This atomic requires the following API permission: Ti.ReadWrite.All.

- Kind: read. Cisco workflow ID: `definition_workflow_0297NEJ47I99F0rHUQp36qXzfzoKi30ursr`.
- Target: Microsoft Defender for Endpoint (Commercial or GCC) integration target or HTTP Endpoint for "api.securitycenter.microsoft.com" with no path
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `GET /indicators?$top={var}&$skip={var}`, content type application/json, custom headers: {var}

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Access Token | secure_string |  |  | If you are using an integration-provided Microsoft Defender for Endpoint target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated with "Microsoft Security Center - Get Access Token" |
| Limit | integer |  | `100` | The maximum number of IOCs to return |
| Offset | integer |  | `0` | The index from which to start returning results. The default offset is 0 |

| Output | Type | Description |
|---|---|---|
| Results | string |  |

### Microsoft Defender for Endpoint - Get Machine CVEs

Fetches a list of CVEs applicable to the specified machine from Microsoft Defender for Endpoint. This atomic requires the following API permission: Vulnerability.Read.All.

- Kind: read. Cisco workflow ID: `definition_workflow_026DWA4N8OZ4I2ZNsLzBIjEJSHdLc8HTQ6H`.
- Target: Microsoft Defender for Endpoint (Commercial or GCC) integration target or HTTP Endpoint for "api.securitycenter.microsoft.com" with no path
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `GET /machines/{var}/vulnerabilities`, content type not set, custom headers: {var}, Accept-Encoding

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Machine ID | string | yes |  | ID of the machine to get CVEs for |
| Access Token | secure_string |  |  | If you are using an integration-provided Microsoft Defender for Endpoint target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated with "Microsoft Security Center - Get Access Token" |

| Output | Type | Description |
|---|---|---|
| Host Vulnerability Count | integer | The count of CVEs returned for the specified host |
| Results | string |  |

### Microsoft Defender for Endpoint - Get Machine by ID

Gets a machine by its ID from Microsoft Defender for Endpoint. This atomic requires the following API permission: Machine.ReadWrite.All.

- Kind: read. Cisco workflow ID: `definition_workflow_028X30XB07G5Q6QgVFK858m4gKRLj3By6KT`.
- Target: Microsoft Defender for Endpoint (Commercial or GCC) integration target or HTTP Endpoint for "api.securitycenter.microsoft.com" with no path
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `GET /machines/{var}`, content type not set, custom headers: {var}

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Machine ID | string | yes |  | ID of the machine to fetch |
| Access Token | secure_string |  |  | If you are using an integration-provided Microsoft Defender for Endpoint target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated with "Microsoft Security Center - Get Access Token" |

| Output | Type | Description |
|---|---|---|
| Results | string |  |

### Microsoft Defender for Endpoint - Isolate Machine

Isolates a host by machine ID in Microsoft Defender for Endpoint. This atomic requires the following API permission: Machine.Isolate.

- Kind: write. Cisco workflow ID: `definition_workflow_026FGMRTYGFCX0vfEeGsnuALHlPCGbjxDEX`.
- Target: Microsoft Defender for Endpoint (Commercial or GCC) integration target or HTTP Endpoint for "api.securitycenter.microsoft.com" with no path
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `POST /machines/{var}/isolate`, content type application/json, custom headers: {var}, Accept-Encoding

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Isolation Type | string | yes | `Full` | Must be "Full" or "Selective". Note that "Selective" allows certain application to run per the configured policy |
| Machine ID | string | yes |  | ID of the machine to isolate |
| Access Token | secure_string |  |  | If you are using an integration-provided Microsoft Defender for Endpoint target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated with "Microsoft Security Center - Get Access Token" |
| Comment | string |  | `Machine isolated by Cisco XDR` | A comment describing why the machine was isolated |

| Output | Type | Description |
|---|---|---|
| Results | string |  |

### Microsoft Defender for Endpoint - Release Machine from Isolation

Releases a machine from isolation in Microsoft Defender for Endpoint. This atomic requires the following API permission: Machine.Isolate.

- Kind: write. Cisco workflow ID: `definition_workflow_025XLL8PZL54C4Bmphw6YisLqNs9gTJ4uPS`.
- Target: Microsoft Defender for Endpoint (Commercial or GCC) integration target or HTTP Endpoint for "api.securitycenter.microsoft.com" with no path
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `POST /machines/{var}/unisolate`, content type application/json, custom headers: {var}, Accept-Encoding

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Machine ID | string | yes |  | ID of the machine to release from isolation |
| Access Token | secure_string |  |  | If you are using an integration-provided Microsoft Defender for Endpoint target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated with "Microsoft Security Center - Get Access Token" |
| Comment | string |  | `Machine isolated by Cisco XDR` | A comment describing why the machine was released from isolation |

| Output | Type | Description |
|---|---|---|
| Results | string |  |

### Microsoft Defender for Endpoint - Remove Tag from Machine

Removes a tag from a machine in Microsoft Defender for Endpoint. This atomic requires the following API permission: Machine.ReadWrite.All.

- Kind: write. Cisco workflow ID: `definition_workflow_029M6D1DR13FS1lo0Vf7Dl6sPa8ELiwGrLC`.
- Target: Microsoft Defender for Endpoint (Commercial or GCC) integration target or HTTP Endpoint for "api.securitycenter.microsoft.com" with no path
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `POST /machines/{var}/tags`, content type application/json, custom headers: {var}

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Machine ID | string | yes |  | ID of the machine to remove the tag from |
| Tag Name | string | yes |  | Name of the tag to remove from the machine |
| Access Token | secure_string |  |  | If you are using an integration-provided Microsoft Defender for Endpoint target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated with "Microsoft Security Center - Get Access Token" |

| Output | Type | Description |
|---|---|---|
| Result | string |  |

### Microsoft Defender for Endpoint - Run Antivirus Scan

Runs an antivirus scan using Microsoft Defender for Endpoint. This atomic requires the following API permission: Machine.Scan.

- Kind: write. Cisco workflow ID: `definition_workflow_0298P045NJVOW1nilCOCDeyW8o0narTrad2`.
- Target: Microsoft Defender for Endpoint (Commercial or GCC) integration target or HTTP Endpoint for "api.securitycenter.microsoft.com" with no path
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `POST /machines/{var}/runAntiVirusScan`, content type application/json, custom headers: {var}, Accept-Encoding

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Comment | string | yes | `Antivirus scan executed by a Cisco XDR automation workflow` | A comment describing why the antivirus scan was executed |
| Machine ID | string | yes |  | ID of the machine to execute an antivirus scan on |
| Scan Type | string | yes |  | The type of scan to execute. Valid values include: Quick, Full |
| Access Token | secure_string |  |  | If you are using an integration-provided Microsoft Defender for Endpoint target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated with "Microsoft Security Center - Get Access Token" |

| Output | Type | Description |
|---|---|---|
| Results | string |  |

### Microsoft Defender for Endpoint - Search Machines

Searches for machines in Microsoft Defender for Endpoint. If an IP address or DNS name are provided, the machines are filtered. If neither of those inputs are provided, all machines are returned. This atomic requires the following API permission: Ti.ReadWrite.All.

- Kind: read. Cisco workflow ID: `definition_workflow_026216Z9O2XLX1napr3HbRReBcm8H0cpHei`.
- Target: Microsoft Defender for Endpoint (Commercial or GCC) integration target or HTTP Endpoint for "api.securitycenter.microsoft.com" with no path
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `GET {var}`, content type not set, custom headers: {var}, Accept-Encoding
- Reads from the response: `$.value[0].id`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Access Token | secure_string |  |  | If you are using an integration-provided Microsoft Defender for Endpoint target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated with "Microsoft Security Center - Get Access Token" |
| DNS Name | string |  |  | DNS name of the machine to search for |
| Limit | integer |  | `100` | The maximum number of machines to return |
| Offset | integer |  | `0` | The index from which to start returning results. The default offset is 0 |
| Private IP Address | string |  |  | Internal IP address of the machine to search for |

| Output | Type | Description |
|---|---|---|
| First Machine ID | string | The ID of the first matching machine |
| Results | string |  |

### Microsoft Defender for Endpoint - Unblock IOC

Unblocks an IOC in Microsoft Defender for Endpoint. This atomic requires the following API permission: Ti.ReadWrite.All.

- Kind: write. Cisco workflow ID: `definition_workflow_0297OCCW0MGE95gXzpdg59P3mNr1nRMUXXa`.
- Target: Microsoft Defender for Endpoint (Commercial or GCC) integration target or HTTP Endpoint for "api.securitycenter.microsoft.com" with no path
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `DELETE /indicators/{var}`, content type application/json, custom headers: {var}, Accept-Encoding

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Indicator ID | string | yes |  | ID of the indicator to delete |
| Access Token | secure_string |  |  | If you are using an integration-provided Microsoft Defender for Endpoint target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated with "Microsoft Security Center - Get Access Token" |

## Microsoft Entra ID

### Microsoft Entra ID - Disable User

Disables a user in Microsoft Entra ID. This atomic requires one of the following API permissions depending on how you use it: User.ManageIdentities.All, User.EnableDisableAccount.All, User.ReadWrite.All, Directory.ReadWrite.All.

- Kind: write. Cisco workflow ID: `definition_workflow_02D8PMPKDFCTW2WJg5RYSEXbWmQNTQERIGh`.
- Target: Microsoft Entra ID or Microsoft Defender for Office 365 integration target or HTTP endpoint for "graph.microsoft.com"
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `PATCH /v1.0/users/{var}`, content type application/json, custom headers: {var}

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| User ID or Principal Name | string | yes |  | The ID or principal name of the user to disable |
| Access Token | secure_string |  |  | If you are using an integration-provided Microsoft Entra ID or Microsoft Defender for Office 365 target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated with "Microsoft Graph - Get Access Token" |

### Microsoft Entra ID - Enable User

Enables a user in Microsoft Entra ID. This atomic requires one of the following API permissions depending on how you use it: User.ManageIdentities.All, User.EnableDisableAccount.All, User.ReadWrite.All, Directory.ReadWrite.All.

- Kind: write. Cisco workflow ID: `definition_workflow_02D8PTEDE8V7I6P6YE3hztRx6sAyQT8ka5y`.
- Target: Microsoft Entra ID or Microsoft Defender for Office 365 integration target or HTTP endpoint for "graph.microsoft.com"
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `PATCH /v1.0/users/{var}`, content type application/json, custom headers: {var}

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| User ID or Principal Name | string | yes |  | The ID or principal name of the user to enable |
| Access Token | secure_string |  |  | If you are using an integration-provided Microsoft Entra ID or Microsoft Defender for Office 365 target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated with "Microsoft Graph - Get Access Token" |

### Microsoft Entra ID - Reset User Password

Resets a user's password in Microsoft Entra ID. This atomic requires the "User.ReadWrite.All" API permission and your Azure application must be assigned at least the "User Administrator" Microsoft Entra role. If you want to be able to reset passwords for administrative or privileged users, you may need different permissions.

- Kind: write. Cisco workflow ID: `definition_workflow_02D8QLC569F1J1bc9JS6uQqRSarDbJIe2O0`.
- Target: Microsoft Entra ID or Microsoft Defender for Office 365 integration target or HTTP endpoint for "graph.microsoft.com"
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `PATCH /v1.0/users/{var}`, content type application/json, custom headers: {var}

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| New Password | secure_string | yes |  | The new password to set for the user. The password must satisfy the minimum requirements specified by the organization's password policy |
| User ID or Principal Name | string | yes |  | The ID or principal name of the user to enable |
| Access Token | secure_string |  |  | If you are using an integration-provided Microsoft Entra ID or Microsoft Defender for Office 365 target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated with "Microsoft Graph - Get Access Token" |
| Force Password Change at Next Sign In | boolean |  | `True` | Whether to force the user to set a new password the next time they sign in. The best practice is to set this to true |
| Force Password Change with MFA at Next Sign In | boolean |  | `False` | Whether to force the user to perform a multi-factor authentication and set a new password the next time they sign in |

### Microsoft Entra ID - Search Users

Searches for users in Microsoft Entra ID. This atomic requires one of the following API permissions depending on how you use it: User.Read.All, User.ReadWrite.All, Directory.Read.All, Directory.ReadWrite.All.

- Kind: read. Cisco workflow ID: `definition_workflow_02DVL2ARY9WDT1YbG2mtYfr3l4u99G743xu`.
- Target: Microsoft Entra ID or Microsoft Defender for Office 365 integration target or HTTP endpoint for "graph.microsoft.com"
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `GET /v1.0/users/{var}`, content type application/json, custom headers: {var}, ConsistencyLevel
- Reads from the response: `$.value.length()`, `$.value`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Access Token | secure_string |  |  | If you are using an integration-provided Microsoft Entra ID or Microsoft Defender for Office 365 target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated with "Microsoft Graph - Get Access Token" |
| Email Address | string |  |  | An optional email address to search for. If a User Principal Name is provided, this input is ignored. If you provide this, any input in the sAM Account Name and Filters inputs will be ignored |
| Fields | string |  |  | An optional comma-separated list of fields to return. By default, this API will return the following fields: businessPhones, displayName, givenName, id, jobTitle, mail, mobilePhone, officeLocation, preferredLanguage, surname, and userPrincipalName. If you want a different set of fields, provide them using this variable |
| Filters | string |  |  | An optional ODATA query to use to filter the users returned. If you provide a sAM Account Name or User ID or Principle Name, this field is ignored. Note that search values within the filter string may need to be URL encoded. More information can be found here: https://learn.microsoft.com/en-us/graph/filter-query-parameter |
| Top | integer |  | `50` | Specifies the number of items to be included in the result. This is used for paging |
| User Principal Name | string |  |  | An optional user principal name to search for. If you provide this, any input in the sAM Account Name, Email Address, and Filters inputs will be ignored |
| sAM Account Name | string |  |  | An optional sAM account name to search for. If a User Principal Name or email address is provided, this input is ignored. If you provide this, any input in the Filters input will be ignored |

| Output | Type | Description |
|---|---|---|
| Record Count | integer |  |
| Users | string |  |

## Microsoft Intune

### Microsoft Intune - Get Managed Device by ID

Fetches a managed device from Microsoft Intune using its ID. This atomic requires one of the following Graph API scopes: DeviceManagementManagedDevices.Read.All, DeviceManagementManagedDevices.ReadWrite.All

- Kind: read. Cisco workflow ID: `definition_workflow_02GBGABB9ZXBN6OIRIaLDgJaVBOJBOU4pWF`.
- Target: Microsoft Intune integration target or HTTP endpoint for "graph.microsoft.com" with a path of "/v1.0/"
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `GET /deviceManagement/managedDevices/{var}`, content type application/json, custom headers: {var}
- Reads from the response: `$.deviceName`, `$.operatingSystem`, `$.osVersion`, `$.model`, `$.manufacturer`, `$.complianceState`, `$.isSupervised`, `$.isEncrypted`, `$.serialNumber`, `$.azureADDeviceId`, `$.userId`, `$.emailAddress`, `$.userPrincipalName`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Device ID | string | yes |  | The ID of the device to get details for |
| Access Token | secure_string |  |  | If you are using an integration-provided Microsoft Intune target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated with "Microsoft Graph - Get Access Token" |

| Output | Type | Description |
|---|---|---|
| Compliance State | string |  |
| Device Details | string |  |
| Device Name | string |  |
| Email Address | string |  |
| Entra Device ID | string |  |
| Is Encrypted | boolean |  |
| Is Supervised | boolean |  |
| Manufacturer | string |  |
| Model | string |  |
| Operating System | string |  |
| Operating System Version | string |  |
| Serial Number | string |  |
| User ID | string |  |
| User Principal Name | string |  |

### Microsoft Intune - Reboot Device

Reboots a device managed by Microsoft Intune. This atomic requires one of the following Graph API scopes: DeviceManagementManagedDevices.PrivilegedOperations.All

- Kind: write. Cisco workflow ID: `definition_workflow_02GFHN7GFBPZE1zBrzGCuqC53W3m2Td61ST`.
- Target: Microsoft Intune integration target or HTTP endpoint for "graph.microsoft.com" with a path of "/v1.0/"
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `POST /deviceManagement/managedDevices/{var}/rebootNow`, content type application/json, custom headers: {var}

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Device ID | string | yes |  | The ID of the device to reboot |
| Access Token | secure_string |  |  | If you are using an integration-provided Microsoft Intune target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated with "Microsoft Graph - Get Access Token" |

### Microsoft Intune - Reset Device Passcode

Resets the passcode for a device managed by Microsoft Intune. This atomic requires one of the following Graph API scopes: DeviceManagementManagedDevices.PrivilegedOperations.All

- Kind: write. Cisco workflow ID: `definition_workflow_02GES0WFNZ4NN0bBZT25rnoBkGTQzzQliSH`.
- Target: Microsoft Intune integration target or HTTP endpoint for "graph.microsoft.com" with a path of "/v1.0/"
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `POST /deviceManagement/managedDevices/{var}/resetPasscode`, content type application/json, custom headers: {var}

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Device ID | string | yes |  | The ID of the device to reset the passcode for |
| Access Token | secure_string |  |  | If you are using an integration-provided Microsoft Intune target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated with "Microsoft Graph - Get Access Token" |

### Microsoft Intune - Search Managed Devices

Searches for managed devices in Microsoft Intune. This atomic requires one of the following Graph API scopes: DeviceManagementManagedDevices.Read.All, DeviceManagementManagedDevices.ReadWrite.All

- Kind: read. Cisco workflow ID: `definition_workflow_02GB7ZHQNZXI26ENbMpvMdZYKi13MGB5CkQ`.
- Target: Microsoft Intune integration target or HTTP endpoint for "graph.microsoft.com" with a path of "/v1.0/"
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `GET /deviceManagement/managedDevices/{var}`, content type application/json, custom headers: {var}
- Reads from the response: `$.value.length()`, `$.value`

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Access Token | secure_string |  |  | If you are using an integration-provided Microsoft Intune target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated with "Microsoft Graph - Get Access Token" |
| Device Name | string |  |  | An optional device name to search for. Only provide a value for one of this atomic's filter inputs. Providing more than one will cause all except for one to be ignored |
| Email Address | string |  |  | An optional email address to search for. Only provide a value for one of this atomic's filter inputs. Providing more than one will cause all except for one to be ignored |
| Entra Device ID | string |  |  | An optional Entra device ID to search for. Only provide a value for one of this atomic's filter inputs. Providing more than one will cause all except for one to be ignored |
| Filters | string |  |  | An optional ODATA query to use to filter the devices returned. If you provide this, other filters are ignored. More information can be found here: https://learn.microsoft.com/en-us/graph/filter-query-parameter |
| IMEI | string |  |  | An optional IMEI to search for. Only provide a value for one of this atomic's filter inputs. Providing more than one will cause all except for one to be ignored |
| Phone Number | string |  |  | An optional phone number to search for. Only provide a value for one of this atomic's filter inputs. Providing more than one will cause all except for one to be ignored |
| Serial Number | string |  |  | An optional serial number to search for. Only provide a value for one of this atomic's filter inputs. Providing more than one will cause all except for one to be ignored |
| Top | integer |  | `50` | Specifies the number of items to be included in the result. This is used for paging |
| User Principal Name | string |  |  | An optional user principal name to search for. Only provide a value for one of this atomic's filter inputs. Providing more than one will cause all except for one to be ignored |

| Output | Type | Description |
|---|---|---|
| Devices | string |  |
| Record Count | integer |  |

### Microsoft Intune - Wipe Device

Wipes a device managed by Microsoft Intune. This atomic requires one of the following Graph API scopes: DeviceManagementManagedDevices.ReadWrite.All, DeviceManagementManagedDevices.PrivilegedOperations.All

- Kind: write. Cisco workflow ID: `definition_workflow_02GEROKQJWAXH1NRyx54ndECIkK30GqFZv6`.
- Target: Microsoft Intune integration target or HTTP endpoint for "graph.microsoft.com" with a path of "/v1.0/"
- Account key: None if using an integration-provided target, access token if using an HTTP Endpoint target
- Request: `POST /deviceManagement/managedDevices/{var}/wipe`, content type application/json, custom headers: {var}

| Input | Type | Required | Default | Description |
|---|---|---|---|---|
| Device ID | string | yes |  | The ID of the device to wipe |
| Access Token | secure_string |  |  | If you are using an integration-provided Microsoft Intune target, this is not required. If you are using your own HTTP Endpoint target, this should be an access token generated with "Microsoft Graph - Get Access Token" |
| Keep Enrollment Data | boolean |  | `False` | Whether to keep the device's enrollment data intact after the wipe |
| Keep User Data | boolean |  | `False` | Whether to keep the user's data intact after the wipe |
| Obliteration Behavior | string |  |  | For macOS devices, you can specify the type of wipe that is executed. Valid values include:  default - If Erase All Content and Settings (EACS) preflight fails, the device responds to the server with an Error status and then attempts to erase itself. If EACS preflight succeeds but EACS fails, then the device attempts to erase itself.  doNotObliterate - If Erase All Content and Settings (EACS) preflight fails, the device responds to the server with an Error status and doesn’t attempt to erase itself. If EACS preflight succeeds but EACS fails, then the device doesn’t attempt to erase itself.  obliterateWithWarning - If Erase All Content and Settings (EACS) preflight fails, the device responds with an Acknowledged status and then attempts to erase itself. If EACS preflight succeeds but EACS fails, then the device attempts to erase itself.  always - The system doesn’t attempt Erase All Content and Settings (EACS). T2 and later devices always obliterate. |
| Persist eSIM Data Plan | boolean |  | `False` | Whether to keep the device's eSIM intact after the wipe |
| macOS Unlock Code | string |  |  | For macOS devices, you can specify an unlock code that will be required after the wipe is complete. This should be a 6 digit number |


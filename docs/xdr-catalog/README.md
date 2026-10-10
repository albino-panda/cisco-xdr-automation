# Cisco XDR catalog

Source: the public Cisco XDR Connect catalog, <https://connect.xdr.security.cisco.com>, read on 2026-10-10.
Machine-readable copy of everything read: [catalog.json](catalog.json). It lists all 107 integrations, the 579
Cisco-managed atomics with their group and workflow ID, the 21 built-in workflows and the 176 installable
workflows. To find the atomics of one integration, filter `atomics` in `catalog.json` by `group`.

The catalog publishes the workflow ID of every Cisco-managed atomic and built-in workflow. It does **not** publish
their input and output variables. A call needs the input variable IDs, so those still come from an export of the
org.

`Kind` is a guess from the verb in the name. Check it before treating an atomic as read-only.

## Platform atomics

Always available. The target is an XDR system target.

**`Cisco XDR: Incident`**

| Atomic | Kind | Workflow ID |
|---|---|---|
| XDR - Incident - Add Note to Incident | write | `definition_workflow_024S5ENDCK1LP5V2CLbAh3WWV20RHOHieks` |
| XDR - Incident - Create Incident | write | `definition_workflow_02E7JHID4LM1X7XL7fEe2ZJLJMH3aM86MbU` |
| XDR - Incident - Get Incident Events | read | `definition_workflow_0292TG7F1CM930K8LhMgUcyo3BCLETwJp0X` |
| XDR - Incident - Get Incident Events (v2) | read | `definition_workflow_02IBG43HC0TZ76djBBrravRu0r09WD8ASnh` |
| XDR - Incident - Get Incident Indicators | read | `definition_workflow_02HD5Y3QW0XB47f0fJZnBDIBmVir6vrZWIr` |
| XDR - Incident - Get Incident Observables | read | `definition_workflow_02CDPGVLJBD5O7ga4bNwx4tZf9nzEV1DukC` |
| XDR - Incident - Get Incident Summary | read | `definition_workflow_027AD9BEHAPW12Ni11mC30lzTcivc01mVT9` |
| XDR - Incident - Get Incident Summary (v2) | read | `definition_workflow_02CEHFNKNGAKM3l9hTjDAI25RifYgzOwYCA` |
| XDR - Incident - Get Incident Targets | read | `definition_workflow_02CDQR7HGM7860ox0CSsx3DerZJQ2EUQox9` |
| XDR - Incident - Link Object | write | `definition_workflow_02E6KP4WL9DTX5uxh14ryljH9zdQwAn4CrM` |
| XDR - Incident - Search Incidents | read | `definition_workflow_029WDE553NH5R1kxFiEeFTOLtKJ71Oxy7Ic` |
| XDR - Incident - Update Properties | write | `definition_workflow_02A36UUYBZLG05NQrmoenWp6IoVvQRK64dJ` |

**`Cisco XDR: Investigate`**

| Atomic | Kind | Workflow ID |
|---|---|---|
| XDR - Investigate - Create Investigation | write | `definition_workflow_02E6L77SRA2I83cArClmRrkQwKxyJUnOO9e` |
| XDR - Investigate - Deliberate Observable | read | `definition_workflow_02980SHNWHYLV0YBGwuL5MSYWxTlqQ0GmqR` |
| XDR - Investigate - Deliberate Observables | read | `definition_workflow_029824AN9OC6K34kBzqjL6SXC0s68449YGU` |
| XDR - Investigate - Enrich Observables | read | `definition_workflow_02980I2B9SID06CCgGlxbAfCAwysn47Ycv2` |
| XDR - Investigate - Get Investigation Assets | read | `definition_workflow_02E7HLVQ87S090q1i1rkAoji29SP3RZBEfl` |
| XDR - Investigate - Get Investigation Events | read | `definition_workflow_02FNFKHBZYTRB3WM0ju9DJhn6uTNEP5U78w` |
| XDR - Investigate - Get Investigation Indicators | read | `definition_workflow_02E7HUIWAWE9M30PqMIWlVGhYnIaTNgIfHZ` |
| XDR - Investigate - Get Investigation Overview | read | `definition_workflow_02E7HWZ5HVYQ94qFfqbQkfSAFBjPiG8mxPb` |
| XDR - Investigate - Get Investigation Status | read | `definition_workflow_02E6MXNQZPIFW1sFl4RtMWomZTiLfgjL8AH` |
| XDR - Investigate - Get Investigation Summary | read | `definition_workflow_02FNFJW7YOERI239VGeuEjljH6uwtOEt5bM` |
| XDR - Investigate - Inspect for Observables | read | `definition_workflow_02980B3RBSZKW79VceNvjWK4fM7B9y2CHeW` |

**`Cisco XDR: Respond`**

| Atomic | Kind | Workflow ID |
|---|---|---|
| XDR - Respond - List Response Actions | read | `definition_workflow_02982SD4ESZ490JzE3VMckLQFDPIjVKtWzn` |
| XDR - Respond - Trigger Response Action | write | `definition_workflow_02982SMGNIQ690vJEzCaD4fzBqkEcbGky8P` |

**`Cisco XDR: Intelligence`**

| Atomic | Kind | Workflow ID |
|---|---|---|
| XDR - Intelligence - Create Feed | write | `definition_workflow_029WDJLZVEO175XLJRbMnD6zWDtkj0b3FPY` |
| XDR - Intelligence - Create Indicator | write | `definition_workflow_029WC38FN220K5oog8uHMvaHoTD6AbMODNy` |
| XDR - Intelligence - Create Judgement | write | `definition_workflow_029M734BM86A80RqX6DtRR1dJbBEZM9ZCsy` |
| XDR - Intelligence - Create Relationship | write | `definition_workflow_029M9CG20F96U0MhkFWb8AoX2XocZ5sUeqp` |
| XDR - Intelligence - Create Sighting | write | `definition_workflow_029JQBDVBIUDD2nYaGAJyzQlXpNiETfF0NY` |
| XDR - Intelligence - Delete Relationship | write | `definition_workflow_029WI7BOS6GMV1T8sMmmG8RL7at9OrXV1iJ` |
| XDR - Intelligence - Expire Judgement | write | `definition_workflow_02N9Y530BCSLI0uaiN0zmJkymjBvsGOKioV` |
| XDR - Intelligence - Get Feed Contents | read | `definition_workflow_02M0XKMHJLKEC1eEPvzlPxhMaxSYRrpj8oP` |
| XDR - Intelligence - Search Feeds | read | `definition_workflow_029WBI3IBHBSF7kXqPSbwxIvFPFIwxSP0oJ` |
| XDR - Intelligence - Search Indicators | read | `definition_workflow_029WC4RHD5HRH7a0ZtcZpfB8bNyUn0NPV37` |
| XDR - Intelligence - Search Judgements | read | `definition_workflow_02NASXE9J2VXX5nxWf9nY5fUtTpGPPDta69` |
| XDR - Intelligence - Search Relationships | read | `definition_workflow_029L7QJS28F1Z0uLpbVRLDyS2NQKegPLUeU` |
| XDR - Intelligence - Search Sightings | read | `definition_workflow_02A36ZIEFF0O23n4wnkYPRaW5iQtWqzJrah` |

**`Cisco XDR: Assets`**

| Atomic | Kind | Workflow ID |
|---|---|---|
| XDR - Assets - Add Labels to Devices | write | `definition_workflow_02GKAPPEKELPY2NgavkxMh3UgZw3y3iRWMU` |
| XDR - Assets - Get Device Label by ID | read | `definition_workflow_02GQGAC4R7AXV5bENHuBBdwMH4CJyxlFZUC` |
| XDR - Assets - Get Device Label by Name | read | `definition_workflow_02GQFSPRJ5GF44zV7zUax8xzohSg3orJzrd` |
| XDR - Assets - Get Device Labels | read | `definition_workflow_02GK9MOJJCGEU6Bz6Hj7GZOZFFg4H7HvdWN` |
| XDR - Assets - Get Device by ID | read | `definition_workflow_02GIYOSH0BFHX0wfkKnpHeR8oVFbgwiNpGH` |
| XDR - Assets - Get Devices | read | `definition_workflow_02GNM58OEU2XF56YtYrDFRmO0wfQiGQ2joG` |
| XDR - Assets - Remove Labels from Devices | write | `definition_workflow_02GKBE2N0TEHP0EcGIixjWSNSZeynLOmURz` |
| XDR - Assets - Set Device Values | write | `definition_workflow_02GMTOSS8218T4WwFHmEzMCk1gzc69tkvx9` |

**`Cisco XDR: Analytics`**

| Atomic | Kind | Workflow ID |
|---|---|---|
| XDR - Analytics - Execute OCSF Query | read | `definition_workflow_02L77PWR0FPCR3vUzJNC4dID3Nfl7PHsjBB` |
| XDR - Analytics - Get Events by Finding ID | read | `definition_workflow_02VDYNIR8BF2W3AQ80o8xAF55pNa9PpcaH0` |
| XDR - Analytics - Get Findings by Detection ID | read | `definition_workflow_02VEO91SHIWW24pm0lDcIEkRxDOWdz4UPXl` |
| XDR - Analytics - Ingest Authentication Event | write | `definition_workflow_02T36LCXU99MR5waeJNYAAEhbhB3tVyxTyw` |
| XDR - Analytics - Ingest Email Security Event | write | `definition_workflow_02OXQQDJA63J37ME6qqjbxqcl5FdhY6DUW2` |
| XDR - Analytics - Ingest Network Security Event | write | `definition_workflow_02ONBB7XCI4261U8fLuzUFS6VrVj29egTKs` |
| XDR - Analytics - Search Detections | read | `definition_workflow_02VEO99GU7C2L2J5n3gdYC9OyNgCFuPFAks` |
| XDR - Analytics - Search Findings | read | `definition_workflow_02VD75F3GPE495sm3wbnwUYKlDsRPfUVBq2` |

**`Cisco XDR: Automate`**

| Atomic | Kind | Workflow ID |
|---|---|---|
| XDR - Automate - Get Account Keys | read | `definition_workflow_02A0OONGKX8TD5a91stOkoMbgesdLjWy7qn` |
| XDR - Automate - Get Target by ID | read | `definition_workflow_02GD192DCTKSA7EzwDBSKxHREiWIQE87Oat` |
| XDR - Automate - Get Targets | read | `definition_workflow_024G3LUCJX64J6lCoOFPo4S6zQwXrV7BrMJ` |

**`Cisco XDR: Administration`**

| Atomic | Kind | Workflow ID |
|---|---|---|
| XDR - Administration - Create Notification | write | `definition_workflow_02HE732Y0IOJV0OEpjjd5kYfqpOZzz0xdLK` |
| XDR - Administration - Get Integration Instance by ID | read | `definition_workflow_02GD1P2Z37N8L2pyqBI2H6H7CGXsYigTnTU` |
| XDR - Administration - Get Integration Instances | read | `definition_workflow_02HSRQ9SJD8SX2olZihv5ICOd5MggSxVfUD` |
| XDR - Administration - Get Integration Types | read | `definition_workflow_02LATH3KKXKKM1zMqAL6BmEgibbj0XH4WvA` |
| XDR - Administration - Search Users | read | `definition_workflow_02A4L4VLP16HE13951udl2tEh7MHp7eoSDV` |

## Built-in workflows

| Workflow | Workflow ID | Ends unless started from a playbook task |
|---|---|---|
| XDR - Automation Rule - Update Incident Properties | `definition_workflow_02A4LFR9RXU820svPYpSMRjCxrVHNW0whG1` | not stated |
| XDR - Close and Export Incident | `definition_workflow_02GCOE7I4SJQC2sBekgsBoNtF8fFrwQKEVD` | yes |
| XDR - Confirm Incident | `definition_workflow_02CQ5IQM1VXZ942BUiEFPeAO5bPJU4sbZEr` | not stated |
| XDR - Contain Incident: Assets | `definition_workflow_023KVFX7H9O0Z1OfA9nqcQ3SLNoWyX8wtC9` | yes |
| XDR - Contain Incident: Domains | `definition_workflow_02496ZJNYJTVH5RB6ApAFfhBXeMsBwFD8LJ` | yes |
| XDR - Contain Incident: File Hashes | `definition_workflow_02496WI0X35LS4ip2r8y2QX22QopbFkl1Mu` | yes |
| XDR - Contain Incident: IP Addresses | `definition_workflow_02H6J8Y3VEYI25M2sCttLPtzkj6okiUOqUP` | yes |
| XDR - Contain Incident: Quarantine Email Messages | `definition_workflow_02HAXDPKWTZLJ4B62R29dwqxRU0Ga6YDg59` | yes |
| XDR - Contain Incident: URLs | `definition_workflow_02496XABHMBZ75DaCPtklc3x4ukTuRY9qEy` | yes |
| XDR - Contain Incident: Users | `definition_workflow_02F1YU0UM2GNS7G6xIckld1U02w2k4wboWE` | yes |
| XDR - Delete Email Messages | `definition_workflow_02HSYPWMHBBBD4e4CRD4ok4mhbHV8Vpj1Hl` | yes |
| XDR - Document and Notify | `definition_workflow_023T9M23J5IG47DbtfY2mAlS1shySuVO6rj` | not stated |
| XDR - Identify Vulnerabilities | `definition_workflow_02496VK5MLHMO3QYa6BXP8o9cNswXHoSayI` | yes |
| XDR - Release Email Messages from Quarantine | `definition_workflow_02HWFMFXOIZHP6CclavYPOrk5H06QS8sMEH` | yes |
| XDR - Restore Domains | `definition_workflow_02NLUFGR5YCCX3mAsDxW3vgzRD9i4RX0bWi` | yes |
| XDR - Restore File Hashes | `definition_workflow_02NYM1LB9PO4975SKltt2fpNe2zsG19E5O0` | yes |
| XDR - Restore IP Addresses | `definition_workflow_02NHJTFUSPIHR6HzXyzy3xgw0sKXeiflaSn` | yes |
| XDR - Restore Systems | `definition_workflow_0245TUQETEDQ07HIq1IzeEzAluJTi7uOz87` | yes |
| XDR - Restore URLs | `definition_workflow_02NLZ7S3O17WG43PWdn0zJheYPqfll0933E` | yes |
| XDR - Restore Users | `definition_workflow_02F1ZBLQJEOKI5Dk7lejNwlRtcesZeX9p40` | yes |
| XDR - Validate or Create Intelligence Feed | `definition_workflow_02HBSJLACUKS75QznDTTBi50u6Hwnm2cs9i` | not stated |


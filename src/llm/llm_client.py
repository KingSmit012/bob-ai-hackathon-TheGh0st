"""
llm/llm_client.py — LLM client abstraction for watsonx.ai and Anthropic.

This module provides a simple interface to call an LLM for text generation.
It supports two providers:

  1. IBM watsonx.ai (PRIMARY) — uses the ibm-watsonx-ai Python SDK
  2. Anthropic Claude  (FALLBACK) — uses the anthropic Python SDK

A factory function get_llm_client() reads the LLM_PROVIDER env var and
returns the right client. All clients expose the same .generate(prompt)
method, so the rest of the codebase doesn't need to know which provider
is being used.

DESIGN DECISION: We use a simple class hierarchy (not a complex plugin
system) because we only have two providers and this is a hackathon.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    LLM_PROVIDER,
    WATSONX_API_KEY, WATSONX_PROJECT_ID, WATSONX_URL, WATSONX_MODEL_ID,
    ANTHROPIC_API_KEY, ANTHROPIC_MODEL,
    LLM_MAX_TOKENS, LLM_TEMPERATURE,
)


class LLMClient:
    """
    Base class for LLM clients. Subclasses must implement generate().
    """

    def generate(self, prompt: str) -> str:
        """
        Send a prompt to the LLM and return the generated text.

        Args:
            prompt: The full prompt string (including any system instructions)

        Returns:
            The LLM's response as a plain string.
        """
        raise NotImplementedError("Subclasses must implement generate()")


class WatsonxClient(LLMClient):
    """
    IBM watsonx.ai client using the ibm-watsonx-ai SDK.

    This is the primary LLM provider for the hackathon since the Bob AI
    Hackathon values IBM technology integration.

    Requires environment variables:
        WATSONX_API_KEY     — Your IBM Cloud API key
        WATSONX_PROJECT_ID  — Your watsonx.ai project ID
        WATSONX_URL         — The watsonx.ai endpoint URL
    """

    def __init__(self):
        """Initialise the watsonx.ai client and model."""
        try:
            from ibm_watsonx_ai.foundation_models import ModelInference
            from ibm_watsonx_ai import Credentials
        except ImportError:
            raise ImportError(
                "ibm-watsonx-ai package not installed. "
                "Run: pip install ibm-watsonx-ai"
            )

        if not WATSONX_API_KEY:
            raise ValueError(
                "WATSONX_API_KEY not set. Add it to your .env file."
            )
        if not WATSONX_PROJECT_ID:
            raise ValueError(
                "WATSONX_PROJECT_ID not set. Add it to your .env file."
            )

        # Set up credentials
        credentials = Credentials(
            url=WATSONX_URL,
            api_key=WATSONX_API_KEY,
        )

        # Configure generation parameters
        self.gen_params = {
            "max_new_tokens": LLM_MAX_TOKENS,
            "temperature": LLM_TEMPERATURE,
            "top_p": 0.95,
            "repetition_penalty": 1.05,
        }

        # Initialise the model
        self.model = ModelInference(
            model_id=WATSONX_MODEL_ID,
            credentials=credentials,
            project_id=WATSONX_PROJECT_ID,
            params=self.gen_params,
        )

        print(f"[LLM] Initialised watsonx.ai client (model: {WATSONX_MODEL_ID})")

    def generate(self, prompt: str) -> str:
        """Send a prompt to watsonx.ai and return the response."""
        try:
            response = self.model.generate_text(prompt=prompt)
            return response.strip()
        except Exception as e:
            print(f"[LLM] watsonx.ai error: {e}")
            return f"ERROR: LLM generation failed — {e}"


class AnthropicClient(LLMClient):
    """
    Anthropic Claude client (fallback provider).

    Useful for development/testing when you don't have watsonx.ai access.

    Requires environment variable:
        ANTHROPIC_API_KEY — Your Anthropic API key
    """

    def __init__(self):
        """Initialise the Anthropic client."""
        try:
            import anthropic
        except ImportError:
            raise ImportError(
                "anthropic package not installed. Run: pip install anthropic"
            )

        if not ANTHROPIC_API_KEY:
            raise ValueError(
                "ANTHROPIC_API_KEY not set. Add it to your .env file."
            )

        self.client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        self.model = ANTHROPIC_MODEL
        print(f"[LLM] Initialised Anthropic client (model: {self.model})")

    def generate(self, prompt: str) -> str:
        """Send a prompt to Anthropic Claude and return the response."""
        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=LLM_MAX_TOKENS,
                messages=[
                    {"role": "user", "content": prompt}
                ],
            )
            # Anthropic returns a list of content blocks; get the text
            return message.content[0].text.strip()
        except Exception as e:
            print(f"[LLM] Anthropic error: {e}")
            return f"ERROR: LLM generation failed - {e}"


class MockLLMClient(LLMClient):
    """
    Mock LLM client for demo/testing when no API credits are available.

    Analyses the prompt content (keywords, severity, alert types) to
    generate plausible responses. This is NOT a real LLM — it uses
    simple pattern matching to produce structured output that looks
    like what a real LLM would return.

    Set LLM_PROVIDER=mock in .env to use this.
    """

    def __init__(self):
        print("[LLM] Initialised Mock LLM client (offline demo mode)")

    def generate(self, prompt: str) -> str:
        """Analyse the prompt and return a context-appropriate response."""
        prompt_lower = prompt.lower()

        # ── CLASSIFICATION PROMPTS ──
        if '"classification"' in prompt_lower and "genuine_threat" in prompt_lower:
            return self._classify(prompt_lower)

        # ── MITRE MAPPING PROMPTS ──
        if "mitre att&ck" in prompt_lower and "technique_id" in prompt_lower:
            return self._mitre_map(prompt_lower)

        # ── BLUF GENERATION PROMPTS ──
        if "bluf" in prompt_lower or "bottom line up front" in prompt_lower:
            return self._generate_bluf(prompt_lower)

        # Generic fallback
        return '{"classification": "genuine_threat", "confidence": 50, "reasoning": "Unable to determine — mock mode."}'

    def _classify(self, prompt: str) -> str:
        """Generate a classification response based on alert content."""
        import json

        # Check for genuine threat indicators
        is_brute = "brute" in prompt or ("ssh" in prompt and "failed" in prompt and "successful" in prompt)
        is_scan_exploit = "port_scan" in prompt and ("sql_injection" in prompt or "command_injection" in prompt or "exploit" in prompt)
        is_phishing = "phishing" in prompt or "credential_harvest" in prompt or "spearphishing" in prompt
        is_lateral = "lateral" in prompt or "exfiltration" in prompt or "unusual_internal" in prompt
        is_c2 = "beacon" in prompt or "c2" in prompt or "command and control" in prompt
        is_unusual_login = "unusual_login" in prompt or "privilege_escalation" in prompt

        # Check for false positive indicators
        is_scanner = "vulnerability_scan" in prompt or "authorised scanner" in prompt or "nessus" in prompt
        is_update = "windows update" in prompt or "windowsupdate" in prompt or "software update" in prompt
        is_routine = ("backup" in prompt and "completed" in prompt) or "certificate_renewal" in prompt or "zone_transfer" in prompt
        is_benign_block = "default-deny" in prompt and "routine" in prompt
        is_single_fail = "single_failed_login" in prompt and "no subsequent" in prompt
        is_info = any(kw in prompt for kw in ["eicar", "usb_device", "software_installation", "spam_filter", "group_policy", "cache_cleared", "vpn_session_expired"])

        if is_brute:
            return json.dumps({"classification": "genuine_threat", "confidence": 95,
                "reasoning": "Multiple failed SSH login attempts followed by a successful login from the same external IP indicates a successful brute-force attack. The source IP is flagged in threat intelligence as a known SSH brute-force botnet node."})
        elif is_scan_exploit:
            return json.dumps({"classification": "genuine_threat", "confidence": 92,
                "reasoning": "Sequential port scan followed by targeted SQL injection and command injection attempts indicates a multi-stage attack. The attacker performed reconnaissance then moved to active exploitation of the web server."})
        elif is_phishing and is_unusual_login:
            return json.dumps({"classification": "genuine_threat", "confidence": 94,
                "reasoning": "Phishing email campaign targeted multiple users, one clicked the malicious link and submitted credentials. Subsequently, the compromised account was used to login from an anomalous location (Russia) and attempted privilege escalation on the domain controller."})
        elif is_phishing:
            return json.dumps({"classification": "genuine_threat", "confidence": 85,
                "reasoning": "Coordinated phishing email campaign targeting multiple workstations with malicious links to credential harvesting infrastructure. SPF and DKIM failures confirm spoofed sender. Domain registered recently matches known phishing kit patterns."})
        elif is_lateral or is_c2:
            return json.dumps({"classification": "genuine_threat", "confidence": 96,
                "reasoning": "Compromised workstation exhibiting lateral movement to internal file, database, and backup servers, followed by large outbound data transfer to an unknown external IP. Periodic C2 beacon pattern detected with consistent intervals and packet sizes characteristic of Cobalt Strike."})
        elif is_unusual_login:
            return json.dumps({"classification": "genuine_threat", "confidence": 90,
                "reasoning": "Login from anomalous geographic location (Russia) using credentials of a user targeted by phishing. Subsequent privilege escalation attempt to Domain Admins group confirms malicious intent."})
        elif is_scanner:
            return json.dumps({"classification": "false_positive", "confidence": 95,
                "reasoning": "All alerts originate from the authorised vulnerability scanner (10.0.4.100, Nessus Professional) during a scheduled weekly scan. Port probing and service enumeration are expected behavior for this asset."})
        elif is_update:
            return json.dumps({"classification": "false_positive", "confidence": 92,
                "reasoning": "High DNS query volume directed at windowsupdate.microsoft.com and related Microsoft domains is consistent with a routine Windows Update download cycle. No indicators of DNS tunneling or exfiltration."})
        elif is_routine or is_info:
            return json.dumps({"classification": "false_positive", "confidence": 90,
                "reasoning": "This is a routine operational event (backup completion, certificate renewal, policy update, or informational log entry) with no security impact. Standard system maintenance activity."})
        elif is_benign_block:
            return json.dumps({"classification": "false_positive", "confidence": 88,
                "reasoning": "Firewall blocked connection due to default-deny rule. Source is an internal IP attempting to reach a service outside its allowed subnet. This is routine traffic from misconfigured clients, not an attack."})
        elif is_single_fail:
            return json.dumps({"classification": "false_positive", "confidence": 85,
                "reasoning": "A single failed authentication attempt with no follow-up suggests a typo, misconfigured client, or low-volume automated probe. No pattern of persistence or escalation."})
        else:
            # Default: check severity and alert count for educated guess
            if "critical" in prompt:
                return json.dumps({"classification": "genuine_threat", "confidence": 70,
                    "reasoning": "Critical severity alerts detected with patterns warranting further investigation. Multiple indicators suggest potential malicious activity."})
            elif "high" in prompt:
                return json.dumps({"classification": "genuine_threat", "confidence": 60,
                    "reasoning": "High severity alerts detected. While not conclusively malicious, the alert pattern warrants investigation and monitoring."})
            else:
                return json.dumps({"classification": "false_positive", "confidence": 65,
                    "reasoning": "Low severity operational alerts with no indicators of compromise. Appears to be normal network activity or routine system events."})

    def _mitre_map(self, prompt: str) -> str:
        """Generate MITRE ATT&CK mappings based on alert context."""
        import json
        techniques = []

        if "brute" in prompt or ("ssh" in prompt and "failed" in prompt):
            techniques.append({"technique_id": "T1110", "name": "Brute Force", "tactic": "Credential Access",
                "relevance": "Multiple failed SSH login attempts from a single IP indicate password brute-forcing."})
            techniques.append({"technique_id": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access",
                "relevance": "Systematic password guessing against SSH service with sequential attempts."})
            if "successful" in prompt:
                techniques.append({"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access",
                    "relevance": "Successful login after brute force indicates compromised valid account credentials."})

        if "port_scan" in prompt or "network_scan" in prompt:
            techniques.append({"technique_id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery",
                "relevance": "Sequential port scanning to identify running services on the target host."})
            techniques.append({"technique_id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance",
                "relevance": "Active reconnaissance of the target network to map attack surface."})

        if "sql_injection" in prompt or "command_injection" in prompt or "exploit" in prompt:
            techniques.append({"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access",
                "relevance": "SQL injection and command injection attempts against the web application to gain unauthorized access."})

        if "phishing" in prompt:
            techniques.append({"technique_id": "T1566", "name": "Phishing", "tactic": "Initial Access",
                "relevance": "Phishing emails sent to multiple targets with malicious links for credential harvesting."})
            techniques.append({"technique_id": "T1566.002", "name": "Phishing: Spearphishing Link", "tactic": "Initial Access",
                "relevance": "Emails contained links to credential harvesting pages hosted on attacker infrastructure."})

        if "unusual_login" in prompt or "privilege_escalation" in prompt:
            techniques.append({"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access",
                "relevance": "Compromised credentials used to authenticate from an anomalous location."})
            if "privilege_escalation" in prompt or "domain admin" in prompt:
                techniques.append({"technique_id": "T1098", "name": "Account Manipulation", "tactic": "Persistence, Privilege Escalation",
                    "relevance": "Attempt to add compromised account to Domain Admins group for privilege escalation."})

        if "lateral" in prompt or "unusual_internal" in prompt:
            techniques.append({"technique_id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement",
                "relevance": "Compromised workstation accessing multiple internal servers it has no historical baseline for."})

        if "exfiltration" in prompt or "large_data_transfer" in prompt or "suspicious_outbound" in prompt:
            techniques.append({"technique_id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration",
                "relevance": "Large data transfer to external IP via HTTPS after collecting data from internal file servers."})

        if "beacon" in prompt or "c2" in prompt:
            techniques.append({"technique_id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control",
                "relevance": "Periodic HTTPS callbacks with consistent interval and packet size indicate C2 beaconing."})
            techniques.append({"technique_id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control",
                "relevance": "C2 channel likely used to download additional tools or receive commands from the attacker."})

        if "dns" in prompt and ("tunnel" in prompt or "suspicious_dns" in prompt or "dga" in prompt):
            techniques.append({"technique_id": "T1071.004", "name": "Application Layer Protocol: DNS", "tactic": "Command and Control",
                "relevance": "Suspicious DNS queries to recently registered domain with DGA-like patterns suggest DNS-based C2."})

        if "vulnerability_scan" in prompt or "nessus" in prompt:
            techniques.append({"technique_id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance",
                "relevance": "Authorised vulnerability scanning - legitimate security assessment activity, not an attack."})

        return json.dumps(techniques[:5])  # Cap at 5 techniques

    def _generate_bluf(self, prompt: str) -> str:
        """Generate a BLUF summary based on incident context."""

        # Check more specific patterns FIRST (lateral/C2/exfil contain keywords
        # from earlier attack phases, so they must be matched before brute force)

        if ("exfiltration" in prompt or "lateral" in prompt) and ("beacon" in prompt or "c2" in prompt):
            return """BOTTOM LINE: Active data breach in progress from compromised WORKSTATION-042. Attacker accessed FILE-SERVER-01, DB-SERVER-01, and BACKUP-SERVER-01, collected 2.3 GB of data, and exfiltrated 1.8 GB to external IP 104.21.45.67. C2 beacons to Cobalt Strike server confirm persistent remote control. Full kill chain observed.

SUPPORTING DETAIL:
- WORKSTATION-042 (Finance dept, compromised via phishing) made first-time connections to 3 internal servers
- 2.3 GB downloaded from FILE-SERVER-01 (normal baseline: < 50 MB/day) indicating bulk data collection
- 1.8 GB outbound HTTPS transfer to external IP 104.21.45.67 (Cloudflare, unknown domain)
- 8 periodic C2 beacons to 185.220.101.34 (confirmed Cobalt Strike server, threat group FIN7)
- SIEM correlated full kill chain: Initial Access -> Credential Access -> Lateral Movement -> Collection -> Exfiltration

MITRE ATT&CK: T1021 - Remote Services, T1048 - Exfiltration Over Alternative Protocol, T1071.001 - Web Protocols C2

RECOMMENDED ACTION:
- Immediately isolate WORKSTATION-042 from the network (preserve forensic evidence)
- Block outbound connections to 104.21.45.67 and 185.220.101.34 at the firewall
- Identify and classify the exfiltrated data — engage legal/compliance if sensitive data was involved
- Conduct full forensic analysis to identify all implants and persistence mechanisms"""

        elif "exfiltration" in prompt or ("lateral" in prompt and "unusual_internal" in prompt):
            return """BOTTOM LINE: Active data breach in progress from compromised WORKSTATION-042. Attacker accessed FILE-SERVER-01, DB-SERVER-01, and BACKUP-SERVER-01, collected 2.3 GB of data, and exfiltrated 1.8 GB to external IP 104.21.45.67. Full kill chain from initial access to exfiltration observed.

SUPPORTING DETAIL:
- WORKSTATION-042 (Finance dept, compromised via phishing) made first-time connections to 3 internal servers
- 2.3 GB downloaded from FILE-SERVER-01 (normal baseline: < 50 MB/day) indicating bulk data collection
- 1.8 GB outbound HTTPS transfer to external IP 104.21.45.67 (Cloudflare, unknown domain)
- Destination not in approved cloud storage list — likely attacker-controlled infrastructure
- SIEM correlated full kill chain: Initial Access -> Credential Access -> Lateral Movement -> Collection -> Exfiltration

MITRE ATT&CK: T1021 - Remote Services, T1048 - Exfiltration Over Alternative Protocol

RECOMMENDED ACTION:
- Immediately isolate WORKSTATION-042 from the network (do NOT power off — preserve forensic evidence)
- Block outbound connections to 104.21.45.67 at the firewall
- Identify and classify the exfiltrated data — engage legal/compliance if sensitive data was involved
- Revoke all credentials associated with WORKSTATION-042 user; scan FILE-SERVER-01, DB-SERVER-01, BACKUP-SERVER-01 for persistence mechanisms"""

        elif "beacon" in prompt or ("c2" in prompt and "cobalt" in prompt):
            return """BOTTOM LINE: WORKSTATION-042 is communicating with a confirmed Cobalt Strike C2 server (185.220.101.34) via periodic HTTPS beacons every ~15 minutes. The host is under active remote control by threat actor FIN7. Immediate network isolation required.

SUPPORTING DETAIL:
- 8 periodic HTTPS connections from 10.0.3.42 to 185.220.101.34:443, interval ~15 min +/- 30s
- Consistent packet size (256 bytes) and JA3 hash match Cobalt Strike 4.9 beacon profile
- Threat intelligence: IP 185.220.101.34 confirmed as Cobalt Strike C2 by AlienVault OTX and Abuse.ch
- Associated threat group: FIN7 (financially motivated cybercrime)
- DGA-like DNS queries to c2-relay.darkops.xyz resolve to the C2 IP

MITRE ATT&CK: T1071.001 - Application Layer Protocol: Web Protocols, T1071.004 - DNS, T1105 - Ingress Tool Transfer

RECOMMENDED ACTION:
- Immediately isolate WORKSTATION-042 from the network
- Block 185.220.101.34 and domain c2-relay.darkops.xyz at DNS and firewall
- Conduct full forensic analysis of WORKSTATION-042 to identify all implants and persistence mechanisms
- Search network logs for any other hosts communicating with this C2 infrastructure"""

        elif "brute" in prompt and "ssh" in prompt:
            return """BOTTOM LINE: WEB-SERVER-01 compromised via SSH brute-force attack from known malicious IP 203.0.113.45 (China, AS4134). Attacker successfully authenticated as 'admin' after 15 failed attempts. Immediate containment required.

SUPPORTING DETAIL:
- 15 failed SSH login attempts from 203.0.113.45 over 20 minutes, followed by successful authentication
- Source IP is listed in abuse.ch blocklist as SSH brute-force botnet node (last seen 2025-09-10)
- SIEM correlation confirmed brute-force pattern; threat intelligence validates malicious source
- Account 'admin' on WEB-SERVER-01 is now potentially under attacker control

MITRE ATT&CK: T1110 - Brute Force, T1110.001 - Password Guessing, T1078 - Valid Accounts

RECOMMENDED ACTION:
- Immediately disable the 'admin' account on WEB-SERVER-01 and force password reset
- Block IP 203.0.113.45 at the perimeter firewall
- Review WEB-SERVER-01 for unauthorized changes, new accounts, or persistent backdoors since the successful login
- Enable SSH key-only authentication and implement account lockout policies"""

        elif "port_scan" in prompt and ("sql_injection" in prompt or "exploit" in prompt):
            return """BOTTOM LINE: WEB-SERVER-01 under active multi-stage attack from 198.51.100.23. Attacker completed network reconnaissance (8-port scan) then launched SQL injection and command injection exploits against the web application. Exploitation may have succeeded.

SUPPORTING DETAIL:
- SYN scan of 8 ports (21, 22, 80, 443, 3306, 5432, 8080, 8443) detected by IDS and firewall
- SQL injection attempt on /api/users endpoint using classic OR-based bypass
- Command injection attempt on /api/export endpoint attempting to read /etc/passwd (CVE-2024-XXXX)
- SIEM correlated the scan-to-exploit chain as a multi-stage attack

MITRE ATT&CK: T1046 - Network Service Scanning, T1595 - Active Scanning, T1190 - Exploit Public-Facing Application

RECOMMENDED ACTION:
- Block IP 198.51.100.23 at the perimeter firewall immediately
- Check web application logs for successful exploitation (HTTP 200 responses to injection payloads)
- Patch the identified vulnerability (CVE-2024-XXXX) on WEB-SERVER-01
- Deploy WAF rules to block SQL injection and command injection patterns"""

        elif "phishing" in prompt and ("unusual_login" in prompt or "privilege_escalation" in prompt):
            return """BOTTOM LINE: Credential compromise confirmed via phishing campaign. User 'j.martinez' (Finance) credentials stolen and used by attacker from Russia (45.33.32.156) to access Domain Controller DC-01. Privilege escalation to Domain Admins was attempted but blocked.

SUPPORTING DETAIL:
- Phishing emails from spoofed sender (micros0ft-verify.com) targeted 3 workstations; WORKSTATION-042 user clicked the link
- User submitted credentials to attacker-controlled page at 192.0.2.100/login.html
- 30 minutes later, 'j.martinez' account logged into DC-01 from IP 45.33.32.156 (GeoIP: Russia)
- Attacker attempted to add 'j.martinez' to Domain Admins group — blocked by AD policy

MITRE ATT&CK: T1566.002 - Spearphishing Link, T1078 - Valid Accounts, T1098 - Account Manipulation

RECOMMENDED ACTION:
- Immediately reset 'j.martinez' credentials and revoke all active sessions
- Block 192.0.2.100 and 45.33.32.156 at the perimeter firewall; add micros0ft-verify.com to email blocklist
- Scan WORKSTATION-042 for malware and browser credential theft
- Issue a phishing awareness alert to all employees who received the email"""

        elif "phishing" in prompt:
            return """BOTTOM LINE: Coordinated phishing campaign detected targeting 3 user workstations (Finance, Engineering, HR departments). Emails contain credential harvesting links to recently registered malicious domain. At least one user interacted with the phishing link.

SUPPORTING DETAIL:
- 3 phishing emails detected by email gateway from spoofed sender security-update@micros0ft-verify.com
- SPF: FAIL, DKIM: NONE — confirms spoofed sender identity
- Domain micros0ft-verify.com registered 48 hours ago on Namecheap with Let's Encrypt certificate
- Threat intelligence matches known phishing kit pattern (APT-PHISH-2025-0912)

MITRE ATT&CK: T1566 - Phishing, T1566.002 - Spearphishing Link

RECOMMENDED ACTION:
- Block domain micros0ft-verify.com and IP 192.0.2.100 at email gateway, proxy, and firewall
- Contact all 3 targeted users to verify if they clicked the link or submitted credentials
- If any user interacted, immediately reset their credentials and scan their workstation
- Add IOCs to threat intelligence platform for future detection"""

        elif "exfiltration" in prompt or "lateral" in prompt:
            return """BOTTOM LINE: Active data breach in progress from compromised WORKSTATION-042. Attacker accessed FILE-SERVER-01, DB-SERVER-01, and BACKUP-SERVER-01, collected 2.3 GB of data, and exfiltrated 1.8 GB to external IP 104.21.45.67. Full kill chain from initial access to exfiltration observed.

SUPPORTING DETAIL:
- WORKSTATION-042 (Finance dept, compromised via phishing) made first-time connections to 3 internal servers
- 2.3 GB downloaded from FILE-SERVER-01 (normal baseline: < 50 MB/day) indicating bulk data collection
- 1.8 GB outbound HTTPS transfer to external IP 104.21.45.67 (Cloudflare, unknown domain)
- Destination not in approved cloud storage list — likely attacker-controlled infrastructure
- SIEM correlated full kill chain: Initial Access -> Credential Access -> Lateral Movement -> Collection -> Exfiltration

MITRE ATT&CK: T1021 - Remote Services, T1048 - Exfiltration Over Alternative Protocol

RECOMMENDED ACTION:
- Immediately isolate WORKSTATION-042 from the network (do NOT power off — preserve forensic evidence)
- Block outbound connections to 104.21.45.67 at the firewall
- Identify and classify the exfiltrated data — engage legal/compliance if sensitive data was involved
- Revoke all credentials associated with WORKSTATION-042 user; scan FILE-SERVER-01, DB-SERVER-01, BACKUP-SERVER-01 for persistence mechanisms"""

        elif "beacon" in prompt or "c2" in prompt:
            return """BOTTOM LINE: WORKSTATION-042 is communicating with a confirmed Cobalt Strike C2 server (185.220.101.34) via periodic HTTPS beacons every ~15 minutes. The host is under active remote control by threat actor FIN7. Immediate network isolation required.

SUPPORTING DETAIL:
- 8 periodic HTTPS connections from 10.0.3.42 to 185.220.101.34:443, interval ~15 min +/- 30s
- Consistent packet size (256 bytes) and JA3 hash match Cobalt Strike 4.9 beacon profile
- Threat intelligence: IP 185.220.101.34 confirmed as Cobalt Strike C2 by AlienVault OTX and Abuse.ch
- Associated threat group: FIN7 (financially motivated cybercrime)
- DGA-like DNS queries to c2-relay.darkops.xyz resolve to the C2 IP

MITRE ATT&CK: T1071.001 - Application Layer Protocol: Web Protocols, T1071.004 - DNS, T1105 - Ingress Tool Transfer

RECOMMENDED ACTION:
- Immediately isolate WORKSTATION-042 from the network
- Block 185.220.101.34 and domain c2-relay.darkops.xyz at DNS and firewall
- Conduct full forensic analysis of WORKSTATION-042 to identify all implants and persistence mechanisms
- Search network logs for any other hosts communicating with this C2 infrastructure"""

        elif "false positive" in prompt or "vulnerability_scan" in prompt or "nessus" in prompt or "authorised scanner" in prompt:
            return """BOTTOM LINE: FALSE POSITIVE — All alerts in this incident originate from the authorised Nessus vulnerability scanner (10.0.4.100) performing a scheduled weekly scan. No security action required.

SUPPORTING DETAIL:
- Source IP 10.0.4.100 is the organisation's registered Nessus Professional scanner
- Scan ID SCHED-WEEKLY-2025-09-12 matches the approved scanning schedule
- Targets include standard infrastructure assets (web, database, mail, DC, VPN servers)
- All alerts are low severity, consistent with expected scanner behavior

MITRE ATT&CK: T1595 - Active Scanning (authorised activity, not adversarial)

RECOMMENDED ACTION:
- No immediate action required — this is expected scanning activity
- Consider whitelisting scanner IP 10.0.4.100 in IDS rules to reduce alert noise
- Review scan results in the Nessus console for any newly discovered vulnerabilities"""

        elif any(kw in prompt for kw in ["windows update", "dns query volume", "windowsupdate"]):
            return """BOTTOM LINE: FALSE POSITIVE — DNS query spikes are caused by routine Windows Update and antivirus signature downloads across workstations. Normal patch cycle activity, no indicators of DNS tunneling or exfiltration.

SUPPORTING DETAIL:
- Multiple workstations generating high DNS query volumes to windowsupdate.microsoft.com and related Microsoft CDN domains
- Query patterns (150-400 queries in 5 minutes) consistent with Windows Update download cycle
- All queried domains are legitimate Microsoft infrastructure
- No indicators of DNS tunneling (no encoded subdomains, no anomalous TXT records)

MITRE ATT&CK: None applicable — this is legitimate system maintenance activity

RECOMMENDED ACTION:
- No security action required
- Consider scheduling Windows Updates during off-hours to reduce DNS query baseline noise
- Add windowsupdate.microsoft.com to DNS monitoring whitelist to suppress future alerts"""

        else:
            return """BOTTOM LINE: Low-severity operational event detected. Assessment indicates routine system activity with no indicators of compromise or malicious intent.

SUPPORTING DETAIL:
- Alert content consists of routine operational events (system maintenance, configuration changes, or informational logging)
- No correlation with known attack patterns or threat intelligence indicators
- All source and destination IPs are internal and expected
- Severity level and alert type are consistent with normal operations

MITRE ATT&CK: None applicable

RECOMMENDED ACTION:
- No immediate security action required
- Log for compliance and audit purposes
- Review if alert threshold tuning could reduce noise from similar events"""


def get_llm_client() -> LLMClient:
    """
    Factory function: returns the right LLM client based on LLM_PROVIDER.

    Usage:
        from llm.llm_client import get_llm_client
        client = get_llm_client()
        response = client.generate("Explain this alert...")

    The LLM_PROVIDER env var controls which client is created:
        "watsonx"   -> WatsonxClient (default)
        "anthropic" -> AnthropicClient
        "mock"      -> MockLLMClient (offline demo mode)
    """
    provider = LLM_PROVIDER.lower().strip()

    if provider == "anthropic":
        return AnthropicClient()
    elif provider == "watsonx":
        return WatsonxClient()
    elif provider == "mock":
        return MockLLMClient()
    else:
        raise ValueError(
            f"Unknown LLM_PROVIDER: '{provider}'. "
            f"Set LLM_PROVIDER to 'watsonx', 'anthropic', or 'mock' in your .env file."
        )


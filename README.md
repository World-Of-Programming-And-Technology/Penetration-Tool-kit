# SecureNet Watcher: AI-Driven Penetration Testing & Cyber Defense Suite

**SecureNet Watcher** is an advanced, AI-integrated, cross-platform Python toolkit that combines ethical hacking tools, intelligent user behavior monitoring, and a feature-rich Web/Terminal UI to protect users from online threats and distractions.

---

## Highlights

- **AI Behavior Tracker**  
  Uses real-time AI models to track website visits, app usage, and focus levels. Provides insights, sends alerts, and auto-blocks distractions.

- **Smart Port & Service Scanner**  
  Deep port scanning with type detection, service identification, and banner grabbing.

- **App Usage Analyzer**  
  Detects frequently used apps/websites and blocks those overused (>3x in 2 hours) with automatic unblocking after 2 hours.

- **Secure Web Monitor**  
  Logs visited websites, resolves domains, counts visit frequency, and flags suspicious activity in real-time.

- **Dangerous Website Detector**  
  Maintains a regularly updated threat database (phishing, malware, scams) and blocks known malicious sites on access.

- **Firewall Control & Port Blocking**  
  Includes a programmable firewall interface that allows blocking/unblocking specific ports with TUI commands or Web UI buttons.

- **Location & Device Fingerprinting**  
  Uses public IP tracing and MAC detection to log user network metadata, including location and device type.

---

## Bonus Features

- **Focus Mode**:  
  User-defined "allowed apps/websites only" mode. AI ensures redirection or blockage if the user attempts to deviate.

- **Data Protection**:  
  On visit, it tries to prevent website trackers by deleting stored cookies, clearing cache, and blocking scripts.

- **Task Manager-like Interface**:  
  Built-in process monitor in the Web UI. View, search, and manage system processes in real time.

- **Web UI Access Log**:  
  A log table with browser, IP, time, and action taken — stored encrypted in `logs/encrypted_logs.db`.

- **Privacy Control Panel**:  
  Toggle firewall, unblock sites, control app access, or go stealth mode via GUI.

---

## Usage Scenarios

| Use Case                        | Description                                      |
|-------------------------------|--------------------------------------------------|
| Ethical Penetration Testing   | Discover vulnerabilities across your network     |
| Kid Mode                      | Lock screen time, restrict content, block games  |
| School/Work Productivity      | Improve focus by limiting access to distractions |
| Secure Browsing               | Trace & remove dangerous data footprints         |
| Real-time Monitoring System   | Track IoT device access or internal threats      |

---

## Installation

```bash
git clone https://github.com/World-Of-Programming-Technology/Penetration-Tool-kit
cd Penetration-Tool-Kit
pip install -r requirements.txt

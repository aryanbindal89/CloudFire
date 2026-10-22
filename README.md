# 🛡️ CloudFire

**A local network monitoring and firewall-response prototype built with Python, FastAPI, Uvicorn, and SQLite.**

CloudFire provides a browser-based dashboard for viewing observed network traffic, recorded block events, and system logs. Its Windows-oriented background engine attempts to detect unusually high packet rates from a source IP and add a Windows Defender Firewall rule.

> **Status:** Educational prototype. It has not been independently security-validated and should not be treated as production-grade firewall, WAF, or DDoS protection software.

## ✨ Features

- **Security dashboard** with traffic and block counts.
- **Traffic view** showing recent source IPs, protocols, timestamps, and packet sizes.
- **Blocklist view** showing recorded block events and an option to request unblocking.
- **System logs** for engine activity and recorded events.
- **SQLite persistence** for traffic, blocks, and logs.
- **FastAPI endpoints** that provide dashboard data as JSON.
- **Windows Firewall integration** through `netsh` commands.

## 🧰 Technology Stack

- Python
- FastAPI
- Uvicorn
- SQLite
- HTML, CSS, and JavaScript
- Windows networking APIs and Windows Defender Firewall command-line tools

## 📁 Project Structure

```text
ibm skills/
├── main.py
├── requirements.txt
├── README.md
└── cloudfire.db       # Created when the application initializes
```

The database file is created in the process's current working directory.

## ✅ Requirements

- Windows environment for the current packet-capture and firewall implementation.
- A compatible Python installation.
- `pip`.
- Administrator privileges for raw packet capture and firewall operations.

Python standard-library modules such as `socket`, `struct`, `time`, `subprocess`, `sqlite3`, and `threading` do not need separate installation.

## 🚀 Installation

Open PowerShell in the project directory:

```powershell
cd "D:\ibm skills"
```

Install the Python dependencies:

```powershell
python -m pip install -r requirements.txt
```

The `requirements.txt` file should contain:

```text
fastapi
uvicorn
```

If you have multiple Python installations, use the same Python executable for installing dependencies and running the app. For example:

```powershell
& "C:\Users\dell\AppData\Local\Python\pythoncore-3.14-64\python.exe" -m pip install -r "D:\ibm skills\requirements.txt"
```

## ▶️ Run the Application

Because packet capture and firewall actions require elevated permissions, open **PowerShell as Administrator** before starting the application.

```powershell
cd "D:\ibm skills"
python main.py
```

If needed, specify your Python executable explicitly:

```powershell
& "C:\Users\dell\AppData\Local\Python\pythoncore-3.14-64\python.exe" "D:\ibm skills\main.py"
```

The launcher is configured to start the dashboard at:

**http://127.0.0.1:8000**

It also attempts to open the page in your default browser automatically.

## 🔌 API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/` | Serves the dashboard HTML |
| `GET` | `/api/stats` | Returns traffic and block counts |
| `GET` | `/api/blocks` | Returns recorded block events |
| `GET` | `/api/traffic` | Returns the latest 50 traffic records |
| `GET` | `/api/syslogs` | Returns the latest 100 system-log records |
| `POST` | `/api/unblock/{ip}` | Requests removal of a recorded firewall block |

## ⚙️ How It Works

1. The database manager creates SQLite tables for traffic, blocks, and system logs.
2. The defense engine opens a raw IPv4 socket and attempts to observe packets.
3. For each observed packet, it extracts the source IP and classifies the IP protocol as TCP, UDP, ICMP, or other.
4. It tracks packet timestamps by source IP. The current threshold is more than **20 packets in a 3-second window**.
5. If the threshold is exceeded, the engine attempts to add a Windows Defender Firewall inbound block rule and records the event.
6. FastAPI exposes the stored data through API endpoints.
7. The browser dashboard polls those endpoints approximately every 1.5 seconds.

The threshold is a simple heuristic. A high packet rate alone does not establish that traffic is malicious.

## 🗃️ Database Tables

| Table | Purpose |
|---|---|
| `traffic` | Stores timestamp, source IP, protocol, and packet size |
| `blocks` | Stores timestamp, IP address, and block reason |
| `syslogs` | Stores timestamp, log level, and message |

## 🧪 Suggested Testing

These are recommended checks, not claims that the application has already passed them.

- Start the application and confirm that the dashboard opens locally.
- Visit each `GET` API endpoint and confirm that it returns JSON.
- Confirm that the SQLite database and expected tables are created.
- Test packet capture only in a controlled environment.
- Verify firewall rule creation and deletion using a test address you control.
- Test startup behavior without administrator privileges.
- Check application logs and error handling when network capture is unavailable.

## ⚠️ Security Notes and Limitations

- **Not production-ready:** This is a learning prototype, not a production WAF or validated DDoS mitigation system.
- **Potential false positives:** The packet-rate threshold is basic and may block legitimate traffic.
- **Windows-specific:** The capture implementation uses Windows-specific socket behavior and `netsh`.
- **Administrator access:** Raw packet capture and firewall modification require appropriate privileges.
- **No API authentication:** The current API does not implement authentication or authorization. Keep it bound to localhost unless proper access controls are added.
- **Permissive CORS:** The current source allows all origins; restrict this before any broader deployment.
- **Input and command safety:** Validate IP addresses and avoid interpolating untrusted input into shell commands. The current code uses `subprocess.run(..., shell=True)` for firewall commands.
- **HTML rendering:** The dashboard inserts API data using `innerHTML`; use safe DOM APIs or proper escaping for untrusted values.
- **Use a test environment:** Do not test automatic blocking on production networks or against IP addresses you do not control. Keep a recovery path for firewall configuration.

## 🔮 Future Improvements

- Add strict IP-address validation and safer firewall command execution.
- Add authentication and authorization for sensitive actions.
- Restrict CORS to trusted origins.
- Render API data safely in the dashboard.
- Add structured logging and clearer error reporting.
- Implement graceful shutdown and robust packet-capture error handling.
- Add unit and integration tests.
- Move embedded HTML, CSS, and JavaScript into separate files.
- Pin tested dependency versions for reproducible installations.
- Add a passive-monitoring mode and require administrator confirmation before applying blocks.

## 📄 License

No license has been specified yet. Add a `LICENSE` file before distributing the project publicly.

---

**CloudFire** is intended for educational use and controlled testing on systems and networks you are authorized to administer.

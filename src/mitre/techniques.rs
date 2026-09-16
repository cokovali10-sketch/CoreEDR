use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tactic {
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

impl Tactic {
    pub fn id(&self) -> &'static str {
        match self {
            Tactic::InitialAccess => "TA0001",
            Tactic::Execution => "TA0002",
            Tactic::Persistence => "TA0003",
            Tactic::PrivilegeEscalation => "TA0004",
            Tactic::DefenseEvasion => "TA0005",
            Tactic::CredentialAccess => "TA0006",
            Tactic::Discovery => "TA0007",
            Tactic::LateralMovement => "TA0008",
            Tactic::Collection => "TA0009",
            Tactic::CommandAndControl => "TA0011",
            Tactic::Exfiltration => "TA0010",
            Tactic::Impact => "TA0040",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Tactic::InitialAccess => "Initial Access",
            Tactic::Execution => "Execution",
            Tactic::Persistence => "Persistence",
            Tactic::PrivilegeEscalation => "Privilege Escalation",
            Tactic::DefenseEvasion => "Defense Evasion",
            Tactic::CredentialAccess => "Credential Access",
            Tactic::Discovery => "Discovery",
            Tactic::LateralMovement => "Lateral Movement",
            Tactic::Collection => "Collection",
            Tactic::CommandAndControl => "Command and Control",
            Tactic::Exfiltration => "Exfiltration",
            Tactic::Impact => "Impact",
        }
    }

    pub fn all() -> Vec<Tactic> {
        vec![
            Tactic::InitialAccess,
            Tactic::Execution,
            Tactic::Persistence,
            Tactic::PrivilegeEscalation,
            Tactic::DefenseEvasion,
            Tactic::CredentialAccess,
            Tactic::Discovery,
            Tactic::LateralMovement,
            Tactic::Collection,
            Tactic::CommandAndControl,
            Tactic::Exfiltration,
            Tactic::Impact,
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TechniqueId(pub String);

impl TechniqueId {
    pub fn new(id: &str) -> Self {
        TechniqueId(id.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technique {
    pub id: TechniqueId,
    pub name: String,
    pub tactic: Tactic,
    pub description: String,
    pub detection_hints: Vec<String>,
    pub data_sources: Vec<String>,
    pub platforms: Vec<String>,
}

impl Technique {
    pub fn short_id(&self) -> &str {
        self.id.0.trim_start_matches("T")
    }
}

pub fn build_technique_database() -> HashMap<TechniqueId, Technique> {
    let mut db = HashMap::new();

    // === EXECUTION ===
    let techniques = vec![
        Technique {
            id: TechniqueId::new("T1059"),
            name: "Command and Scripting Interpreter".into(),
            tactic: Tactic::Execution,
            description: "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.".into(),
            detection_hints: vec![
                "Process with suspicious command line arguments".into(),
                "PowerShell with encoded commands".into(),
                "WScript/CScript execution".into(),
                "Python/Ruby/Perl execution from unusual paths".into(),
            ],
            data_sources: vec!["Process creation".into(), "Command-line logging".into()],
            platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
        },
        Technique {
            id: TechniqueId::new("T1059.001"),
            name: "PowerShell".into(),
            tactic: Tactic::Execution,
            description: "Adversaries may abuse PowerShell commands and scripts for execution.".into(),
            detection_hints: vec![
                "-EncodedCommand or -enc parameter".into(),
                "Download cradles (Invoke-WebRequest, Net.WebClient)".into(),
                "Base64 encoded payloads".into(),
                "Execution policy bypass".into(),
                "PowerShell running as a service".into(),
            ],
            data_sources: vec!["Process creation".into(), "PowerShell script block logging".into()],
            platforms: vec!["Windows".into()],
        },
        Technique {
            id: TechniqueId::new("T1059.003"),
            name: "Windows Command Shell".into(),
            tactic: Tactic::Execution,
            description: "Adversaries may abuse cmd.exe commands to execute commands.".into(),
            detection_hints: vec![
                "cmd.exe spawned by unusual parent".into(),
                "cmd.exe with /c flag executing network commands".into(),
                "For loop execution patterns".into(),
            ],
            data_sources: vec!["Process creation".into(), "Command-line logging".into()],
            platforms: vec!["Windows".into()],
        },
        Technique {
            id: TechniqueId::new("T1059.006"),
            name: "Python".into(),
            tactic: Tactic::Execution,
            description: "Adversaries may abuse Python commands and scripts for execution.".into(),
            detection_hints: vec![
                "Python execution with -c flag".into(),
                "Python downloading and executing".into(),
                "Python from temp directories".into(),
            ],
            data_sources: vec!["Process creation".into()],
            platforms: vec!["Linux".into(), "macOS".into(), "Windows".into()],
        },
        Technique {
            id: TechniqueId::new("T1204"),
            name: "User Execution".into(),
            tactic: Tactic::Execution,
            description: "An adversary may rely upon specific actions by a user in order to gain execution.".into(),
            detection_hints: vec![
                "Executable launched from downloads folder".into(),
                "Document with macros enabled".into(),
                "Suspicious file extension double-clicked".into(),
            ],
            data_sources: vec!["Process creation".into(), "File creation".into()],
            platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
        },

        // === PERSISTENCE ===
        Technique {
            id: TechniqueId::new("T1547"),
            name: "Boot or Logon Autostart Execution".into(),
            tactic: Tactic::Persistence,
            description: "Adversaries may configure system settings to automatically execute a program during system boot or logon.".into(),
            detection_hints: vec![
                "Registry Run key modification".into(),
                "Startup folder file creation".into(),
                "Scheduled task creation".into(),
                "WMI event subscription".into(),
                "Service installation".into(),
            ],
            data_sources: vec!["Registry modification".into(), "File creation".into(), "Process creation".into()],
            platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
        },
        Technique {
            id: TechniqueId::new("T1547.001"),
            name: "Registry Run Keys / Startup Folder".into(),
            tactic: Tactic::Persistence,
            description: "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.".into(),
            detection_hints: vec![
                "New entry in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
                "New entry in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
                "File placed in Startup folder".into(),
            ],
            data_sources: vec!["Registry modification".into(), "File creation".into()],
            platforms: vec!["Windows".into()],
        },
        Technique {
            id: TechniqueId::new("T1053"),
            name: "Scheduled Task/Job".into(),
            tactic: Tactic::Persistence,
            description: "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.".into(),
            detection_hints: vec![
                "schtasks.exe /create".into(),
                "crontab -e".into(),
                "at.exe usage".into(),
                "Systemd timer creation".into(),
            ],
            data_sources: vec!["Process creation".into(), "Scheduled job creation".into()],
            platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
        },
        Technique {
            id: TechniqueId::new("T1543"),
            name: "Create or Modify System Process".into(),
            tactic: Tactic::Persistence,
            description: "Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence.".into(),
            detection_hints: vec![
                "New systemd service unit".into(),
                "New Windows service".into(),
                "launchd plist modification".into(),
            ],
            data_sources: vec!["Service creation".into(), "Process creation".into()],
            platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
        },

        // === PRIVILEGE ESCALATION ===
        Technique {
            id: TechniqueId::new("T1548"),
            name: "Abuse Elevation Control Mechanism".into(),
            tactic: Tactic::PrivilegeEscalation,
            description: "Adversaries may circumvent mechanisms designed to control elevated privileges to gain higher-level permissions.".into(),
            detection_hints: vec![
                "UAC bypass attempts".into(),
                "Sudo abuse".into(),
                "Setuid binary abuse".into(),
                "Token manipulation".into(),
            ],
            data_sources: vec!["Process creation".into(), "Registry modification".into()],
            platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
        },

        // === DEFENSE EVASION ===
        Technique {
            id: TechniqueId::new("T1070"),
            name: "Indicator Removal".into(),
            tactic: Tactic::DefenseEvasion,
            description: "Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses.".into(),
            detection_hints: vec![
                "Log clearing (wevtutil cl)".into(),
                "Bash history deletion".into(),
                "Timestomping".into(),
                "File deletion after execution".into(),
            ],
            data_sources: vec!["File deletion".into(), "Log clearing".into()],
            platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
        },
        Technique {
            id: TechniqueId::new("T1027"),
            name: "Obfuscated Files or Information".into(),
            tactic: Tactic::DefenseEvasion,
            description: "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents.".into(),
            detection_hints: vec![
                "Base64 encoded executables".into(),
                "High entropy sections in PE".into(),
                "Packed executables".into(),
                "Obfuscated scripts".into(),
            ],
            data_sources: vec!["File analysis".into(), "Process creation".into()],
            platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
        },
        Technique {
            id: TechniqueId::new("T1562"),
            name: "Impair Defenses".into(),
            tactic: Tactic::DefenseEvasion,
            description: "Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms.".into(),
            detection_hints: vec![
                "Antivirus service stopped".into(),
                "Firewall rules modified".into(),
                "EDR agent tampered".into(),
                "Logging disabled".into(),
            ],
            data_sources: vec!["Service modification".into(), "Registry modification".into(), "Process creation".into()],
            platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
        },
        Technique {
            id: TechniqueId::new("T1055"),
            name: "Process Injection".into(),
            tactic: Tactic::DefenseEvasion,
            description: "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.".into(),
            detection_hints: vec![
                "Remote thread creation".into(),
                "Process hollowing".into(),
                "DLL injection".into(),
                "Process with injected memory".into(),
            ],
            data_sources: vec!["Process creation".into(), "API monitoring".into()],
            platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
        },

        // === CREDENTIAL ACCESS ===
        Technique {
            id: TechniqueId::new("T1003"),
            name: "OS Credential Dumping".into(),
            tactic: Tactic::CredentialAccess,
            description: "Adversaries may attempt to dump credentials to obtain account login and credential material.".into(),
            detection_hints: vec![
                "LSASS process access".into(),
                "SAM database access".into(),
                "Mimikatz detection".into(),
                "/etc/shadow access".into(),
                "NTDS.dit access".into(),
            ],
            data_sources: vec!["Process access".into(), "File access".into()],
            platforms: vec!["Windows".into(), "Linux".into()],
        },
        Technique {
            id: TechniqueId::new("T1003.001"),
            name: "LSASS Memory".into(),
            tactic: Tactic::CredentialAccess,
            description: "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).".into(),
            detection_hints: vec![
                "lsass.exe accessed by unknown process".into(),
                "MiniDumpWriteDump API call".into(),
                "Procdump on lsass".into(),
                "Comsvcs.dll Minidump".into(),
            ],
            data_sources: vec!["Process access".into(), "API monitoring".into()],
            platforms: vec!["Windows".into()],
        },

        // === DISCOVERY ===
        Technique {
            id: TechniqueId::new("T1082"),
            name: "System Information Discovery".into(),
            tactic: Tactic::Discovery,
            description: "An adversary may attempt to get detailed information about the operating system and hardware.".into(),
            detection_hints: vec![
                "systeminfo.exe execution".into(),
                "uname -a execution".into(),
                "WMI queries for OS info".into(),
                "Registry queries for system info".into(),
            ],
            data_sources: vec!["Process creation".into(), "Command-line logging".into()],
            platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
        },
        Technique {
            id: TechniqueId::new("T1083"),
            name: "File and Directory Discovery".into(),
            tactic: Tactic::Discovery,
            description: "Adversaries may enumerate files and directories or may search in specific locations of a host or network share.".into(),
            detection_hints: vec![
                "dir/ls -R in sensitive directories".into(),
                "Find commands searching for credentials".into(),
                "Tree enumeration".into(),
            ],
            data_sources: vec!["Process creation".into(), "File access".into()],
            platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
        },
        Technique {
            id: TechniqueId::new("T1049"),
            name: "System Network Connections Discovery".into(),
            tactic: Tactic::Discovery,
            description: "Adversaries may attempt to get a listing of network connections to or from the compromised system.".into(),
            detection_hints: vec![
                "netstat execution".into(),
                "ss/netstat -an".into(),
                "TCPView execution".into(),
            ],
            data_sources: vec!["Process creation".into()],
            platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
        },
        Technique {
            id: TechniqueId::new("T1057"),
            name: "Process Discovery".into(),
            tactic: Tactic::Discovery,
            description: "Adversaries may attempt to get information about running processes on a system.".into(),
            detection_hints: vec![
                "tasklist execution".into(),
                "ps aux execution".into(),
                "WMI process query".into(),
            ],
            data_sources: vec!["Process creation".into()],
            platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
        },

        // === LATERAL MOVEMENT ===
        Technique {
            id: TechniqueId::new("T1021"),
            name: "Remote Services".into(),
            tactic: Tactic::LateralMovement,
            description: "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections.".into(),
            detection_hints: vec![
                "SSH to remote host".into(),
                "RDP connection".into(),
                "WMI remote execution".into(),
                "PsExec execution".into(),
            ],
            data_sources: vec!["Network connection".into(), "Process creation".into()],
            platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
        },

        // === COMMAND AND CONTROL ===
        Technique {
            id: TechniqueId::new("T1071"),
            name: "Application Layer Protocol".into(),
            tactic: Tactic::CommandAndControl,
            description: "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering.".into(),
            detection_hints: vec![
                "HTTP/HTTPS to unusual ports".into(),
                "DNS tunneling".into(),
                "Custom protocol over raw sockets".into(),
            ],
            data_sources: vec!["Network connection".into(), "DNS queries".into()],
            platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
        },
        Technique {
            id: TechniqueId::new("T1573"),
            name: "Encrypted Channel".into(),
            tactic: Tactic::CommandAndControl,
            description: "Adversaries may employ a known encryption algorithm to conceal command and control traffic.".into(),
            detection_hints: vec![
                "TLS to unknown certificates".into(),
                "Self-signed certificates".into(),
                "Unusual cipher suites".into(),
            ],
            data_sources: vec!["Network connection".into(), "TLS inspection".into()],
            platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
        },
        Technique {
            id: TechniqueId::new("T1105"),
            name: "Ingress Tool Transfer".into(),
            tactic: Tactic::CommandAndControl,
            description: "Adversaries may transfer tools or other files from an external system into a compromised environment.".into(),
            detection_hints: vec![
                "curl/wget downloading executables".into(),
                "PowerShell downloading files".into(),
                "Certutil -urlcache -split -f".into(),
            ],
            data_sources: vec!["Network connection".into(), "File creation".into(), "Process creation".into()],
            platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
        },
        Technique {
            id: TechniqueId::new("T1572"),
            name: "Protocol Tunneling".into(),
            tactic: Tactic::CommandAndControl,
            description: "Adversaries may tunnel network communications to and from a victim system using a non-standard protocol.".into(),
            detection_hints: vec![
                "DNS over HTTPS to suspicious domains".into(),
                "ICMP tunneling".into(),
                "SSH tunnel".into(),
            ],
            data_sources: vec!["Network connection".into(), "DNS queries".into()],
            platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
        },

        // === EXFILTRATION ===
        Technique {
            id: TechniqueId::new("T1048"),
            name: "Exfiltration Over Alternative Protocol".into(),
            tactic: Tactic::Exfiltration,
            description: "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel.".into(),
            detection_hints: vec![
                "Large data upload to cloud services".into(),
                "DNS exfiltration".into(),
                "ICMP data exfiltration".into(),
            ],
            data_sources: vec!["Network connection".into(), "File access".into()],
            platforms: vec!["Windows".into(), "Linux".into(), "macOS".into()],
        },

        // === IMPACT ===
        Technique {
            id: TechniqueId::new("T1486"),
            name: "Data Encrypted for Impact".into(),
            tactic: Tactic::Impact,
            description: "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources (ransomware).".into(),
            detection_hints: vec![
                "Rapid file modification".into(),
                "Known ransomware extensions".into(),
                "VSS deletion".into(),
                "Ransom note creation".into(),
            ],
            data_sources: vec!["File modification".into(), "File creation".into()],
            platforms: vec!["Windows".into(), "Linux".into()],
        },
    ];

    for tech in techniques {
        db.insert(tech.id.clone(), tech);
    }

    db
}

//! Ghost Shell — AI-powered fake terminal emulator.
//! Every command returns hyper-realistic output.

use anyhow::Result;
use maya_core::types::{DecoyType, SessionId};
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;

use crate::fakegen::FakeDataGenerator;
use crate::filesystem::FilesystemGenerator;

/// The Ghost Shell — a fake but hyper-realistic terminal.
pub struct GhostShell {
    _session_id: SessionId,
    hostname: String,
    cwd: String,
    username: String,
    _decoy_type: DecoyType,
    _history: Vec<String>,
    env: HashMap<String, String>,
    fake_gen: Arc<FakeDataGenerator>,
    fs_gen: Arc<FilesystemGenerator>,
    uptime_secs: u64,
}

impl GhostShell {
    pub fn new(
        session_id: SessionId,
        hostname: String,
        decoy_type: DecoyType,
        fake_gen: Arc<FakeDataGenerator>,
        fs_gen: Arc<FilesystemGenerator>,
    ) -> Self {
        let mut env = HashMap::new();
        env.insert("HOME".into(), "/root".into());
        env.insert(
            "PATH".into(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        );
        env.insert("SHELL".into(), "/bin/bash".into());
        env.insert("TERM".into(), "xterm-256color".into());
        env.insert("LANG".into(), "en_US.UTF-8".into());
        env.insert("USER".into(), "root".into());

        Self {
            _session_id: session_id,
            hostname,
            cwd: "/root".into(),
            username: "root".into(),
            _decoy_type: decoy_type,
            _history: Vec::new(),
            env,
            fake_gen,
            fs_gen,
            uptime_secs: rand::rng().random_range(86400..8640000u64),
        }
    }

    pub async fn execute(&self, command: &str) -> Result<String> {
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(String::new());
        }
        let cmd = parts[0];
        let args = &parts[1..];

        match cmd {
            "ls" => Ok(self.cmd_ls(args)),
            "pwd" => Ok(format!("{}\n", self.cwd)),
            "whoami" => Ok(format!("{}\n", self.username)),
            "id" => Ok("uid=0(root) gid=0(root) groups=0(root)\n".into()),
            "hostname" => Ok(format!("{}\n", self.hostname)),
            "uname" => Ok(self.cmd_uname(args)),
            "cat" => Ok(self.cmd_cat(args)),
            "ps" => Ok(self.cmd_ps()),
            "netstat" | "ss" => Ok(self.cmd_netstat()),
            "ifconfig" | "ip" => Ok(self.cmd_ifconfig()),
            "uptime" => Ok(self.cmd_uptime()),
            "df" => Ok(self.cmd_df()),
            "free" => Ok(self.cmd_free()),
            "date" => Ok(format!(
                "{}\n",
                chrono::Utc::now().format("%a %b %d %H:%M:%S UTC %Y")
            )),
            "echo" => Ok(format!("{}\n", args.join(" "))),
            "env" => Ok(self
                .env
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n"),
            "mysql" => Ok(self.cmd_mysql(args)),
            "sqlite3" => Ok(self.cmd_sqlite3(args)),
            "exit" | "logout" => Ok("logout\n".into()),
            "clear" => Ok("\x1b[2J\x1b[H".into()),
            "sudo" if !args.is_empty() => Box::pin(self.execute(&args.join(" "))).await,
            _ => Ok(format!("-bash: {cmd}: command not found\n")),
        }
    }

    fn cmd_mysql(&self, _args: &[&str]) -> String {
        let mut output = crate::services::ServiceEmulator::mysql_greeting();
        output.push_str("show databases;\n");
        output.push_str("+--------------------+\n");
        output.push_str("| Database           |\n");
        output.push_str("+--------------------+\n");
        output.push_str("| information_schema |\n");
        output.push_str("| mysql              |\n");
        output.push_str("| performance_schema |\n");
        output.push_str("| sys                |\n");
        output.push_str("| user_db            |\n");
        output.push_str("| inventory          |\n");
        output.push_str("+--------------------+\n");
        output.push_str("6 rows in set (0.01 sec)\n\nmysql> ");
        output
    }

    fn cmd_sqlite3(&self, args: &[&str]) -> String {
        if args.is_empty() {
            return "SQLite version 3.37.2 2022-01-06 13:25:41\nEnter \".help\" for usage hints.\nconnected to a transient in-memory database.\nUse \".open FILENAME\" to reopen on a persistent database.\nsqlite> ".into();
        }

        let db_file = args[0];
        if db_file == "patients.db" || db_file == "banking.db" {
            let mut output = format!(
                "SQLite version 3.37.2\nEnter \".help\" for usage hints.\nsqlite> SELECT * FROM {};\n",
                if db_file == "patients.db" {
                    "patients"
                } else {
                    "transactions"
                }
            );

            if db_file == "patients.db" {
                for _ in 0..5 {
                    output.push_str(&self.fake_gen.generate_patient_record());
                    output.push('\n');
                }
            } else {
                for _ in 0..10 {
                    output.push_str(&self.fake_gen.generate_bank_record());
                    output.push('\n');
                }
            }
            output.push_str("sqlite> ");
            output
        } else {
            format!(
                "Error: unable to open database \"{}\": unable to open database file\n",
                db_file
            )
        }
    }

    pub fn prompt(&self) -> String {
        format!(
            "[{}@{} ~]# ",
            self.username,
            self.hostname.split('.').next().unwrap_or("maya")
        )
    }

    fn cmd_ls(&self, args: &[&str]) -> String {
        if args.contains(&"-la") || args.contains(&"-l") {
            "total 48\ndrwxr-xr-x  5 root root 4096 Mar 14 09:22 .\ndrwxr-xr-x 22 root root 4096 Mar 14 09:22 ..\n-rw-------  1 root root 2847 Mar 14 11:05 .bash_history\n-rw-r--r--  1 root root  570 Jan  1  2024 .bashrc\ndrwx------  2 root root 4096 Feb 20 14:33 .ssh\n-rw-r--r--  1 root root 8192 Mar 13 22:10 backup.tar.gz\ndrwxr-xr-x  2 root root 4096 Mar 12 08:45 scripts\n-rwxr-xr-x  1 root root 1234 Mar 11 14:22 monitor.sh\n-rw-r--r--  1 root root 3456 Mar 10 09:15 config.yml\n".into()
        } else {
            "backup.tar.gz  config.yml  monitor.sh  scripts\n".into()
        }
    }

    fn cmd_uname(&self, args: &[&str]) -> String {
        if args.contains(&"-a") {
            format!(
                "Linux {} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n",
                self.hostname.split('.').next().unwrap_or("maya")
            )
        } else {
            "Linux\n".into()
        }
    }

    fn cmd_cat(&self, args: &[&str]) -> String {
        if args.is_empty() {
            return String::new();
        }
        match args[0] {
            "/etc/passwd" => self.fs_gen.generate_passwd(),
            "/etc/shadow" => self.fs_gen.generate_shadow(),
            "/etc/hosts" => self.fs_gen.generate_hosts(&self.hostname),
            "/etc/os-release" => self.fs_gen.generate_os_release(),
            "/var/log/auth.log" => self.fs_gen.generate_auth_log(),
            "/proc/cpuinfo" => self.fs_gen.generate_cpuinfo(),
            "/proc/meminfo" => self.fs_gen.generate_meminfo(),
            "~/.bash_history" => self.fs_gen.generate_bash_history(),
            _ => format!("cat: {}: No such file or directory\n", args[0]),
        }
    }

    fn cmd_ps(&self) -> String {
        "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT   COMMAND\n\
         root         1  0.0  0.1 169936 13264 ?        Ss     /sbin/init\n\
         root       283  0.0  0.1  72308  6340 ?        Ss     /usr/sbin/sshd -D\n\
         root       401  0.0  0.0   4628  1872 ?        Ss     /usr/sbin/cron -f\n\
         mysql     1142  0.5  2.1 1748264 175408 ?      Ssl    /usr/sbin/mysqld\n\
         www-data  1356  0.1  0.3 364652 26884 ?        S      apache2 -k start\n\
         root     28541  0.0  0.1  21624  5344 pts/0    Ss     -bash\n"
            .into()
    }

    fn cmd_netstat(&self) -> String {
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n\
         tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n\
         tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n\
         tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN\n\
         tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN\n\
         tcp        0      0 127.0.0.1:3306          127.0.0.1:49284         ESTABLISHED\n"
            .into()
    }

    fn cmd_ifconfig(&self) -> String {
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n\
         \tinet 10.13.37.105  netmask 255.255.255.0  broadcast 10.13.37.255\n\
         \tether 02:42:0a:0d:25:69  txqueuelen 1000  (Ethernet)\n\
         \tRX packets 4538291  bytes 891247556 (850.0 MiB)\n\
         \tTX packets 3219847  bytes 412983712 (393.8 MiB)\n\n\
         lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n\
         \tinet 127.0.0.1  netmask 255.0.0.0\n"
            .into()
    }

    fn cmd_uptime(&self) -> String {
        let d = self.uptime_secs / 86400;
        let h = (self.uptime_secs % 86400) / 3600;
        let m = (self.uptime_secs % 3600) / 60;
        format!(
            " {}:00 up {} days, {:02}:{:02},  2 users,  load average: 0.42, 0.38, 0.31\n",
            chrono::Utc::now().format("%H:%M"),
            d,
            h,
            m
        )
    }

    fn cmd_df(&self) -> String {
        "Filesystem      Size  Used Avail Use% Mounted on\n\
         /dev/sda1       200G   87G  113G  44% /\n\
         tmpfs           16G     0   16G   0% /dev/shm\n\
         /dev/sdb1       1.0T  234G  766G  24% /data\n"
            .into()
    }

    fn cmd_free(&self) -> String {
        "              total        used        free      shared  buff/cache   available\n\
         Mem:       16384000     8847232     2156800      524288     5379968     6912000\n\
         Swap:       4194304           0     4194304\n"
            .into()
    }
}

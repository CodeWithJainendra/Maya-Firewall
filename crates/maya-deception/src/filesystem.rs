//! Fake filesystem generator for MAYA decoys.
//! Generates realistic /etc/passwd, /var/log/auth.log, /proc/cpuinfo, etc.

use rand::Rng;

pub struct FilesystemGenerator;

impl FilesystemGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_passwd(&self) -> String {
        "root:x:0:0:root:/root:/bin/bash\n\
         daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
         bin:x:2:2:bin:/bin:/usr/sbin/nologin\n\
         sys:x:3:3:sys:/dev:/usr/sbin/nologin\n\
         sync:x:4:65534:sync:/bin:/bin/sync\n\
         games:x:5:60:games:/usr/games:/usr/sbin/nologin\n\
         man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n\
         lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n\
         mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n\
         news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n\
         www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
         sshd:x:106:65534::/run/sshd:/usr/sbin/nologin\n\
         mysql:x:107:113:MySQL Server,,,:/nonexistent:/bin/false\n\
         admin:x:1000:1000:System Administrator:/home/admin:/bin/bash\n\
         deploy:x:1001:1001:Deployment User:/home/deploy:/bin/bash\n\
         backup:x:1002:1002:Backup Manager:/home/backup:/bin/bash\n\
         monitoring:x:1003:1003:Monitoring Service:/home/monitoring:/bin/bash\n"
            .to_string()
    }

    pub fn generate_shadow(&self) -> String {
        "root:$6$rounds=656000$rAND0mS4Lt$fakeHashThisIsNotRealButLooksLikeItIs/.KzYxQp2L:19742:0:99999:7:::\n\
         daemon:*:19500:0:99999:7:::\n\
         bin:*:19500:0:99999:7:::\n\
         admin:$6$rounds=656000$s4LtY$anotherFakeHash12345678901234567890abcdef/:19750:0:99999:7:::\n\
         deploy:$6$rounds=656000$d3pL0y$deployHashFake1234567890abcdefghijklmnop/:19755:0:99999:7:::\n"
            .to_string()
    }

    pub fn generate_hosts(&self, hostname: &str) -> String {
        format!(
            "127.0.0.1\tlocalhost\n\
             127.0.1.1\t{hostname}\n\
             10.13.37.1\tgateway.corp.local\n\
             10.13.37.10\tdc01.corp.local\n\
             10.13.37.20\tdb-primary.corp.local\n\
             10.13.37.21\tdb-replica.corp.local\n\
             10.13.37.30\tweb01.corp.local\n\
             10.13.37.31\tweb02.corp.local\n\
             10.13.37.50\tmonitoring.corp.local\n\n\
             # The following lines are desirable for IPv6 capable hosts\n\
             ::1     ip6-localhost ip6-loopback\n\
             fe00::0 ip6-localnet\n"
        )
    }

    pub fn generate_os_release(&self) -> String {
        "PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\n\
         NAME=\"Ubuntu\"\n\
         VERSION_ID=\"22.04\"\n\
         VERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\n\
         VERSION_CODENAME=jammy\n\
         ID=ubuntu\n\
         ID_LIKE=debian\n\
         HOME_URL=\"https://www.ubuntu.com/\"\n\
         SUPPORT_URL=\"https://help.ubuntu.com/\"\n\
         BUG_REPORT_URL=\"https://bugs.launchpad.net/ubuntu/\"\n"
            .to_string()
    }

    pub fn generate_auth_log(&self) -> String {
        let mut rng = rand::rng();
        let mut log = String::new();
        let months = ["Jan", "Feb", "Mar"];
        for _ in 0..20 {
            let m = months[rng.random_range(0..3usize)];
            let d = rng.random_range(1..29u32);
            let h = rng.random_range(0..24u32);
            let min = rng.random_range(0..60u32);
            let sec = rng.random_range(0..60u32);
            let ip = format!(
                "{}.{}.{}.{}",
                rng.random_range(1..255u32),
                rng.random_range(0..255u32),
                rng.random_range(0..255u32),
                rng.random_range(1..255u32)
            );
            let entries = [
                format!(
                    "{m} {d:>2} {h:02}:{min:02}:{sec:02} srv-001 sshd[{}]: Failed password for invalid user admin from {ip} port {} ssh2",
                    rng.random_range(1000..30000u32),
                    rng.random_range(40000..65000u32)
                ),
                format!(
                    "{m} {d:>2} {h:02}:{min:02}:{sec:02} srv-001 sshd[{}]: Accepted publickey for root from {ip} port {} ssh2",
                    rng.random_range(1000..30000u32),
                    rng.random_range(40000..65000u32)
                ),
                format!(
                    "{m} {d:>2} {h:02}:{min:02}:{sec:02} srv-001 sudo: root : TTY=pts/0 ; PWD=/root ; COMMAND=/usr/bin/apt update"
                ),
            ];
            log.push_str(&entries[rng.random_range(0..entries.len())]);
            log.push('\n');
        }
        log
    }

    pub fn generate_syslog(&self) -> String {
        self.generate_auth_log() // Simplified
    }

    pub fn generate_cpuinfo(&self) -> String {
        "processor\t: 0\n\
         vendor_id\t: GenuineIntel\n\
         cpu family\t: 6\n\
         model\t\t: 85\n\
         model name\t: Intel(R) Xeon(R) Gold 6248 CPU @ 2.50GHz\n\
         stepping\t: 7\n\
         microcode\t: 0x5003604\n\
         cpu MHz\t\t: 2500.000\n\
         cache size\t: 28160 KB\n\
         physical id\t: 0\n\
         siblings\t: 8\n\
         core id\t\t: 0\n\
         cpu cores\t: 4\n\
         bogomips\t: 5000.00\n\
         flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon nopl xtopology tsc_reliable nonstop_tsc cpuid pni pclmulqdq vmx ssse3 fma cx16 pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch cpuid_fault invpcid_single ssbd ibrs ibpb stibp ibrs_enhanced fsgsbase bmi1 avx2 smep bmi2 erms invpcid avx512f avx512dq rdseed adx smap avx512ifma clflushopt clwb avx512cd sha_ni avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves arat avx512vbmi umip pku ospke avx512_vbmi2 gfni vaes vpclmulqdq avx512_vnni avx512_bitalg avx512_vpopcntdq\n\n"
            .to_string()
    }

    pub fn generate_meminfo(&self) -> String {
        "MemTotal:       16384000 kB\n\
         MemFree:         2156800 kB\n\
         MemAvailable:    6912000 kB\n\
         Buffers:          524288 kB\n\
         Cached:          4855680 kB\n\
         SwapTotal:       4194304 kB\n\
         SwapFree:        4194304 kB\n\
         Active:          8192000 kB\n\
         Inactive:        4096000 kB\n\
         Dirty:              1024 kB\n\
         Writeback:             0 kB\n\
         AnonPages:       7340032 kB\n\
         Mapped:          1048576 kB\n\
         Shmem:            524288 kB\n"
            .to_string()
    }

    pub fn generate_bash_history(&self) -> String {
        "systemctl status nginx\n\
         tail -f /var/log/nginx/access.log\n\
         docker ps -a\n\
         docker-compose up -d\n\
         mysql -u root -p\n\
         SELECT * FROM users LIMIT 10;\n\
         netstat -tlnp\n\
         iptables -L -n\n\
         apt update && apt upgrade -y\n\
         cat /etc/ssh/sshd_config\n\
         vim /etc/nginx/sites-available/default\n\
         certbot renew\n\
         df -h\n\
         htop\n\
         git pull origin main\n\
         pip install -r requirements.txt\n\
         python3 manage.py runserver 0.0.0.0:8000\n\
         crontab -l\n\
         tar -czf backup_$(date +%Y%m%d).tar.gz /var/www/html\n\
         scp backup.tar.gz admin@10.13.37.10:/backups/\n"
            .to_string()
    }
}

impl Default for FilesystemGenerator {
    fn default() -> Self {
        Self::new()
    }
}

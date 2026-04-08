//! Fake service emulators (SSH banner, HTTP, MySQL prompt, etc.)

pub struct ServiceEmulator;

impl ServiceEmulator {
    pub fn ssh_banner() -> String {
        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6".to_string()
    }

    pub fn http_response(path: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\n\
             Server: Apache/2.4.41 (Ubuntu)\r\n\
             Content-Type: text/html; charset=UTF-8\r\n\
             X-Powered-By: PHP/8.1.2\r\n\
             \r\n\
             <!DOCTYPE html><html><head><title>Internal Portal</title></head>\
             <body><h1>Corporate Intranet</h1><p>Path: {}</p></body></html>",
            path
        )
    }

    pub fn mysql_greeting() -> String {
        "Welcome to the MySQL monitor. Commands end with ; or \\g.\n\
         Your MySQL connection id is 42\n\
         Server version: 8.0.33-0ubuntu0.22.04.1 (Ubuntu)\n\
         mysql> "
            .to_string()
    }

    pub fn ftp_banner() -> String {
        "220 ProFTPD 1.3.5 Server (Corporate FTP) [10.13.37.50]\r\n".to_string()
    }

    pub fn smtp_banner() -> String {
        "220 mail.corp.local ESMTP Postfix (Ubuntu)\r\n".to_string()
    }

    pub fn rdp_banner() -> Vec<u8> {
        // RDP uses binary protocol - return minimal connection response
        vec![
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02, 0x01, 0x08,
            0x00, 0x02, 0x00, 0x00, 0x00,
        ]
    }
}

//! Deception Brain — LLM integration for complex command responses.
//! When the Ghost Shell cannot handle a command with templates,
//! it falls back to this AI brain for hyper-realistic generation.

use anyhow::Result;
use maya_core::config::AiConfig;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// LLM request for Ollama-compatible API.
#[derive(Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    system: String,
    stream: bool,
    options: OllamaOptions,
}

#[derive(Serialize)]
struct OllamaOptions {
    temperature: f32,
    num_predict: u32,
    top_p: f32,
}

/// LLM response from Ollama.
#[derive(Deserialize)]
struct OllamaResponse {
    response: String,
}

/// The Deception Brain — generates hyper-realistic terminal output.
pub struct DeceptionBrain {
    config: AiConfig,
    client: Client,
    system_prompt: String,
}

impl DeceptionBrain {
    pub fn new(config: AiConfig) -> Self {
        let system_prompt = r#"You are simulating a production Linux server terminal. 
You MUST respond ONLY with the exact terminal output that the given command would produce.
DO NOT add any explanations, comments, or markdown formatting.
The server is an Ubuntu 22.04 LTS running Apache, MySQL, and SSH.
Hostname: srv-001.corp.local
IP: 10.13.37.105
The server has been running for 47 days.
There are real services running: Apache on 80/443, MySQL on 3306, SSH on 22.
The /data directory contains a MySQL backup and application files.
Generate realistic, logically consistent output."#
            .to_string();

        info!(
            model = %config.model_name,
            endpoint = %config.llm_endpoint,
            "🧠 Deception Brain initialized"
        );

        Self {
            config,
            client: Client::new(),
            system_prompt,
        }
    }

    /// Generate a response for any command using the LLM.
    pub async fn generate_response(
        &self,
        command: &str,
        context: &CommandContext,
    ) -> Result<String> {
        let prompt = format!(
            "The user (attacker) executed this command:\n$ {}\n\n\
             Current directory: {}\n\
             Current user: {}\n\
             Previous commands: {:?}\n\n\
             Generate the EXACT terminal output this command would produce.",
            command, context.cwd, context.user, context.recent_commands
        );

        let request = OllamaRequest {
            model: self.config.model_name.clone(),
            prompt,
            system: self.system_prompt.clone(),
            stream: false,
            options: OllamaOptions {
                temperature: self.config.temperature,
                num_predict: 2048,
                top_p: 0.9,
            },
        };

        let response = self
            .client
            .post(format!("{}/api/generate", self.config.llm_endpoint))
            .json(&request)
            .timeout(std::time::Duration::from_secs(self.config.timeout_secs))
            .send()
            .await;

        match response {
            Ok(resp) => {
                let ollama_resp: OllamaResponse = resp.json().await?;
                debug!(
                    cmd = command,
                    response_len = ollama_resp.response.len(),
                    "🧠 AI generated response"
                );
                Ok(ollama_resp.response)
            }
            Err(e) => {
                warn!("🧠 LLM unavailable: {} — using template fallback", e);
                Ok(format!(
                    "-bash: {}: command not found\n",
                    command.split_whitespace().next().unwrap_or(command)
                ))
            }
        }
    }

    /// Generate fake but consistent database query results.
    pub async fn generate_sql_result(&self, query: &str) -> Result<String> {
        let prompt = format!(
            "A MySQL 8.0 server received this query:\n{}\n\n\
             Generate realistic MySQL terminal output with fake but consistent Indian data.\n\
             Include proper table formatting with +---+ borders.\n\
             Data should include realistic Indian names, Aadhaar numbers, PAN numbers.\n\
             End with 'X rows in set (0.XX sec)' format.",
            query
        );

        let request = OllamaRequest {
            model: self.config.model_name.clone(),
            prompt,
            system: "You are a MySQL 8.0 server. Respond ONLY with MySQL terminal output.".into(),
            stream: false,
            options: OllamaOptions {
                temperature: 0.2,
                num_predict: 4096,
                top_p: 0.9,
            },
        };

        match self
            .client
            .post(format!("{}/api/generate", self.config.llm_endpoint))
            .json(&request)
            .timeout(std::time::Duration::from_secs(self.config.timeout_secs))
            .send()
            .await
        {
            Ok(resp) => {
                let r: OllamaResponse = resp.json().await?;
                Ok(r.response)
            }
            Err(_) => Ok("ERROR 1064 (42000): You have an error in your SQL syntax\n".to_string()),
        }
    }
}

/// Context for AI generation — maintains session state.
#[derive(Debug, Clone)]
pub struct CommandContext {
    pub cwd: String,
    pub user: String,
    pub hostname: String,
    pub recent_commands: Vec<String>,
    pub session_duration_secs: u64,
}

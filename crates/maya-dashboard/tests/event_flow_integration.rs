use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use maya_core::config::MayaConfig;
use maya_core::events::{EventBus, MayaEvent};
use maya_core::types::{DecoyId, DecoyType, EngagementLevel, Protocol, SessionId, Severity};
use maya_dashboard::state::DashboardState;
use maya_deception::DeceptionOrchestrator;
use maya_network::NetworkEngine;

#[tokio::test]
async fn event_chain_network_deception_dashboard_updates_state() {
    let config = MayaConfig::default_dev();
    let event_bus = Arc::new(EventBus::new());

    let network = NetworkEngine::new(config.network.clone(), event_bus.clone());
    network.start().await.expect("network start");

    let orchestrator = DeceptionOrchestrator::new(
        config.deception.clone(),
        config.network.decoy_subnet.clone(),
        event_bus.clone(),
    );
    assert_eq!(orchestrator.active_decoy_count(), 0);

    let dashboard_state = DashboardState::new();
    let mut rx = event_bus.subscribe();
    let state_for_listener = dashboard_state.clone();

    let listener = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => state_for_listener.apply_event(event).await,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    let attacker_ip: IpAddr = "203.0.113.77".parse().expect("attacker ip");
    network
        .process_connection(attacker_ip, 44444, 22, Protocol::Tcp)
        .await
        .expect("connection processing");

    let decoy_id = DecoyId::new();
    event_bus
        .publish(MayaEvent::DecoySpawned {
            decoy_id: decoy_id.clone(),
            decoy_type: DecoyType::LinuxServer,
            ip_addr: "10.13.37.99".parse().expect("decoy ip"),
            services: vec![22, 80],
        })
        .expect("publish decoy spawned");

    let session_id = SessionId::new();
    event_bus
        .publish(MayaEvent::AttackerEngaged {
            session_id: session_id.clone(),
            attacker_ip,
            decoy_id: decoy_id.clone(),
            engagement_level: EngagementLevel::High,
        })
        .expect("publish attacker engaged");

    event_bus
        .publish(MayaEvent::CommandExecuted {
            session_id,
            command: "cat /etc/passwd".to_string(),
            command_label: Some("credential_discovery".to_string()),
            severity: Some(Severity::High),
            decoy_id,
            decoy_type: Some(DecoyType::LinuxServer),
            metadata: HashMap::new(),
            timestamp: Utc::now(),
        })
        .expect("publish command executed");

    tokio::time::sleep(Duration::from_millis(120)).await;

    let stats = dashboard_state.stats_snapshot().await;
    assert_eq!(stats.active_decoys, 1, "decoy spawn should update stats");
    assert_eq!(stats.active_sessions, 1, "engagement should increase sessions");
    assert_eq!(stats.trapped_attackers, 1, "attacker set should be tracked");

    let stream = dashboard_state.recent_stream(20).await;
    assert!(
        stream
            .iter()
            .any(|entry| entry.feed.source_module == "network"),
        "network-origin feed events should be present"
    );
    assert!(
        stream
            .iter()
            .any(|entry| entry.feed.source_module == "deception"),
        "deception-origin feed events should be present"
    );
    assert!(
        stream
            .iter()
            .any(|entry| entry.feed.command_label == "credential_discovery"),
        "deception command label should flow into dashboard feed"
    );

    listener.abort();
}

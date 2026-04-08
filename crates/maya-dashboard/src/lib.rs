//! # Maya Dashboard — SOC Dashboard API
//! Real-time threat visualization, attacker tracking, and alert management.

pub mod api;
pub mod server;
pub mod state;
pub use server::DashboardServer;

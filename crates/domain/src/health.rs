use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Ok,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheckResponse {
    pub status: HealthStatus,
    pub app_name: String,
    pub architecture: String,
}

impl HealthCheckResponse {
    pub fn ok(app_name: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Ok,
            app_name: app_name.into(),
            architecture: std::env::consts::ARCH.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_response_serializes_for_ipc() {
        let response = HealthCheckResponse {
            status: HealthStatus::Ok,
            app_name: "Lawyer Assistance".to_owned(),
            architecture: "x86_64".to_owned(),
        };

        let serialized = serde_json::to_value(response).expect("health response serializes");

        assert_eq!(serialized["status"], "ok");
        assert_eq!(serialized["appName"], "Lawyer Assistance");
        assert_eq!(serialized["architecture"], "x86_64");
    }
}

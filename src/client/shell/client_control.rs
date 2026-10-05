use super::*;

pub(crate) fn control_machine_id(endpoint: &ClientEndpointId) -> &str {
    match endpoint {
        ClientEndpointId::Local => "local",
        ClientEndpointId::Ssh(profile) => profile.as_str(),
    }
}

impl ClientShellState {
    pub(crate) fn control_snapshot(
        &self,
        client_id: &str,
        transitioning: bool,
    ) -> serde_json::Value {
        let selected_pane = self
            .snapshot
            .as_deref()
            .and_then(|snapshot| snapshot.focused_pane_id.as_deref());
        let machines = self.endpoints.iter().map(|endpoint| {
            // Disconnected snapshots are retained for recovery, not live observations.
            let snapshot = (endpoint.status == ClientEndpointStatus::Online)
                .then_some(endpoint.snapshot.as_deref()).flatten();
            let agents = snapshot.map(|snapshot| snapshot.agents.iter().map(|agent| {
                serde_json::json!({
                    "pane_id": agent.pane_id,
                    "tab_id": agent.tab_id,
                    "workspace_id": agent.workspace_id,
                    "agent": agent.agent,
                    "agent_status": agent.agent_status,
                    "state_change_seq": agent.state_change_seq,
                    "focused": !transitioning && endpoint.endpoint_id == self.active_endpoint_id
                        && selected_pane == Some(agent.pane_id.as_str()),
                })
            }).collect::<Vec<_>>()).unwrap_or_default();
            serde_json::json!({
                "machine_id": control_machine_id(&endpoint.endpoint_id),
                "label": endpoint.label,
                "status": match endpoint.status {
                    ClientEndpointStatus::Online => "online",
                    ClientEndpointStatus::Connecting => "connecting",
                    ClientEndpointStatus::Reconnecting => "reconnecting",
                    ClientEndpointStatus::Attention => "attention",
                    ClientEndpointStatus::Disabled => "disabled",
                },
                "boot_id": snapshot.map(|snapshot| snapshot.boot_id.as_str()),
                "focused_pane_id": snapshot.and_then(|snapshot| snapshot.focused_pane_id.as_deref()),
                "agents": agents,
            })
        }).collect::<Vec<_>>();
        serde_json::json!({
            "client_id": client_id,
            "selected_machine_id": control_machine_id(&self.active_endpoint_id),
            "selected_pane_id": selected_pane,
            "transitioning": transitioning,
            "machines": machines,
        })
    }

    pub(crate) fn control_focus_target(
        &self,
        machine_id: &str,
        pane_id: Option<&str>,
    ) -> Result<(ClientEndpointId, Option<ClientEndpointFocusTarget>), (&'static str, String)> {
        let endpoint_id = if machine_id == "local" {
            ClientEndpointId::Local
        } else {
            ClientEndpointId::Ssh(
                super::super::endpoint::ProfileId::parse(machine_id)
                    .map_err(|error| ("invalid_params", error))?,
            )
        };
        let endpoint = self
            .endpoints
            .iter()
            .find(|endpoint| endpoint.endpoint_id == endpoint_id)
            .ok_or_else(|| {
                (
                    "machine_not_found",
                    "The client has no such saved machine.".into(),
                )
            })?;
        if !self.endpoint_is_online(&endpoint_id) {
            return Err((
                "machine_unavailable",
                "The selected machine is not online in this client.".into(),
            ));
        }
        let target = pane_id
            .map(|pane_id| {
                if pane_id.trim().is_empty() {
                    return Err(("invalid_params", "pane_id must not be blank.".into()));
                }
                let exists = endpoint.snapshot.as_deref().is_some_and(|snapshot| {
                    snapshot.panes.iter().any(|pane| pane.pane_id == pane_id)
                });
                if !exists {
                    return Err((
                        "pane_not_found",
                        "The machine has no such pane in the client's snapshot.".into(),
                    ));
                }
                Ok(ClientEndpointFocusTarget::Pane(pane_id.to_owned()))
            })
            .transpose()?;
        Ok((endpoint_id, target))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(
        boot_id: &str,
        status: crate::api::schema::AgentStatus,
    ) -> Box<ClientShellSnapshot> {
        Box::new(ClientShellSnapshot {
            boot_id: boot_id.into(),
            revision: 1,
            config_diagnostic: None,
            product_announcement: None,
            update_available: None,
            update_install_command: String::new(),
            server_keybindings_toml: None,
            latest_release_notes_available: false,
            integration_updates_available: false,
            worktree_directory: String::new(),
            release_notes: None,
            focused_workspace_id: Some("w1".into()),
            focused_tab_id: Some("w1:t1".into()),
            focused_pane_id: Some("w1:p1".into()),
            tab_bar_right: Vec::new(),
            tab_bar_right_separator: String::new(),
            agent_view_label: None,
            agent_order: Vec::new(),
            workspaces: Vec::new(),
            tabs: Vec::new(),
            commands: Vec::new(),
            panes: vec![crate::protocol::ClientShellPane {
                pane_id: "w1:p1".into(),
                workspace_id: "w1".into(),
                tab_id: "w1:t1".into(),
                label: None,
                cwd: None,
                foreground_cwd: None,
                focused: true,
                right_click_passthrough: false,
            }],
            agents: vec![crate::protocol::ClientShellAgent {
                pane_id: "w1:p1".into(),
                workspace_id: "w1".into(),
                tab_id: "w1:t1".into(),
                name: None,
                display_agent: None,
                agent: Some("omp".into()),
                title: None,
                terminal_title: None,
                terminal_title_stripped: None,
                agent_status: status,
                state_change_seq: 9,
                state_labels: Vec::new(),
                tokens: Vec::new(),
                focused: true,
            }],
        })
    }

    fn shell() -> (ClientShellState, ClientEndpointId) {
        let mut shell = ClientShellState::new(ClientShellConfig::from_config(&Config::default()));
        let profile = SavedSshEndpoint::new("Remote", "example.invalid", "default").unwrap();
        let remote = ClientEndpointId::Ssh(profile.id.clone());
        shell.set_endpoint_catalog(&[profile]);
        shell.set_snapshot(snapshot(
            "local-boot",
            crate::api::schema::AgentStatus::Idle,
        ));
        shell.set_endpoint_status(&remote, ClientEndpointStatus::Online);
        shell.set_endpoint_snapshot(
            &remote,
            snapshot("remote-boot", crate::api::schema::AgentStatus::Working),
        );
        (shell, remote)
    }

    #[test]
    fn control_snapshot_scopes_duplicate_panes_and_visible_focus_by_machine() {
        let (shell, remote) = shell();
        let snapshot = shell.control_snapshot("client", false);
        assert_eq!(snapshot["selected_machine_id"], "local");
        assert_eq!(snapshot["machines"][0]["agents"][0]["agent_status"], "idle");
        assert_eq!(
            snapshot["machines"][1]["machine_id"],
            control_machine_id(&remote)
        );
        assert_eq!(snapshot["machines"][1]["boot_id"], "remote-boot");
        assert_eq!(
            snapshot["machines"][1]["agents"][0]["agent_status"],
            "working"
        );
        assert_eq!(snapshot["machines"][0]["agents"][0]["focused"], true);
        assert_eq!(snapshot["machines"][1]["agents"][0]["focused"], false);
    }

    #[test]
    fn control_snapshot_does_not_publish_stale_offline_agents() {
        let (mut shell, remote) = shell();
        shell.mark_endpoint_disconnected(&remote);
        let snapshot = shell.control_snapshot("client", false);
        assert_eq!(snapshot["machines"][1]["status"], "reconnecting");
        assert_eq!(snapshot["machines"][1]["agents"], serde_json::json!([]));
        assert_eq!(snapshot["machines"][1]["boot_id"], serde_json::Value::Null);
        assert_eq!(
            shell
                .control_focus_target(control_machine_id(&remote), Some("w1:p1"))
                .unwrap_err()
                .0,
            "machine_unavailable"
        );
    }

    #[test]
    fn control_focus_validates_pane_in_the_addressed_machine() {
        let (mut shell, remote) = shell();
        shell.set_endpoint_snapshot(&remote, {
            let mut snapshot = snapshot("remote-boot", crate::api::schema::AgentStatus::Idle);
            snapshot.panes.clear();
            snapshot
        });
        assert_eq!(
            shell
                .control_focus_target(control_machine_id(&remote), Some("w1:p1"))
                .unwrap_err()
                .0,
            "pane_not_found"
        );
        assert_eq!(
            shell
                .control_focus_target("local", Some("w1:p1"))
                .unwrap()
                .0,
            ClientEndpointId::Local
        );
    }
}

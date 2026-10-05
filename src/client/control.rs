use super::*;
use crate::client_control::{ControlCommand, ControlEvent};

pub(super) struct PendingControlFocus {
    pub(super) id: String,
    pub(super) reply: tokio::sync::oneshot::Sender<serde_json::Value>,
    pub(super) endpoint_id: endpoint::ClientEndpointId,
    pub(super) pane_id: Option<String>,
}

impl PendingControlFocus {
    pub(super) fn fail(self, code: &str, message: impl Into<String>) {
        let _ = self
            .reply
            .send(crate::client_control::error(&self.id, code, message));
    }

    pub(super) fn complete(self) {
        let result = serde_json::json!({
            "machine_id": shell::control_machine_id(&self.endpoint_id),
            "pane_id": self.pane_id,
        });
        let _ = self
            .reply
            .send(crate::client_control::success(&self.id, result));
    }
}

impl ClientState {
    pub(super) fn fail_control_focus(&mut self, code: &str, message: impl Into<String>) {
        if let Some(request) = self.control_focus.take() {
            request.fail(code, message);
        }
    }
}

pub(super) fn cancel_disconnected_focus(
    state: &mut ClientState,
    endpoints: &mut endpoint::EndpointRegistry,
    pending: &mut Option<endpoint::PendingEndpointActivation>,
) {
    if state
        .control_focus
        .as_ref()
        .is_some_and(|request| request.reply.is_closed())
    {
        shell_runtime::rollback_endpoint_activation(
            state,
            endpoints,
            pending,
            "Client control caller disconnected or its request expired.".into(),
            false,
        );
    }
}

pub(super) fn handle_control_event(
    event: ControlEvent,
    client_id: &str,
    state: &mut ClientState,
    endpoints: &mut endpoint::EndpointRegistry,
    commands: &mut endpoint_commands::EndpointCommands,
    pending: &mut Option<endpoint::PendingEndpointActivation>,
    next_surface_serial: &mut u64,
    scheduled: bool,
    now: std::time::Instant,
) -> Option<endpoint::ClientEndpointId> {
    let ControlEvent { id, command, reply } = event;
    // A timed-out queued request must not navigate later.
    if reply.is_closed() {
        return None;
    }
    let Some(shell) = state.shell.as_ref() else {
        let _ = reply.send(crate::client_control::error(
            &id,
            "client_unavailable",
            "This client has no full TUI.",
        ));
        return None;
    };
    // A disconnected surface stays frozen until a healthy endpoint is selected.
    // That is an unavailable presentation, not an in-progress handoff.
    let transitioning = pending.is_some() || scheduled || state.deferred_local_activation.is_some();
    match command {
        ControlCommand::Snapshot => {
            let _ = reply.send(crate::client_control::success(
                &id,
                shell.control_snapshot(client_id, transitioning),
            ));
        }
        ControlCommand::Focus {
            machine_id,
            pane_id,
        } => {
            if transitioning || state.control_focus.is_some() {
                let _ = reply.send(crate::client_control::error(
                    &id,
                    "client_busy",
                    "The client is already changing its presentation.",
                ));
                return None;
            }
            let (endpoint_id, target) =
                match shell.control_focus_target(&machine_id, pane_id.as_deref()) {
                    Ok(target) => target,
                    Err((code, message)) => {
                        let _ = reply.send(crate::client_control::error(&id, code, message));
                        return None;
                    }
                };
            let resize = client_shell_resize_message(
                shell,
                state.reported_size.0,
                state.reported_size.1,
                state.reported_cell_size.0,
                state.reported_cell_size.1,
                state.pixel_geometry_exact,
            );
            let prepared = endpoint::PendingEndpointActivation::prepare(
                shell,
                endpoints,
                endpoint_id.clone(),
                target,
                resize,
                *next_surface_serial,
                now,
            );
            let request = PendingControlFocus {
                id,
                reply,
                endpoint_id: endpoint_id.clone(),
                pane_id,
            };
            match prepared.and_then(|activation| activation.start(endpoints)) {
                Ok(activation) => {
                    install_pending_activation(
                        state,
                        commands,
                        pending,
                        next_surface_serial,
                        activation,
                    );
                    state.control_focus = Some(request);
                    return Some(endpoint_id);
                }
                Err(endpoint::ActivationBeginError::Preflight(message)) => {
                    request.fail("activation_failed", message);
                }
                Err(endpoint::ActivationBeginError::Partial { activation, error }) => {
                    install_pending_activation(
                        state,
                        commands,
                        pending,
                        next_surface_serial,
                        *activation,
                    );
                    request.fail("activation_failed", error.clone());
                    rollback_endpoint_activation(state, endpoints, pending, error, false);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_queued_control_request_cannot_start_navigation() {
        let mut state = ClientState::test_new();
        let mut registry = endpoint::EndpointRegistry::empty();
        let mut commands = endpoint_commands::EndpointCommands::default();
        let mut pending = None;
        let mut serial = 1;
        let (reply, receiver) = tokio::sync::oneshot::channel();
        drop(receiver);
        handle_control_event(
            ControlEvent {
                id: "expired".into(),
                command: ControlCommand::Focus {
                    machine_id: "local".into(),
                    pane_id: None,
                },
                reply,
            },
            "client",
            &mut state,
            &mut registry,
            &mut commands,
            &mut pending,
            &mut serial,
            false,
            std::time::Instant::now(),
        );
        assert!(state.control_focus.is_none());
        assert!(pending.is_none());
        assert!(!state.presentation_frozen);
        assert_eq!(serial, 1);
    }

    #[test]
    fn queued_authoritative_selection_rejects_external_navigation() {
        let mut state = ClientState::test_new();
        state.deferred_local_activation = Some(endpoint::EndpointActivationIntent {
            endpoint_id: endpoint::ClientEndpointId::Local,
            target: None,
        });
        let mut registry = endpoint::EndpointRegistry::empty();
        let mut commands = endpoint_commands::EndpointCommands::default();
        let mut pending = None;
        let mut serial = 1;
        let (reply, mut receiver) = tokio::sync::oneshot::channel();
        handle_control_event(
            ControlEvent {
                id: "focus".into(),
                command: ControlCommand::Focus {
                    machine_id: "local".into(),
                    pane_id: None,
                },
                reply,
            },
            "client",
            &mut state,
            &mut registry,
            &mut commands,
            &mut pending,
            &mut serial,
            false,
            std::time::Instant::now(),
        );
        assert_eq!(receiver.try_recv().unwrap()["error"]["code"], "client_busy");
        assert!(matches!(
            state.deferred_local_activation,
            Some(endpoint::EndpointActivationIntent {
                endpoint_id: endpoint::ClientEndpointId::Local,
                target: None,
            })
        ));
        assert!(pending.is_none());
    }
}

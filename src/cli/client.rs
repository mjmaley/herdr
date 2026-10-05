use std::io;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::client::endpoint::{EndpointCatalog, SavedSshEndpoint};
use crate::client_control;

const HELP: &str = "Usage:
  herdr client list [--json]
  herdr client snapshot [--client <client-id>]
  herdr client focus <local|label-or-id> [--pane <pane-id>] [--client <client-id>]

Experimental fork feature: controls one local full TUI, not a server.
Use list to discover live client IDs. With multiple clients, --client is required.
Focus never broadcasts, installs, starts, or restarts Herdr.";

#[derive(Debug, PartialEq, Eq)]
enum ClientArgs {
    List {
        json: bool,
    },
    Snapshot {
        client: Option<String>,
    },
    Focus {
        machine: String,
        pane: Option<String>,
        client: Option<String>,
    },
    Help,
}

pub(super) fn run_client_command(args: &[String]) -> io::Result<i32> {
    let args = match parse_args(args) {
        Ok(args) => args,
        Err(message) => return usage_error(&message),
    };
    if args == ClientArgs::Help {
        println!("{HELP}");
        return Ok(0);
    }

    // Resolve profiles before any control request, and never use the persisted
    // selected profile as a substitute for a live client selection.
    let machine_id = if let ClientArgs::Focus { machine, .. } = &args {
        let profiles = if machine == "local" {
            Vec::new()
        } else {
            EndpointCatalog::load_profiles().map_err(io::Error::other)?
        };
        match resolve_machine_id(&profiles, machine) {
            Ok(id) => Some(id),
            Err(message) => return usage_error(&message),
        }
    } else {
        None
    };

    let clients = inspect_clients(client_control::discover()?, client_control::request);
    match args {
        ClientArgs::List { json } => list(&clients, json),
        ClientArgs::Snapshot { client } => {
            let selected = match select_client(&clients, client.as_deref()) {
                Ok(selected) => selected,
                Err(message) => return usage_error(&message),
            };
            super::print_response(&selected.response)
        }
        ClientArgs::Focus { pane, client, .. } => {
            let selected = match select_client(&clients, client.as_deref()) {
                Ok(selected) => selected,
                Err(message) => return usage_error(&message),
            };
            let Some(machine_id) = machine_id else {
                return Err(io::Error::other("missing resolved machine ID"));
            };
            let mut params = json!({ "machine_id": machine_id });
            if let Some(pane) = pane {
                params["pane_id"] = Value::String(pane);
            }
            let response = client_control::request(&selected.path, "client.focus", params)?;
            super::print_response(&response)
        }
        ClientArgs::Help => Ok(0),
    }
}

fn usage_error(message: &str) -> io::Result<i32> {
    eprintln!("error: {message}\n{HELP}");
    Ok(2)
}

fn parse_args(args: &[String]) -> Result<ClientArgs, String> {
    let args = super::expand_equals_args(args, &["--client", "--pane"]);
    let Some(command) = args.first().map(String::as_str) else {
        return Err("a client subcommand is required".into());
    };
    if matches!(command, "help" | "--help" | "-h") && args.len() == 1 {
        return Ok(ClientArgs::Help);
    }
    if command == "list" {
        return match &args[1..] {
            [] => Ok(ClientArgs::List { json: false }),
            [flag] if flag == "--json" => Ok(ClientArgs::List { json: true }),
            _ => Err("client list accepts only --json".into()),
        };
    }
    if !matches!(command, "snapshot" | "focus") {
        return Err(format!("unknown client command '{command}'"));
    }
    let mut client = None;
    let mut pane = None;
    let mut machine = None;
    let mut rest = args[1..].iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--client" | "--pane" => {
                if arg == "--pane" && command != "focus" {
                    return Err("--pane is only valid for client focus".into());
                }
                let slot = if arg == "--client" {
                    &mut client
                } else {
                    &mut pane
                };
                if slot.is_some() {
                    return Err(format!("{arg} may be specified only once"));
                }
                let value = rest
                    .next()
                    .filter(|value| !value.is_empty() && !value.starts_with('-'))
                    .ok_or_else(|| format!("{arg} requires a nonempty value"))?;
                if arg == "--client" && !valid_client_id(value) {
                    return Err(
                        "--client must be a client ID from `herdr client list`, not a path".into(),
                    );
                }
                *slot = Some(value.clone());
            }
            _ if command == "focus" && !arg.starts_with('-') && machine.is_none() => {
                if arg.is_empty() {
                    return Err("client focus requires a nonempty machine selector".into());
                }
                machine = Some(arg.clone());
            }
            _ => return Err(format!("unexpected client {command} argument '{arg}'")),
        }
    }
    if command == "snapshot" {
        Ok(ClientArgs::Snapshot { client })
    } else {
        Ok(ClientArgs::Focus {
            machine: machine.ok_or("client focus requires local or a saved machine label/ID")?,
            pane,
            client,
        })
    }
}

fn valid_client_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn resolve_machine_id(profiles: &[SavedSshEndpoint], selector: &str) -> Result<String, String> {
    if selector == "local" {
        return Ok("local".into());
    }
    super::target::resolve_machine(profiles, selector).map(|profile| profile.id.as_str().to_owned())
}

#[derive(Debug)]
struct LiveClient {
    path: PathBuf,
    response: Value,
}

impl LiveClient {
    fn from_snapshot(path: PathBuf, response: Value) -> Option<Self> {
        let stem = path.file_stem()?.to_str()?;
        let result = response.get("result")?.as_object()?;
        if response.get("error").is_some()
            || !valid_client_id(stem)
            || result.get("client_id")?.as_str()? != stem
            || result.get("selected_machine_id")?.as_str()?.is_empty()
            || !result.get("machines")?.is_array()
        {
            return None;
        }
        Some(Self { path, response })
    }

    fn id(&self) -> &str {
        // Admission above guarantees this field exists and is a string.
        self.response["result"]["client_id"]
            .as_str()
            .unwrap_or_default()
    }
}

fn inspect_clients(
    paths: Vec<PathBuf>,
    mut request: impl FnMut(&Path, &str, Value) -> io::Result<Value>,
) -> Vec<LiveClient> {
    paths
        .into_iter()
        .filter_map(|path| {
            let response = request(&path, "client.snapshot", json!({})).ok()?;
            LiveClient::from_snapshot(path, response)
        })
        .collect()
}

fn select_client<'a>(
    clients: &'a [LiveClient],
    selector: Option<&str>,
) -> Result<&'a LiveClient, String> {
    if let Some(selector) = selector {
        if !valid_client_id(selector) {
            return Err("--client must be a client ID, not a path".into());
        }
        let mut matches = clients.iter().filter(|client| client.id() == selector);
        let selected = matches
            .next()
            .ok_or_else(|| format!("no live client '{selector}'; use `herdr client list`"))?;
        if matches.next().is_some() {
            return Err(format!("client ID '{selector}' is ambiguous"));
        }
        return Ok(selected);
    }
    match clients {
        [selected] => Ok(selected),
        [] => Err("no live full TUI clients; open this fork's TUI first".into()),
        _ => Err(
            "multiple live clients; choose --client <client-id> from `herdr client list`".into(),
        ),
    }
}

fn list(clients: &[LiveClient], json_output: bool) -> io::Result<i32> {
    if json_output {
        let results = clients
            .iter()
            .map(|client| {
                let mut result = client.response["result"].clone();
                result["socket_path"] = json!(client.path);
                result
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::to_string(&results).map_err(io::Error::other)?
        );
    } else if clients.is_empty() {
        println!("No live full TUI clients.");
    } else {
        println!("CLIENT_ID\tMACHINE_ID\tPANE_ID\tTRANSITIONING\tSOCKET_PATH");
        for client in clients {
            let result = &client.response["result"];
            println!(
                "{}\t{}\t{}\t{}\t{}",
                client.id(),
                result["selected_machine_id"].as_str().unwrap_or_default(),
                result["selected_pane_id"].as_str().unwrap_or("-"),
                result["transitioning"].as_bool().unwrap_or(false),
                client.path.display(),
            );
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_A: &str = "0123456789abcdef0123456789abcdef";
    const CLIENT_B: &str = "fedcba9876543210fedcba9876543210";

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).into()).collect()
    }

    fn response(client_id: &str) -> Value {
        json!({
            "id": "test", "result": {
                "client_id": client_id,
                "selected_machine_id": "local",
                "selected_pane_id": "w1:p1",
                "transitioning": false,
                "machines": []
            }
        })
    }

    fn client(id: &str) -> LiveClient {
        LiveClient::from_snapshot(PathBuf::from(format!("{id}.sock")), response(id)).unwrap()
    }

    #[test]
    fn parses_focus_without_interpreting_machine_or_pane_payload() {
        for input in [
            args(&[
                "focus",
                "Build machine",
                "--pane",
                "w4:p2",
                "--client",
                CLIENT_A,
            ]),
            args(&[
                "focus",
                &format!("--client={CLIENT_A}"),
                "--pane=w4:p2",
                "Build machine",
            ]),
        ] {
            assert_eq!(
                parse_args(&input).unwrap(),
                ClientArgs::Focus {
                    machine: "Build machine".into(),
                    pane: Some("w4:p2".into()),
                    client: Some(CLIENT_A.into()),
                }
            );
        }
        let literal = "$(touch /tmp/not-executed);host";
        assert_eq!(
            parse_args(&args(&["focus", literal])).unwrap(),
            ClientArgs::Focus {
                machine: literal.into(),
                pane: None,
                client: None,
            }
        );
    }

    #[test]
    fn rejects_missing_duplicate_unknown_and_path_arguments() {
        for input in [
            args(&[]),
            args(&["focus"]),
            args(&["focus", ""]),
            args(&["focus", "local", "extra"]),
            args(&["focus", "local", "--pane"]),
            args(&["focus", "local", "--pane="]),
            args(&["focus", "local", "--pane", "p1", "--pane", "p2"]),
            args(&["snapshot", "--client", CLIENT_A, "--client", CLIENT_B]),
            args(&["snapshot", "--client"]),
            args(&["snapshot", "--client", "--pane"]),
            args(&["snapshot", "--pane", "p1"]),
            args(&["snapshot", "local"]),
            args(&["list", "--client", CLIENT_A]),
            args(&["list", "--json", "--json"]),
            args(&["focus", "local", "--json"]),
            args(&["select", "local"]),
        ] {
            assert!(parse_args(&input).is_err(), "{input:?}");
        }
        for selector in [
            "../a",
            "/tmp/a",
            "a.sock",
            "..",
            "a/b",
            "a\\b",
            "a:b",
            "",
            "abc123",
            "0123456789ABCDEF0123456789ABCDEF",
        ] {
            assert!(
                parse_args(&args(&["snapshot", "--client", selector])).is_err(),
                "{selector}"
            );
        }
        assert_eq!(
            parse_args(&args(&["list", "--json"])).unwrap(),
            ClientArgs::List { json: true }
        );
        assert_eq!(
            parse_args(&args(&["snapshot"])).unwrap(),
            ClientArgs::Snapshot { client: None }
        );
    }

    #[test]
    fn parses_snapshot_with_exact_client_id_and_help() {
        assert_eq!(
            parse_args(&args(&["snapshot", &format!("--client={CLIENT_A}")])).unwrap(),
            ClientArgs::Snapshot {
                client: Some(CLIENT_A.into())
            },
        );
        for flag in ["help", "--help", "-h"] {
            assert_eq!(parse_args(&args(&[flag])).unwrap(), ClientArgs::Help);
        }
    }

    #[test]
    fn requires_exact_unique_live_client_selection() {
        assert!(select_client(&[], None).is_err());
        let clients = vec![client(CLIENT_A)];
        assert_eq!(select_client(&clients, None).unwrap().id(), CLIENT_A);
        assert!(select_client(&clients, Some("0123")).is_err());
        assert!(select_client(&clients, Some(CLIENT_B)).is_err());
        assert!(select_client(&clients, Some("../abc123")).is_err());
        let clients = vec![client(CLIENT_A), client(CLIENT_B)];
        assert!(select_client(&clients, None).is_err());
        assert_eq!(
            select_client(&clients, Some(CLIENT_B)).unwrap().id(),
            CLIENT_B
        );
        assert!(select_client(&[client(CLIENT_A), client(CLIENT_A)], Some(CLIENT_A)).is_err());
    }

    #[test]
    fn discovery_uses_read_only_snapshots_and_rejects_dead_or_mismatched_clients() {
        const MISMATCH: &str = "11111111111111111111111111111111";
        const MALFORMED: &str = "22222222222222222222222222222222";
        let paths = [
            format!("{CLIENT_A}.sock"),
            format!("{CLIENT_B}.sock"),
            "error.sock".into(),
            format!("{MISMATCH}.sock"),
            format!("{MALFORMED}.sock"),
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect();
        let clients = inspect_clients(paths, |path, method, params| {
            assert_eq!(method, "client.snapshot");
            assert_eq!(params, json!({}));
            let stem = path.file_stem().unwrap().to_str().unwrap();
            match stem {
                CLIENT_A => Ok(response(CLIENT_A)),
                CLIENT_B => Err(io::ErrorKind::ConnectionRefused.into()),
                "error" => Ok(client_control::error(
                    "test",
                    "client_unavailable",
                    "closing",
                )),
                MISMATCH => Ok(response(CLIENT_B)),
                _ => Ok(json!({"id": "test", "result": {"client_id": MALFORMED}})),
            }
        });
        assert_eq!(clients.len(), 1);
        assert_eq!(select_client(&clients, None).unwrap().id(), CLIENT_A);
        assert!(select_client(&clients, Some(CLIENT_B)).is_err());
    }

    #[test]
    fn machine_resolution_preserves_ids_and_rejects_disabled_unknown_or_ambiguous_labels() {
        let profile = SavedSshEndpoint::new("Build machine", "ssh-host", "agents").unwrap();
        let profiles = vec![profile.clone()];
        assert_eq!(resolve_machine_id(&profiles, "local").unwrap(), "local");
        assert_eq!(
            resolve_machine_id(&profiles, "Build machine").unwrap(),
            profile.id.as_str()
        );
        assert_eq!(
            resolve_machine_id(&profiles, profile.id.as_str()).unwrap(),
            profile.id.as_str()
        );
        assert!(resolve_machine_id(&profiles, "build machine").is_err());
        assert!(resolve_machine_id(&profiles, "ssh-host").is_err());
        assert!(resolve_machine_id(&profiles, "missing").is_err());
        let duplicate = SavedSshEndpoint::new("Build machine", "other", "default").unwrap();
        assert!(resolve_machine_id(&[profile.clone(), duplicate], "Build machine").is_err());
        let mut disabled = profile;
        disabled.enabled = false;
        assert!(resolve_machine_id(&[disabled.clone()], disabled.id.as_str()).is_err());
        assert!(resolve_machine_id(&[disabled], "Build machine").is_err());
    }

    #[test]
    fn machine_prefix_cannot_forward_client_navigation() {
        for command in [
            args(&["list"]),
            args(&["snapshot"]),
            args(&["focus", "local"]),
        ] {
            let mut input = args(&["herdr", "--machine", "remote", "client"]);
            input.extend(command);
            assert!(matches!(
                super::super::maybe_run_machine(&input),
                Some(Ok(super::super::CommandOutcome::Handled(2)))
            ));
        }
    }
}

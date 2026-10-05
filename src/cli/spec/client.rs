use clap::Command;

use super::{json_flag, option, required};

pub(super) fn command() -> Command {
    Command::new("client")
        .about("Inspect or navigate one local TUI client (experimental fork)")
        .subcommand(
            Command::new("list")
                .about("List live full TUI clients and their current selection")
                .arg(json_flag()),
        )
        .subcommand(
            Command::new("snapshot")
                .about("Print one live client's machine and agent metadata as JSON")
                .arg(client_option()),
        )
        .subcommand(
            Command::new("focus")
                .about("Activate a machine and optional pane in one local TUI client")
                .arg(
                    required("machine", "LOCAL_OR_LABEL_OR_ID").help(
                        "local, an enabled saved profile ID, or a unique case-sensitive label",
                    ),
                )
                .arg(option("pane", "PANE_ID").help("Focus this pane on the target machine"))
                .arg(client_option()),
        )
}

fn client_option() -> clap::Arg {
    option("client", "CLIENT_ID")
        .help("Exact live client ID from client list; required unless exactly one client is live")
}

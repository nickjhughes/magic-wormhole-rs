use clap::{Parser, Subcommand};
use futures_channel::mpsc::unbounded;
use futures_util::{future, StreamExt, TryStreamExt};
use log::{debug, error};
use magic_wormhole::message::ServerMessage;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

use client::*;

mod client;
mod crypto;
mod words;

#[derive(Parser, Debug)]
#[command(arg_required_else_help = true)]
#[command(
    version,
    about = "Create a Magic Wormhole and communicate through it.",
    long_about = "Create a Magic Wormhole and communicate through it.

Wormholes are created by speaking the same magic CODE in two different
places at the same time. Wormholes are secure against anyone who doesn't
use the same code."
)]
struct Cli {
    /// Application namespace ID to use
    #[arg(long, default_value = "nickjhughes.com/wormhole/text-xfer")]
    app_id: String,

    /// Mailbox server to use
    #[arg(long, value_name = "URL", default_value = "ws://127.0.0.1:4000/")]
    relay_url: String,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Receive a text message (from "wormhole send")
    Receive {
        #[arg(value_name = "CODE")]
        code: String,
    },

    /// Send a text message
    Send {
        /// Text message to send
        #[arg(long, value_name = "MESSAGE")]
        text: String,
    },
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let cli = Cli::parse();

    let mode = match cli.command.unwrap() {
        Command::Send { text } => {
            let msg_size = text.len();
            println!("Sending text message ({} bytes)", msg_size);
            debug!("Sending {:?} {:?}", text, text.as_bytes());
            ClientCommand::Send { text }
        }
        Command::Receive { code } => {
            debug!("Receiving with code {:?}", code);
            ClientCommand::Receive { code }
        }
    };

    let (ws_stream, _) = connect_async(cli.relay_url)
        .await
        .expect("failed to connect");
    debug!("websocket handshake has been successfully completed");
    let (ws_sender, ws_receiver) = ws_stream.split();
    let (tx, rx) = unbounded();
    let mut client = Client::new(mode, cli.app_id, tx);

    let handle_incoming = ws_receiver
        .try_filter(|msg| future::ready(msg.is_binary() || msg.is_text()))
        .try_for_each(|ws_msg| {
            let msg = match ws_msg {
                Message::Text(s) => serde_json::from_str::<ServerMessage>(&s),
                Message::Binary(v) => serde_json::from_slice::<ServerMessage>(&v),
                _ => unreachable!(),
            };

            if msg.is_err() {
                eprintln!("Failed to decode message: {:?}", msg.err());
                return future::ok(());
            }
            let msg = msg.unwrap();

            match &msg.ty {
                magic_wormhole::message::ServerMessageType::Ack => {
                    debug!("Recieved Ack for {:?}", msg.id.unwrap());
                }
                ty => debug!("Recieved {:?}", ty),
            }

            match &msg.ty {
                magic_wormhole::message::ServerMessageType::Welcome { welcome } => {
                    if let Some(motd) = &welcome.motd {
                        println!("{}", motd);
                    }
                    if let Some(error) = &welcome.error {
                        println!("{}", error);
                        return future::err(
                            tokio_tungstenite::tungstenite::Error::ConnectionClosed,
                        );
                    }

                    // Bind
                    if client.bind().is_err() {
                        error!("Bind failed");
                    } else {
                        // TODO: This logic should live inside Client
                        if matches!(client.command, ClientCommand::Send { .. }) {
                            // Try to allocate a nameplate
                            if client.allocate().is_err() {
                                error!("Allocate failed");
                            };
                        } else {
                            // Try to claim receive command nameplate
                            if client.claim(None).is_err() {
                                error!("Claim failed");
                            }
                        }
                    }
                }
                magic_wormhole::message::ServerMessageType::Nameplates { .. } => {}
                magic_wormhole::message::ServerMessageType::Allocated { nameplate_id } => {
                    if client.allocated(*nameplate_id).is_err() {
                        error!("Allocated failed");
                    };
                }
                magic_wormhole::message::ServerMessageType::Claimed { mailbox_id } => {
                    if client.claimed(mailbox_id).is_err() {
                        error!("Claimed failed");
                    };
                }
                magic_wormhole::message::ServerMessageType::Released => {}
                magic_wormhole::message::ServerMessageType::Message { side, phase, body } => {
                    if client.message(side, phase, body).is_err() {
                        error!("Message reception failed");
                    };
                }
                magic_wormhole::message::ServerMessageType::Closed => {
                    client.closed();
                }
                magic_wormhole::message::ServerMessageType::Ack => {}
                magic_wormhole::message::ServerMessageType::Pong { .. } => {}
                magic_wormhole::message::ServerMessageType::Error { error, .. } => {
                    error!("Server returned error: {:?}", error);
                }
            }

            if client.is_closed() {
                future::err(tokio_tungstenite::tungstenite::Error::ConnectionClosed)
            } else {
                future::ok(())
            }
        });

    let forward_to_websocket = rx.map(Ok).forward(ws_sender);

    future::select(handle_incoming, forward_to_websocket).await;
}

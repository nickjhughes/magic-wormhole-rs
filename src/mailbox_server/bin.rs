use futures_channel::mpsc::unbounded;
use futures_util::{future, StreamExt, TryStreamExt};
use log::{debug, error};
use std::{
    sync::{Arc, Mutex},
    {io, net::SocketAddr},
};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::{Error, Message, Result};

use magic_wormhole::message::{ClientMessage, ClientMessageType, ServerMessage};
use server::*;

mod app;
mod server;

async fn accept_connection(server: Arc<Mutex<MailboxServer>>, peer: SocketAddr, stream: TcpStream) {
    if let Err(e) = handle_connection(server, peer, stream).await {
        match e {
            Error::ConnectionClosed | Error::Protocol(_) | Error::Utf8 => (),
            err => error!("Error processing connection: {}", err),
        }
    }
}

async fn handle_connection(
    server: Arc<Mutex<MailboxServer>>,
    peer: SocketAddr,
    stream: TcpStream,
) -> Result<()> {
    let ws_stream = tokio_tungstenite::accept_async(stream)
        .await
        .expect("Error during the websocket handshake occurred");
    debug!("New WebSocket connection: {}", peer);
    let (ws_sender, ws_receiver) = ws_stream.split();
    let (tx, rx) = unbounded();
    let mut connection = Connection::new(tx);
    server
        .lock()
        .unwrap()
        .connect(&connection)
        .expect("failed to setup new connection");

    let handle_incoming = ws_receiver
        .try_filter(|msg| future::ready(msg.is_binary() || msg.is_text()))
        .try_for_each(|ws_msg| {
            let msg = match ws_msg {
                Message::Text(s) => serde_json::from_str::<ClientMessage>(&s),
                Message::Binary(v) => serde_json::from_slice::<ClientMessage>(&v),
                _ => unreachable!(),
            };
            if msg.is_err() {
                eprintln!("Failed to decode message");
                return future::ok(());
            }
            let msg = msg.unwrap();

            debug!("Recieved {:?}", &msg.ty);

            match server.lock().unwrap().ack(&connection, &msg) {
                Ok(()) => {}
                Err(e) => {
                    let error_msg = ServerMessage::error(&msg, &e.to_string());
                    connection.sender.unbounded_send(error_msg).unwrap();
                }
            }

            let result = match &msg.ty {
                ClientMessageType::Bind { app_id, side } => {
                    server.lock().unwrap().bind(&mut connection, app_id, side)
                }
                ClientMessageType::SubmitPermissions => {
                    // We don't accept any authentication schemes, so just ignore
                    Ok(())
                }
                ClientMessageType::List => server.lock().unwrap().list(&connection),
                ClientMessageType::Allocate => server.lock().unwrap().allocate(&mut connection),
                ClientMessageType::Claim { nameplate_id } => {
                    server.lock().unwrap().claim(&mut connection, *nameplate_id)
                }
                ClientMessageType::Release { nameplate_id } => server
                    .lock()
                    .unwrap()
                    .release(&mut connection, *nameplate_id),
                ClientMessageType::Open { mailbox_id } => {
                    server.lock().unwrap().open(&mut connection, mailbox_id)
                }
                ClientMessageType::Add { phase, body } => {
                    server
                        .lock()
                        .unwrap()
                        .add(&connection, &msg.id, phase, body)
                }
                ClientMessageType::Close { mailbox_id, .. } => {
                    server.lock().unwrap().close(&connection, mailbox_id)
                }
                ClientMessageType::Ping { ping } => {
                    server.lock().unwrap().ping(&connection, &msg.id, *ping)
                }
            };
            match result {
                Ok(()) => {}
                Err(e) => {
                    error!("{:?}", e);
                    let error_msg = ServerMessage::error(&msg, &e.to_string());
                    connection.sender.unbounded_send(error_msg).unwrap();
                }
            }

            future::ok(())
        });

    let forward_to_websocket = rx
        .map(|msg| {
            Ok(Message::Text(
                serde_json::to_string(&msg).expect("failed to encode message"),
            ))
        })
        .forward(ws_sender);

    future::select(handle_incoming, forward_to_websocket).await;

    server.lock().unwrap().disconnect(&mut connection);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    env_logger::init();

    let addr = "127.0.0.1:4000".to_string();
    let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
    debug!("Listening on: {}", addr);

    let state = Arc::new(Mutex::new(MailboxServer::default()));

    while let Ok((stream, _)) = listener.accept().await {
        let peer = stream
            .peer_addr()
            .expect("connected streams should have a peer address");
        debug!("Peer address: {}", peer);
        tokio::spawn(accept_connection(state.clone(), peer, stream));
    }

    Ok(())
}

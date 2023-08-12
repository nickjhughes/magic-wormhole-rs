/// Messages sent between the client and mailbox server.
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::time::{SystemTime, UNIX_EPOCH};

/// A message sent from the mailbox server to the client.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// All server -> client messages have a `server_tx` timestamp (seconds since epoch, as a
    /// float), which records when the message left the server.
    pub server_tx: f64,
    /// Direct responses include a `server_rx` timestamp, to record when the client's command
    /// was received.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_rx: Option<f64>,
    #[serde(rename = "type")]
    #[serde(flatten)]
    pub ty: ServerMessageType,
}

/// A message sent from the client to the mailbox server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientMessage {
    /// Client -> server messages include a random id key.
    pub id: String,
    #[serde(rename = "type")]
    #[serde(flatten)]
    pub ty: ClientMessageType,
}

/// An authentication method for access to the mailbox server.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum PermissionMethod {
    /// No permission required, send a normal `bind`.
    None,
}

/// Welcome information sent from the mailbox server to clients on connection.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub struct WelcomeInfo {
    /// This message is intended to inform users about performance problems, scheduled downtime,
    /// or to beg for donations to keep the server running. Clients should print it or otherwise
    /// display prominently to the user. The value should be a plain string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub motd: Option<String>,
    /// The client should show this message to the user and then terminate. The value should be a
    /// plain string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// A set of available authentication methods, proof of work challenges, etc. The client needs
    /// to "solve" one of them in order to get access to the service.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub permission_required: Vec<PermissionMethod>,
}

/// Information about a nameplate.
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NameplateInfo {
    #[serde_as(as = "DisplayFromStr")]
    pub id: usize,
}

/// Mood of the client. Reported to the server on disconnection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mood {
    /// The PAKE key-establishment worked, and the client saw at least one valid encrypted message
    /// from its peer
    Happy,
    /// The client gave up without hearing anything from its peer.
    Lonely,
    /// The client saw an invalid encrypted message from its peer, indicating that either the
    /// wormhole code was typed in wrong, or an attacker tried (and failed) to guess the code.
    Scary,
    /// The client encountered some other error: protocol problem or internal error.
    Errory,
}

/// Peer to peer message type.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// The initial PAKE message.
    Pake,
    /// An encrypted message with details of the peer's capabilities.
    Version,
    /// An encrypted application-specific message.
    #[serde(untagged)]
    Message(#[serde_as(as = "DisplayFromStr")] usize),
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
#[serde(tag = "type")]
pub enum ServerMessageType {
    /// welcome {welcome: {permission-required: hashcash: {}}
    Welcome { welcome: WelcomeInfo },
    /// nameplates {nameplates: [{id: str},..]}
    Nameplates { nameplates: Vec<NameplateInfo> },
    /// allocated {nameplate:}
    Allocated {
        #[serde(rename = "nameplate")]
        #[serde_as(as = "DisplayFromStr")]
        nameplate_id: usize,
    },
    /// claimed {mailbox:}
    Claimed {
        #[serde(rename = "mailbox")]
        mailbox_id: String,
    },
    /// released
    Released,
    /// message {side:, phase:, body:, id:}
    Message {
        side: String,
        phase: Phase,
        #[serde_as(as = "serde_with::hex::Hex")]
        body: Vec<u8>,
    },
    /// closed
    Closed,
    /// ack
    Ack,
    /// pong {pong: int}
    Pong { ping: u32 },
    /// error {error: str, orig:}
    Error { error: String, orig: ClientMessage },
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[serde(tag = "type")]
pub enum ClientMessageType {
    /// submit-permissions {..} (optional)
    SubmitPermissions,
    /// bind {appid:, side:, }
    Bind {
        #[serde(rename = "appid")]
        app_id: String,
        side: String,
    },
    /// list {} -> nameplates
    List,
    /// allocate {} -> allocated
    Allocate,
    /// claim {nameplate:} -> claimed
    Claim {
        #[serde(rename = "nameplate")]
        #[serde_as(as = "DisplayFromStr")]
        nameplate_id: usize,
    },
    /// release {nameplate:?} -> released
    Release {
        #[serde(rename = "nameplate")]
        #[serde_as(as = "Option<DisplayFromStr>")]
        nameplate_id: Option<usize>,
    },
    /// open {mailbox:}
    Open {
        #[serde(rename = "mailbox")]
        mailbox_id: String,
    },
    /// add {phase: str, body: hex} -> message (to all connected clients)
    Add {
        phase: Phase,
        #[serde_as(as = "serde_with::hex::Hex")]
        body: Vec<u8>,
    },
    /// close {mailbox:?, mood:?} -> closed
    Close {
        #[serde(rename = "mailbox")]
        mailbox_id: String,
        mood: Mood,
    },
    /// ping {ping: int} -> ping
    Ping { ping: u32 },
}

impl ServerMessage {
    /// Construct a message with the given `ty` information. The `server_tx` is automatically
    /// filled with the current timestamp.
    pub fn new(id: Option<String>, server_rx: Option<f64>, ty: ServerMessageType) -> Self {
        ServerMessage {
            id,
            server_tx: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
            server_rx,
            ty,
        }
    }

    /// Construct an Ack message for the given incoming message ID.
    pub fn ack(id: String) -> Self {
        ServerMessage::new(Some(id), None, ServerMessageType::Ack)
    }

    /// Construct an Error message for the given incoming message.
    pub fn error(client_msg: &ClientMessage, error: &str) -> Self {
        ServerMessage {
            id: Some(client_msg.id.clone()),
            server_tx: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
            server_rx: None,
            ty: ServerMessageType::Error {
                error: error.to_owned(),
                orig: client_msg.clone(),
            },
        }
    }
}

impl ClientMessage {
    /// Construct a message with the given `ty` information. A random message ID is generated
    /// and added to the `id` field.
    pub fn new(ty: ClientMessageType) -> Self {
        let id = {
            let mut rng = rand::thread_rng();
            let mut buffer = [0u8; 2];
            rng.fill_bytes(&mut buffer);
            hex::encode(buffer)
        };
        ClientMessage { id, ty }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClientMessage, ClientMessageType, Mood, Phase, ServerMessage, ServerMessageType,
        WelcomeInfo,
    };

    #[test]
    fn serialization() {
        // welcome
        let msg = ServerMessage {
            id: None,
            server_tx: 1687594898.0583792,
            server_rx: None,
            ty: ServerMessageType::Welcome {
                welcome: WelcomeInfo {
                    motd: None,
                    error: None,
                    permission_required: vec![],
                },
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(
            json,
            "{\"server_tx\":1687594898.0583792,\"type\":\"welcome\",\"welcome\":{}}"
        );

        // bind
        let msg = ClientMessage {
            id: "5d67".into(),
            ty: ClientMessageType::Bind {
                app_id: "lothar.com/wormhole/text-or-file-xfer".into(),
                side: "6d89484e10".into(),
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, "{\"id\":\"5d67\",\"type\":\"bind\",\"appid\":\"lothar.com/wormhole/text-or-file-xfer\",\"side\":\"6d89484e10\"}");

        // allocate
        let msg = ClientMessage {
            id: "2280".into(),
            ty: ClientMessageType::Allocate,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, "{\"id\":\"2280\",\"type\":\"allocate\"}");

        // ack
        let msg = ServerMessage {
            id: Some("5d67".into()),
            server_tx: 1687594898.2351809,
            server_rx: None,
            ty: ServerMessageType::Ack,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(
            json,
            "{\"id\":\"5d67\",\"server_tx\":1687594898.2351809,\"type\":\"ack\"}"
        );

        // allocated
        let msg = ServerMessage {
            id: None,
            server_tx: 1687594898.2387502,
            server_rx: None,
            ty: ServerMessageType::Allocated { nameplate_id: 6 },
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(
            json,
            "{\"server_tx\":1687594898.2387502,\"type\":\"allocated\",\"nameplate\":\"6\"}"
        );

        // claim
        let msg = ClientMessage {
            id: "e02d".into(),
            ty: ClientMessageType::Claim { nameplate_id: 6 },
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(
            json,
            "{\"id\":\"e02d\",\"type\":\"claim\",\"nameplate\":\"6\"}"
        );

        // claimed
        let msg = ServerMessage {
            id: None,
            server_tx: 1687594898.4249387,
            server_rx: None,
            ty: ServerMessageType::Claimed {
                mailbox_id: "ojr7vqldbwayg".into(),
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(
            json,
            "{\"server_tx\":1687594898.4249387,\"type\":\"claimed\",\"mailbox\":\"ojr7vqldbwayg\"}"
        );

        // release
        let msg = ClientMessage {
            id: "8b03".into(),
            ty: ClientMessageType::Release {
                nameplate_id: Some(6),
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(
            json,
            "{\"id\":\"8b03\",\"type\":\"release\",\"nameplate\":\"6\"}"
        );

        // released
        let msg = ServerMessage {
            id: None,
            server_tx: 1687594905.0208652,
            server_rx: None,
            ty: ServerMessageType::Released,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(
            json,
            "{\"server_tx\":1687594905.0208652,\"type\":\"released\"}"
        );

        // open
        let msg = ClientMessage {
            id: "dcf5".into(),
            ty: ClientMessageType::Open {
                mailbox_id: "ojr7vqldbwayg".into(),
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(
            json,
            "{\"id\":\"dcf5\",\"type\":\"open\",\"mailbox\":\"ojr7vqldbwayg\"}"
        );

        // add
        let msg = ClientMessage {
            id: "d8c1".into(),
            ty: ClientMessageType::Add {
                phase: Phase::Message(0),
                body: vec![0xf9, 0x21],
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(
            json,
            "{\"id\":\"d8c1\",\"type\":\"add\",\"phase\":\"0\",\"body\":\"f921\"}"
        );

        // message
        let msg = ServerMessage {
            id: Some("ec1e".into()),
            server_tx: 1687594905.022232,
            server_rx: Some(1687594905.0211902),
            ty: ServerMessageType::Message {
                side: "6d89484e10".into(),
                phase: Phase::Version,
                body: vec![0x60, 0x41],
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(
            json,"{\"id\":\"ec1e\",\"server_tx\":1687594905.022232,\"server_rx\":1687594905.0211902,\"type\":\"message\",\"side\":\"6d89484e10\",\"phase\":\"version\",\"body\":\"6041\"}");

        // close
        let msg = ClientMessage {
            id: "00c2".into(),
            ty: ClientMessageType::Close {
                mailbox_id: "ojr7vqldbwayg".into(),
                mood: Mood::Happy,
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(
            json,
            "{\"id\":\"00c2\",\"type\":\"close\",\"mailbox\":\"ojr7vqldbwayg\",\"mood\":\"happy\"}"
        );

        // closed
        let msg = ServerMessage {
            id: None,
            server_tx: 1687594905.6118436,
            server_rx: None,
            ty: ServerMessageType::Closed,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(
            json,
            "{\"server_tx\":1687594905.6118436,\"type\":\"closed\"}"
        );
    }
}

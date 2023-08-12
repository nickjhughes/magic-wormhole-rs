use data_encoding::BASE32;
use futures_channel::mpsc::UnboundedSender;
use log::debug;
use rand::prelude::*;
use std::collections::HashMap;

use magic_wormhole::message::{Phase, ServerMessage, ServerMessageType};

/// The range of valid nameplate IDs.
const NAMEPLATE_ID_RANGE: std::ops::Range<usize> = 1..999;

/// An application namespace.
#[derive(Debug, Default)]
pub(crate) struct App {
    /// Currently active nameplates, keyed by ID.
    pub(crate) nameplates: HashMap<usize, Nameplate>,
    /// Currently allocated mailboxes, keyed by name.
    pub(crate) mailboxes: HashMap<String, Mailbox>,
}

/// A collection of messages.
#[derive(Debug, Default)]
pub(crate) struct Mailbox {
    /// All messages sent by any connected client.
    pub(crate) messages: Vec<MailboxMessage>,
    /// The clients currently subscribed to the mailbox.
    pub(crate) subscribers: Vec<Subscriber>,
}

/// A two-sided identifier to faciliate connecting clients to a shared mailbox.
#[derive(Debug, Default)]
pub(crate) struct Nameplate {
    /// The associated mailbox ID.
    pub(crate) mailbox_id: String,
    /// Sides which have claimed the nameplate.
    pub(crate) sides: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct Subscriber {
    /// ID string of the client.
    pub(crate) side: String,
    /// A transmission channel for sending messages to the client.
    pub(crate) sender: UnboundedSender<ServerMessage>,
}

#[derive(Debug)]
pub(crate) struct MailboxMessage {
    /// Original ID of the message as sent by the source client.
    pub(crate) id: String,
    /// The timestamp at which the server received the original message.
    pub(crate) timestamp: f64,
    /// The side (ID string) of the source client.
    pub(crate) side: String,
    /// Message phase.
    pub(crate) phase: Phase,
    /// Message body.
    pub(crate) body: Vec<u8>,
}

impl Mailbox {
    /// Add a new message to the mailbox.
    fn add_message(&mut self, msg: MailboxMessage) {
        // Forward the new message to all subscribers
        let forward_msg = ServerMessage::new(
            Some(msg.id.clone()),
            Some(msg.timestamp),
            ServerMessageType::Message {
                side: msg.side.clone(),
                phase: msg.phase.clone(),
                body: msg.body.clone(),
            },
        );
        for subscriber in &self.subscribers {
            debug!(
                "Forwarding message {:?} to subscriber {:?}",
                msg.id, subscriber.side
            );
            subscriber
                .sender
                .unbounded_send(forward_msg.clone())
                .expect("failed to send message");
        }

        self.messages.push(msg);
    }

    /// Add the given side to the mailbox.
    fn add_subscriber(&mut self, side: &str, sender: UnboundedSender<ServerMessage>) {
        if self.subscribers.iter().any(|s| s.side == side) {
            // Side is already subscribed, do nothing
            return;
        }

        // Send the new subscriber any messages that are already in the mailbox
        for msg in &self.messages {
            debug!(
                "Forwarding message {:?} to new subscriber {:?}",
                msg.id, side
            );
            let forward_msg = ServerMessage::new(
                Some(msg.id.clone()),
                Some(msg.timestamp),
                ServerMessageType::Message {
                    side: msg.side.clone(),
                    phase: msg.phase.clone(),
                    body: msg.body.clone(),
                },
            );
            sender
                .unbounded_send(forward_msg)
                .expect("failed to send message");
        }

        self.subscribers.push(Subscriber {
            side: side.to_owned(),
            sender,
        });
    }

    /// Remove the given side from the mailbox.
    fn remove_subscriber(&mut self, side: &str) {
        self.subscribers.retain(|s| s.side != side);
    }
}

impl App {
    /// Find the smallest available nameplate, claim it, and return it. Returns None if no
    /// nameplates are available.
    pub(crate) fn allocate_nameplate(
        &mut self,
        side: &str,
        sender: UnboundedSender<ServerMessage>,
    ) -> Option<usize> {
        for i in NAMEPLATE_ID_RANGE {
            if !self.nameplates.contains_key(&i) {
                self.claim_nameplate(i, side, sender);
                return Some(i);
            }
        }
        None
    }

    /// Claim the given nameplate. Returns None if the nameplate is already full.
    pub(crate) fn claim_nameplate(
        &mut self,
        nameplate_id: usize,
        side: &str,
        sender: UnboundedSender<ServerMessage>,
    ) -> Option<String> {
        if let Some(nameplate) = self.nameplates.get_mut(&nameplate_id) {
            // This nameplate already has at least one side
            assert!(!nameplate.sides.is_empty());
            if nameplate.sides.contains(&side.to_owned()) {
                // Side is already associated with the nameplate (from an allocate),
                // so nothing to do
                Some(nameplate.mailbox_id.clone())
            } else {
                // TODO: Handle reclaimed errors, where a side tried to re-claim a nameplate
                // it already released (since that might cause a new mailbox to be allocated)
                nameplate.sides.push(side.to_owned());
                if nameplate.sides.len() >= 3 {
                    // TODO: Return a CrowdedNameplate error
                    None
                } else {
                    Some(nameplate.mailbox_id.clone())
                }
            }
        } else {
            // The nameplate is free, so let's create a mailbox for it
            // We also add this client to the mailbox and subscribe them
            let mailbox_id = App::generate_mailbox_id();
            self.open_mailbox(&mailbox_id, side, sender);
            self.nameplates.insert(
                nameplate_id,
                Nameplate {
                    mailbox_id: mailbox_id.clone(),
                    sides: vec![side.to_owned()],
                },
            );
            Some(mailbox_id)
        }
    }

    /// Remove the given side from the given nameplate. If the nameplate is then
    /// unused, it will be freed. Non-existant nameplates are ignored, as are sides
    /// which aren't associated with the nameplate.
    pub(crate) fn release_nameplate(&mut self, nameplate_id: usize, side: &str) {
        debug!("Removing {:?} from nameplate {:?}", side, nameplate_id);
        if let Some(nameplate) = self.nameplates.get_mut(&nameplate_id) {
            nameplate.sides.retain(|s| s != side);
            if nameplate.is_empty() {
                debug!("Freeing empty nameplate {:?}", nameplate_id);
                self.nameplates.remove(&nameplate_id);
            }
        }
    }

    /// Return the list of active nameplates.
    pub(crate) fn get_nameplates(&self) -> Vec<usize> {
        self.nameplates.keys().copied().collect::<Vec<usize>>()
    }

    /// Subscribe a client to a mailbox, opening it in the process if necessary.
    pub(crate) fn open_mailbox(
        &mut self,
        mailbox_id: &str,
        side: &str,
        sender: UnboundedSender<ServerMessage>,
    ) -> Option<()> {
        if !self.mailboxes.contains_key(mailbox_id) {
            debug!("Creating mailbox {:?}", mailbox_id);
            let mailbox = Mailbox {
                messages: Vec::new(),
                subscribers: Vec::new(),
            };
            self.mailboxes.insert(mailbox_id.to_owned(), mailbox);
        }

        let mailbox = self
            .mailboxes
            .get_mut(mailbox_id)
            .expect("non-existant mailbox");
        mailbox.add_subscriber(side, sender);
        if mailbox.subscribers.len() >= 3 {
            // TODO: Return CrowdedMailbox error
            None
        } else {
            Some(())
        }
    }

    /// Remove the given side from a mailbox.
    pub(crate) fn close_mailbox(&mut self, mailbox_id: &str, side: &str) {
        let mailbox = self
            .mailboxes
            .get_mut(mailbox_id)
            .expect("non-existant mailbox");
        mailbox.remove_subscriber(side);
        if mailbox.subscribers.is_empty() {
            self.mailboxes.remove(mailbox_id);
        }
    }

    /// Add a new message to the given mailbox. If any mailboxes are then empty, they will be
    /// freed.
    pub(crate) fn add_message_to_mailbox(&mut self, mailbox_id: &str, message: MailboxMessage) {
        let mailbox = self
            .mailboxes
            .get_mut(mailbox_id)
            .expect("non-existant mailbox");
        debug!(
            "Adding message {:?} to mailbox {:?}",
            message.id, mailbox_id
        );
        mailbox.add_message(message);

        self.mailboxes.retain(|mailbox_id, mailbox| {
            if mailbox.subscribers.is_empty() {
                debug!("Removing empty mailbox {:?}", mailbox_id);
            }
            !mailbox.subscribers.is_empty()
        });
    }

    /// Remove the given side from any active nameplates. Any nameplates that are
    /// then unused will be freed.
    pub(crate) fn remove_side_from_nameplates(&mut self, side: &str) {
        for (nameplate_id, nameplate) in self.nameplates.iter_mut() {
            nameplate.sides.retain(|s| {
                if s == side {
                    debug!("Removing side {:?} from nameplate {:?}", side, nameplate_id);
                }
                s != side
            });
        }

        // Remove any now-empty nameplates
        self.nameplates.retain(|nameplate_id, nameplate| {
            if nameplate.is_empty() {
                debug!("Removing empty nameplate {:?}", nameplate_id);
            }
            !nameplate.is_empty()
        });
    }

    /// Remove the given subscriber from any open mailboxes.
    pub(crate) fn remove_subscriber_from_mailboxes(
        &mut self,
        sender: &UnboundedSender<ServerMessage>,
    ) {
        for (mailbox_id, mailbox) in self.mailboxes.iter_mut() {
            mailbox.subscribers.retain(|s| {
                if s.sender.same_receiver(sender) {
                    debug!("Remove side {:?} from mailbox {:?}", s.side, mailbox_id);
                }
                !s.sender.same_receiver(sender)
            });
        }
    }

    /// Generate 13 characters of random, base32, lowercase ASCII.
    fn generate_mailbox_id() -> String {
        let mut rng = rand::thread_rng();
        let mut buffer = [0u8; 8];
        rng.fill_bytes(&mut buffer);
        BASE32
            .encode(&buffer)
            .to_ascii_lowercase()
            .strip_suffix("===")
            .unwrap()
            .to_owned()
    }
}

impl Nameplate {
    /// Check if the nameplate has no associated clients.
    pub(crate) fn is_empty(&self) -> bool {
        self.sides.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{App, MailboxMessage, Nameplate, ServerMessageType, NAMEPLATE_ID_RANGE};
    use futures_channel::mpsc::unbounded;

    #[test]
    fn nameplate_allocation() {
        let mut app = App::default();
        let (sender, _) = unbounded();

        let nameplate_id = app.allocate_nameplate("side1", sender.clone());
        assert_eq!(nameplate_id, Some(1));

        let nameplate_id = app.allocate_nameplate("side2", sender.clone());
        assert_eq!(nameplate_id, Some(2));
    }

    #[test]
    fn full_nameplate_allocation() {
        let mut app = App::default();
        let (sender, _) = unbounded();

        // Fill all nameplate slots
        for i in NAMEPLATE_ID_RANGE {
            app.nameplates.insert(
                i,
                Nameplate {
                    mailbox_id: format!("mailbox{}", i),
                    sides: Vec::new(),
                },
            );
        }

        let namplate_id = app.allocate_nameplate("side1", sender.clone());
        assert_eq!(namplate_id, None);
    }

    #[test]
    fn list_nameplates() {
        let mut app = App::default();
        assert!(app.get_nameplates().is_empty());

        let (sender, _) = unbounded();
        let _ = app.allocate_nameplate("side1", sender.clone());
        let nameplates = app.get_nameplates();
        assert_eq!(nameplates.len(), 1);
        assert_eq!(nameplates[0], 1);
    }

    #[test]
    fn claim_nameplate_after_allocation() {
        let mut app = App::default();
        let (sender, _) = unbounded();

        let nameplate_id = app.allocate_nameplate("side1", sender.clone()).unwrap();
        let mailbox_id = app.claim_nameplate(nameplate_id, "side1", sender.clone());
        assert!(mailbox_id.is_some());
    }

    #[test]
    fn claim_nameplate_no_allocation() {
        let mut app = App::default();
        let (sender, _) = unbounded();
        let nameplate_id = app.allocate_nameplate("side1", sender.clone()).unwrap();

        let mailbox_id = app.claim_nameplate(nameplate_id, "side2", sender.clone());
        assert!(mailbox_id.is_some());
    }

    #[test]
    fn claim_nameplate_crowded() {
        let mut app = App::default();
        let (sender, _) = unbounded();
        let nameplate_id = app.allocate_nameplate("side1", sender.clone()).unwrap();
        let _ = app.claim_nameplate(nameplate_id, "side2", sender.clone());

        let mailbox_id = app.claim_nameplate(nameplate_id, "side3", sender.clone());
        assert_eq!(mailbox_id, None);
    }

    #[test]
    fn remove_side() {
        let mut app = App::default();
        let (sender, _) = unbounded();
        assert!(app.nameplates.is_empty());

        let _ = app.allocate_nameplate("side1", sender.clone()).unwrap();
        let _ = app.allocate_nameplate("side1", sender.clone()).unwrap();
        assert_eq!(app.nameplates.len(), 2);

        app.remove_side_from_nameplates("side1");
        assert!(app.nameplates.is_empty());
    }

    #[test]
    fn remove_subscriber() {
        let mut app = App::default();
        let (sender, _) = unbounded();

        let nameplate_id = app.allocate_nameplate("side1", sender.clone()).unwrap();
        let mailbox_id = app
            .claim_nameplate(nameplate_id, "side1", sender.clone())
            .unwrap();
        assert_eq!(
            app.mailboxes
                .get(&mailbox_id)
                .unwrap()
                .subscribers
                .iter()
                .filter(|s| s.side == "side1")
                .count(),
            1
        );

        app.remove_subscriber_from_mailboxes(&sender);
        // Either the subscriber is removed from the mailbox, or the mailbox is
        // deallocated completely
        if let Some(mailbox) = app.mailboxes.get(&mailbox_id) {
            assert_eq!(
                mailbox
                    .subscribers
                    .iter()
                    .filter(|s| s.side == "side1")
                    .count(),
                0
            );
        } else {
            assert!(app.mailboxes.is_empty());
        }
    }

    #[test]
    fn release_empty_nameplate() {
        let mut app = App::default();
        let (sender, _) = unbounded();

        let nameplate_id = app.allocate_nameplate("side1", sender.clone()).unwrap();
        assert_eq!(app.nameplates.len(), 1);

        app.release_nameplate(nameplate_id, "side1");
        assert!(app.nameplates.is_empty());
    }

    #[test]
    fn release_nonempty_nameplate() {
        let mut app = App::default();
        let (sender, _) = unbounded();

        let nameplate_id = app.allocate_nameplate("side1", sender.clone()).unwrap();
        assert_eq!(app.nameplates.len(), 1);
        let _ = app.claim_nameplate(nameplate_id, "side2", sender.clone());
        assert_eq!(app.nameplates.len(), 1);

        app.release_nameplate(nameplate_id, "side1");
        assert_eq!(app.nameplates.len(), 1);
    }

    #[test]
    fn nameplate_is_empty() {
        let mut nameplate = Nameplate {
            mailbox_id: "mailbox".into(),
            sides: Vec::new(),
        };
        assert!(nameplate.is_empty());

        nameplate.sides.push("side1".into());
        assert!(!nameplate.is_empty());
    }

    #[test]
    fn mailbox_id_generation() {
        let mailbox_id = App::generate_mailbox_id();
        assert_eq!(mailbox_id.len(), 13);
        assert!(mailbox_id.is_ascii());
    }

    #[test]
    fn nameplate() {
        let mut app = App::default();
        let (sender, _) = unbounded();

        let nameplate_id = app.allocate_nameplate("side1", sender.clone()).unwrap();
        assert_eq!(nameplate_id, 1);
        assert_eq!(app.get_nameplates(), vec![nameplate_id]);

        // Allocate also does a claim
        let nameplate = app.nameplates.get(&nameplate_id).unwrap();
        let nameplate_mailbox_id = nameplate.mailbox_id.clone();
        assert_eq!(nameplate.sides.len(), 1);
        assert!(nameplate.sides.contains(&"side1".into()));

        // Duplicate claims by the same side are combined
        let mailbox_id_1 = app
            .claim_nameplate(nameplate_id, "side1", sender.clone())
            .unwrap();
        assert_eq!(mailbox_id_1, nameplate_mailbox_id);
        let nameplate = app.nameplates.get(&nameplate_id).unwrap();
        assert!(nameplate.sides.contains(&"side1".into()));
        assert_eq!(nameplate.mailbox_id, mailbox_id_1);

        // Claim by the second side is new
        let mailbox_id_2 = app
            .claim_nameplate(nameplate_id, "side2", sender.clone())
            .unwrap();
        assert_eq!(mailbox_id_1, mailbox_id_2);
        let nameplate = app.nameplates.get(&nameplate_id).unwrap();
        assert_eq!(nameplate.sides.len(), 2);
        assert_eq!(nameplate.sides, vec!["side1", "side2"]);

        // A third claim marks the nameplate as "crowded", and adds a third
        // claim (which must be released later), but leaves the two existing
        // claims alone
        let result = app.claim_nameplate(nameplate_id, "side3", sender.clone());
        assert_eq!(result, None);
        let nameplate = app.nameplates.get(&nameplate_id).unwrap();
        assert_eq!(nameplate.sides.len(), 3);

        // Releasing a non-existent nameplate is ignored
        app.release_nameplate(2, "side4");

        // Releasing a side that never claimed the nameplate is ignored
        app.release_nameplate(nameplate_id, "side4");
        let nameplate = app.nameplates.get(&nameplate_id).unwrap();
        assert_eq!(nameplate.sides.len(), 3);

        // Releasing one side leaves the second claim
        app.release_nameplate(nameplate_id, "side1");
        let nameplate = app.nameplates.get(&nameplate_id).unwrap();
        assert!(!nameplate.sides.contains(&"side1".into()));
        assert!(nameplate.sides.contains(&"side2".into()));
        assert!(nameplate.sides.contains(&"side3".into()));

        // Releasing one side multiple times is ignored
        app.release_nameplate(nameplate_id, "side1");
        let nameplate = app.nameplates.get(&nameplate_id).unwrap();
        assert!(!nameplate.sides.contains(&"side1".into()));
        assert!(nameplate.sides.contains(&"side2".into()));
        assert!(nameplate.sides.contains(&"side3".into()));

        // Release the second side
        app.release_nameplate(nameplate_id, "side2");
        let nameplate = app.nameplates.get(&nameplate_id).unwrap();
        assert!(!nameplate.sides.contains(&"side1".into()));
        assert!(!nameplate.sides.contains(&"side2".into()));
        assert!(nameplate.sides.contains(&"side3".into()));

        // Releasing the third side frees the nameplate
        app.release_nameplate(nameplate_id, "side3");
        assert!(app.nameplates.get(&nameplate_id).is_none());
    }

    #[test]
    fn mailbox() {
        let mut app = App::default();
        let (sender, _) = unbounded();

        let mailbox_id = "mid";
        app.open_mailbox(mailbox_id, "side1", sender.clone());
        let mailbox = app.mailboxes.get(mailbox_id).unwrap();
        assert_eq!(mailbox.subscribers.len(), 1);
        assert_eq!(mailbox.subscribers[0].side, "side1");

        // Opening the same mailbox twice, by the same side, does nothing
        app.open_mailbox(mailbox_id, "side1", sender.clone());
        assert_eq!(app.mailboxes.len(), 1);
        let mailbox = app.mailboxes.get(mailbox_id).unwrap();
        assert_eq!(mailbox.subscribers.len(), 1);
        assert_eq!(mailbox.subscribers[0].side, "side1");

        // Opening a second side adds a new subscriber
        app.open_mailbox(mailbox_id, "side2", sender.clone());
        assert_eq!(app.mailboxes.len(), 1);
        let mailbox = app.mailboxes.get(mailbox_id).unwrap();
        assert_eq!(mailbox.subscribers.len(), 2);
        assert!(mailbox.subscribers.iter().any(|s| s.side == "side1"));
        assert!(mailbox.subscribers.iter().any(|s| s.side == "side2"));

        // A third open marks it as crowded
        let result = app.open_mailbox(mailbox_id, "side3", sender.clone());
        assert_eq!(result, None);
        let mailbox = app.mailboxes.get(mailbox_id).unwrap();
        assert_eq!(mailbox.subscribers.len(), 3);
        app.close_mailbox(mailbox_id, "side3");

        // Closing a side that never claimed the mailbox is ignored
        app.close_mailbox(mailbox_id, "side4");
        let mailbox = app.mailboxes.get(mailbox_id).unwrap();
        assert_eq!(mailbox.subscribers.len(), 2);

        // Closing one side leaves the second claim
        app.close_mailbox(mailbox_id, "side1");
        let mailbox = app.mailboxes.get(mailbox_id).unwrap();
        assert_eq!(mailbox.subscribers.len(), 1);
        assert!(mailbox.subscribers.iter().any(|s| s.side == "side2"));

        // Closing one side multiple times is ignored
        app.close_mailbox(mailbox_id, "side1");
        let mailbox = app.mailboxes.get(mailbox_id).unwrap();
        assert_eq!(mailbox.subscribers.len(), 1);
        assert!(mailbox.subscribers.iter().any(|s| s.side == "side2"));

        // Closing the second side frees the mailbox
        app.close_mailbox(mailbox_id, "side2");
        assert!(app.mailboxes.is_empty());
    }

    #[test]
    fn messages() {
        let mut app = App::default();

        let (sender1, mut receiver1) = unbounded();
        let mailbox_id = "mid";
        app.open_mailbox(mailbox_id, "side1", sender1.clone());
        app.add_message_to_mailbox(
            &mailbox_id,
            MailboxMessage {
                id: "msgid".into(),
                timestamp: 1.0,
                side: "side1".into(),
                phase: super::Phase::Message(0),
                body: "body1".into(),
            },
        );

        // Existing subscriber receives the new message
        let msg = receiver1.try_next().unwrap().unwrap();
        assert!(matches!(msg.ty, ServerMessageType::Message { .. }));
        match msg.ty {
            ServerMessageType::Message { side, body, .. } => {
                assert_eq!(side, "side1");
                assert_eq!(body, b"body1");
            }
            _ => unreachable!(),
        }

        app.add_message_to_mailbox(
            &mailbox_id,
            MailboxMessage {
                id: "msgid".into(),
                timestamp: 1.0,
                side: "side1".into(),
                phase: super::Phase::Message(1),
                body: "body2".into(),
            },
        );
        let msg = receiver1.try_next().unwrap().unwrap();
        assert!(matches!(msg.ty, ServerMessageType::Message { .. }));
        match msg.ty {
            ServerMessageType::Message { body, .. } => {
                assert_eq!(body, b"body2");
            }
            _ => unreachable!(),
        }

        // New subscribers is forwarded all existing messages
        let (sender2, mut receiver2) = unbounded();
        app.open_mailbox(mailbox_id, "side2", sender2.clone());
        let msg1 = receiver2.try_next().unwrap().unwrap();
        assert!(matches!(msg1.ty, ServerMessageType::Message { .. }));
        match msg1.ty {
            ServerMessageType::Message { body, .. } => {
                assert_eq!(body, b"body1");
            }
            _ => unreachable!(),
        }
        let msg2 = receiver2.try_next().unwrap().unwrap();
        assert!(matches!(msg2.ty, ServerMessageType::Message { .. }));
        match msg2.ty {
            ServerMessageType::Message { body, .. } => {
                assert_eq!(body, b"body2");
            }
            _ => unreachable!(),
        }

        app.add_message_to_mailbox(
            mailbox_id,
            MailboxMessage {
                id: "msgid".into(),
                timestamp: 1.0,
                side: "side1".into(),
                phase: super::Phase::Message(2),
                body: "body3".into(),
            },
        );
        let msg3 = receiver1.try_next().unwrap().unwrap();
        assert!(matches!(msg3.ty, ServerMessageType::Message { .. }));
        match msg3.ty {
            ServerMessageType::Message { body, .. } => {
                assert_eq!(body, b"body3");
            }
            _ => unreachable!(),
        }
        let msg3 = receiver2.try_next().unwrap().unwrap();
        assert!(matches!(msg3.ty, ServerMessageType::Message { .. }));
        match msg3.ty {
            ServerMessageType::Message { body, .. } => {
                assert_eq!(body, b"body3");
            }
            _ => unreachable!(),
        }

        app.remove_subscriber_from_mailboxes(&sender1);

        app.add_message_to_mailbox(
            mailbox_id,
            MailboxMessage {
                id: "msgid".into(),
                timestamp: 1.0,
                side: "side1".into(),
                phase: super::Phase::Message(3),
                body: "body4".into(),
            },
        );
        // Error here means there are no messages available, but the channel is still open
        assert!(receiver1.try_next().is_err());
        let msg4 = receiver2.try_next().unwrap().unwrap();
        assert!(matches!(msg4.ty, ServerMessageType::Message { .. }));
        match msg4.ty {
            ServerMessageType::Message { body, .. } => {
                assert_eq!(body, b"body4");
            }
            _ => unreachable!(),
        }

        // Message adds are not idempotent: clients filter duplicates
        app.add_message_to_mailbox(
            mailbox_id,
            MailboxMessage {
                id: "msgid".into(),
                timestamp: 1.0,
                side: "side1".into(),
                phase: super::Phase::Message(0),
                body: "body1".into(),
            },
        );
        assert_eq!(app.mailboxes.get(mailbox_id).unwrap().messages.len(), 5);
        assert_eq!(
            app.mailboxes
                .get(mailbox_id)
                .unwrap()
                .messages
                .last()
                .unwrap()
                .body,
            b"body1"
        );
    }
}

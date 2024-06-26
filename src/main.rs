use anyhow::Result;
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use crypto::{CryptoProvider, EcdhAesProvider, EcdhDesProvider, RsaProvider};
use message::{Header, Message};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Public},
    rsa::Rsa,
    sign::{Signer, Verifier},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame, Terminal,
};
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::Duration,
};

mod crypto;
mod message;

#[derive(Parser)]
struct Arg {
    #[arg(short, long, default_value_t = 4321)]
    port: u16,
    #[arg(short, long, default_value = "rsa")]
    crypto: CryptoKind,
}

#[derive(Clone)]
enum CryptoKind {
    Rsa,
    EcdhAes,
    EcdhDes,
}

impl std::str::FromStr for CryptoKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "rsa" => Ok(Self::Rsa),
            "ecdh-aes" => Ok(Self::EcdhAes),
            "ecdh-des" => Ok(Self::EcdhDes),
            _ => Err("Invalid crypto kind".to_string()),
        }
    }
}

struct State {
    addr: String,
    port: u16,

    curr_input: String,
    messages: Vec<String>,
    informations: Vec<String>,

    stream: Option<TcpStream>,

    pub crypto_provider: Box<dyn CryptoProvider>,
    pub signer: Signer<'static>,
    pub pubkey_for_sign: Vec<u8>,
    pub peer_pubkey_for_sign: Option<PKey<Public>>,

    stopped: bool,
}

enum Command {
    Connect(String, u16),
    Quit,
}

fn main() -> Result<()> {
    let args = Arg::parse();
    let port = args.port;
    let addr = "127.0.0.1".to_string();
    let crypto_kind = args.crypto;

    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    let (tx, rx) = mpsc::channel::<Vec<u8>>();

    let state = Arc::new(Mutex::new(State::new(addr.clone(), port, crypto_kind)));

    {
        let tx = tx.clone();
        let state = state.clone();
        thread::spawn(move || listen(tx, state));
    }

    loop {
        terminal.draw(|f| {
            ui(f, state.clone());
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char(c) => {
                        let mut locked_state = state.lock().unwrap();
                        locked_state.input_char(c);
                    }
                    KeyCode::Backspace => {
                        let mut locked_state = state.lock().unwrap();
                        locked_state.delete_char();
                    }
                    KeyCode::Enter => {
                        let mut locked_state = state.lock().unwrap();
                        let start_recv = locked_state.submit();

                        if start_recv {
                            let tx = tx.clone();
                            let state = state.clone();
                            thread::spawn(move || recv(tx, state));
                        }
                    }
                    _ => {}
                }
            }
        }

        if let Ok(msg) = rx.try_recv() {
            let mut state = state.lock().unwrap();
            state.peer_msg(String::from_utf8(msg).unwrap());
        }

        if state.lock().unwrap().is_stopped() {
            // draw last time for the informations.
            terminal.draw(|f| {
                ui(f, state.clone());
            })?;
            break;
        }
    }

    // wait for key
    event::read()?;

    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;

    Ok(())
}

impl State {
    fn new(addr: String, port: u16, crypto_kind: CryptoKind) -> Self {
        let provider = match crypto_kind {
            CryptoKind::Rsa => RsaProvider::initialize(),
            CryptoKind::EcdhAes => EcdhAesProvider::initialize(),
            CryptoKind::EcdhDes => EcdhDesProvider::initialize(),
        };

        let keypair = Rsa::generate(2048).unwrap();
        let keypair = PKey::from_rsa(keypair).unwrap();

        let signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();

        let pubkey = keypair.public_key_to_pem().unwrap();

        Self {
            addr,
            port,
            curr_input: String::new(),
            messages: Vec::new(),
            informations: Vec::new(),
            stream: None,
            crypto_provider: provider,
            signer,
            pubkey_for_sign: pubkey,
            peer_pubkey_for_sign: None,
            stopped: false,
        }
    }

    fn input_char(&mut self, c: char) {
        self.curr_input.push(c);
    }

    fn delete_char(&mut self) {
        self.curr_input.pop();
    }

    fn handle_command(&mut self) -> Option<Command> {
        if !self.curr_input.starts_with("/") {
            return None;
        }

        let mut parts = self.curr_input.split_whitespace();

        match parts.next() {
            Some("/connect") => {
                let addr = parts.next().unwrap_or(&self.addr).to_string();
                let port = parts.next().unwrap_or("4321").parse().unwrap_or(4321);

                self.curr_input.clear();

                Some(Command::Connect(addr, port))
            }
            Some("/quit") => {
                self.curr_input.clear();
                Some(Command::Quit)
            }
            _ => None,
        }
    }

    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    fn info(&mut self, info: String) {
        self.informations.push(info);
    }

    fn error(&mut self, error: String) {
        self.informations.push(error);
    }

    fn peer_msg(&mut self, msg: String) {
        self.messages.push(format!("PEER: {}", msg));
    }

    fn user_msg(&mut self, msg: String) {
        self.messages.push(format!("USER: {}", msg));
    }

    fn send(&mut self) {
        self.info("Sending".to_string());
        if let Some(ref mut stream) = self.stream {
            let msg = self
                .crypto_provider
                .encrypt(self.curr_input.clone())
                .unwrap();
            let signature = self.signer.sign_oneshot_to_vec(&msg).unwrap();
            let msg = Message::new(Header::Data, msg, signature);
            let msg = msg.serialize();
            stream.write(&msg).unwrap();
            self.user_msg(self.curr_input.clone());
            self.curr_input.clear();
        } else {
            self.error("Not connected to peer".to_string());
            return;
        }
        self.info("Sent".to_string());
    }

    fn connect(&mut self, addr: String, port: u16) {
        self.info(format!("Connecting to {}:{}", addr, port));
        let stream = TcpStream::connect((addr, port)).unwrap();
        stream.set_nonblocking(true).unwrap();
        self.stream = Some(stream);
        self.info("Connected".to_string());

        self.info("Sending public key".to_string());

        let public_key = self.crypto_provider.public_key().unwrap();
        let msg = Message::new(Header::Prepare, public_key, self.pubkey_for_sign.clone());
        let msg = msg.serialize();
        self.stream.as_ref().unwrap().write(&msg).unwrap();

        self.info("Sent public key".to_string());
    }

    fn submit(&mut self) -> bool {
        if self.curr_input.is_empty() {
            return false;
        }
        let mut start_recv = false;
        if self.curr_input.starts_with("/") {
            let cmd = self.handle_command();
            match cmd {
                Some(Command::Connect(addr, port)) => {
                    self.connect(addr, port);
                    start_recv = true;
                }
                Some(Command::Quit) => {
                    self.set_stopped();
                }
                None => {}
            }
        } else {
            self.send();
        }

        start_recv
    }

    fn is_stopped(&self) -> bool {
        self.stopped
    }

    fn message_text(&self, max_lines: usize) -> String {
        self.messages
            .iter()
            .rev()
            .take(max_lines)
            .map(|msg| format!("{}\n", msg))
            .rev()
            .collect()
    }

    fn information_text(&self, max_lines: usize) -> String {
        self.informations
            .iter()
            .rev()
            .take(max_lines)
            .map(|info| format!("{}\n", info))
            .rev()
            .collect()
    }

    fn curr_input(&self) -> &str {
        &self.curr_input
    }

    fn set_stopped(&mut self) {
        self.stopped = true;
        self.info("Stopped".to_string());
        self.stream = None;
    }
}

fn recv(tx: mpsc::Sender<Vec<u8>>, state: Arc<Mutex<State>>) {
    let mut buffer = [0; 1024];
    loop {
        {
            let mut state = state.lock().unwrap();

            if state.is_stopped() {
                break;
            }

            let mut stream = state.stream.as_ref().unwrap();
            match stream.read(&mut buffer) {
                Ok(n) => {
                    if n == 0 {
                        state.error("Peer disconnected".to_string());
                        state.stream = None;
                        state.set_stopped();
                        break;
                    }

                    state.info(format!("Received: {}", n));
                    let msg = buffer[..n].to_vec();

                    // deserialize the message
                    let msg = Message::deserialize(&msg);

                    match msg.header() {
                        Header::Prepare => {
                            state.info("Received public key".to_string());

                            if !state.crypto_provider.is_prepared() {
                                let data = msg.data();
                                let peer_pubkey = msg.signature();
                                let peer_pubkey = PKey::public_key_from_pem(peer_pubkey).unwrap();

                                // just debug
                                state.info(format!(
                                    "Peer public key for sign: {:?}",
                                    peer_pubkey.public_key_to_der().unwrap().bytes()
                                ));

                                state.crypto_provider.prepare(data.to_vec());
                                state.peer_pubkey_for_sign = Some(peer_pubkey);

                                // send the public key
                                state.info("Sending public key".to_string());
                                let public_key = state.crypto_provider.public_key().unwrap();
                                let msg = Message::new(
                                    Header::Prepare,
                                    public_key,
                                    state.pubkey_for_sign.clone(),
                                );
                                let msg = msg.serialize();
                                state.stream.as_ref().unwrap().write(&msg).unwrap();
                                state.info("Sent public key".to_string());
                            }
                        }
                        Header::Data => {
                            let raw = msg.data();

                            state.info(format!("Received data: {:?}", raw));

                            let verified = if let Some(peer_pubkey) =
                                state.peer_pubkey_for_sign.as_ref()
                            {
                                let signature = msg.signature();
                                let mut verifier =
                                    Verifier::new(MessageDigest::sha256(), peer_pubkey).unwrap();
                                let verified = verifier.verify_oneshot(signature, raw).unwrap();
                                verified
                            } else {
                                panic!("No public key for signature verification");
                            };

                            if verified {
                                state.info("Signature verified".to_string());
                            } else {
                                state.error("Signature verification failed".to_string());
                            }

                            let decrypted = state.crypto_provider.decrypt(raw.to_vec()).unwrap();
                            tx.send(decrypted.into()).unwrap();
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    state.error(format!("Failed to receive data: {}", e));
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn listen(tx: mpsc::Sender<Vec<u8>>, state: Arc<Mutex<State>>) {
    let (addr, port) = {
        let state = state.lock().unwrap();
        (state.addr.clone(), state.port)
    };

    {
        state
            .lock()
            .unwrap()
            .info(format!("Listening on {}:{}", addr, port));
    }

    let listener = TcpListener::bind((addr, port)).unwrap();

    loop {
        {
            if state.lock().unwrap().is_connected() {
                break;
            }
        }

        {
            if state.lock().unwrap().is_stopped() {
                break;
            }
        }

        if let Ok((stream, _)) = listener.accept() {
            stream.set_nonblocking(true).unwrap();
            state
                .lock()
                .unwrap()
                .info("Connection established".to_string());
            state.lock().unwrap().stream = Some(stream);
            break;
        }

        thread::sleep(Duration::from_millis(100));
    }

    recv(tx, state);
}

fn ui(frame: &mut Frame, state: Arc<Mutex<State>>) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(20),
                Constraint::Min(2),
                Constraint::Length(3),
            ]
            .as_ref(),
        )
        .split(frame.size());

    let state = state.lock().unwrap();

    let message_text = state.message_text(chunks[1].height as usize - 2);
    let information_text = state.information_text(chunks[0].height as usize - 2);

    let input = state.curr_input();

    let info_view = Paragraph::new(information_text)
        .block(Block::default().borders(Borders::ALL).title("Info"));
    let msg_view = Paragraph::new(message_text)
        .block(Block::default().borders(Borders::ALL).title("Messages"))
        .wrap(Wrap { trim: true });
    let input_view = Paragraph::new(input)
        .block(Block::default().borders(Borders::ALL).title("Input"))
        .wrap(Wrap { trim: true });

    frame.render_widget(info_view, chunks[0]);
    frame.render_widget(msg_view, chunks[1]);
    frame.render_widget(input_view, chunks[2]);
}

use anyhow::Result;
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, Paragraph},
    Frame, Terminal,
};
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::Duration,
};

#[derive(Parser)]
struct Arg {
    #[arg(short, long, default_value_t = 4321)]
    port: u16,
}

struct State {
    addr: String,
    port: u16,

    curr_input: String,
    messages: Vec<String>,
    informations: Vec<String>,

    stream: Option<TcpStream>,

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

    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    let (tx, rx) = mpsc::channel::<Vec<u8>>();

    let state = Arc::new(Mutex::new(State::new(addr.clone(), port)));

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
    fn new(addr: String, port: u16) -> Self {
        Self {
            addr,
            port,
            curr_input: String::new(),
            messages: Vec::new(),
            informations: Vec::new(),
            stream: None,
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
            stream.write(self.curr_input.as_bytes()).unwrap();
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
                    tx.send(msg).unwrap();
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
                Constraint::Length(5),
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
        .block(Block::default().borders(Borders::ALL).title("Messages"));
    let input_view =
        Paragraph::new(input).block(Block::default().borders(Borders::ALL).title("Input"));

    frame.render_widget(info_view, chunks[0]);
    frame.render_widget(msg_view, chunks[1]);
    frame.render_widget(input_view, chunks[2]);
}

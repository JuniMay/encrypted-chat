use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Message {
    header: Header,
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub enum Header {
    Prepare,
    Data,
}

impl Message {
    pub fn new(header: Header, data: Vec<u8>) -> Self {
        Self { header, data }
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

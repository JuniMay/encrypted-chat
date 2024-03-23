use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
pub struct Message {
    /// The header
    #[serde(with = "serde_bytes")]
    header: Header,
    /// The data, for handshake, this stores the public key of the provider.
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
    /// The signature, for handshake, this stores the public rsa key
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Header {
    Prepare = 0,
    Data = 1,
}

impl serde_bytes::Serialize for Header {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> serde_bytes::Deserialize<'de> for Header {
    fn deserialize<D>(deserializer: D) -> Result<Header, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        match value {
            0 => Ok(Header::Prepare),
            1 => Ok(Header::Data),
            _ => Err(serde::de::Error::custom("invalid value")),
        }
    }
}

impl Message {
    pub fn new(header: Header, data: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            header,
            data,
            signature,
        }
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn deserialize(data: &[u8]) -> Self {
        bincode::deserialize(data).unwrap()
    }
}

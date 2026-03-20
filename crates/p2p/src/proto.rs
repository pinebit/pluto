use std::io;

use futures::prelude::*;
use prost::Message;
use unsigned_varint::aio::read_usize;

/// Default maximum message size (64KB should be plenty for peer info).
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024;

/// Writes a length-delimited payload with an unsigned varint length prefix.
///
/// Wire format: `[uvarint length][payload bytes]`
pub async fn write_length_delimited<S: AsyncWrite + Unpin>(
    stream: &mut S,
    payload: &[u8],
) -> io::Result<()> {
    let mut len_buf = unsigned_varint::encode::usize_buffer();
    let encoded_len = unsigned_varint::encode::usize(payload.len(), &mut len_buf);
    stream.write_all(encoded_len).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

/// Reads a length-delimited payload with an unsigned varint length prefix.
///
/// Wire format: `[uvarint length][payload bytes]`
///
/// Returns an error if the payload exceeds `max_message_size`.
pub async fn read_length_delimited<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_message_size: usize,
) -> io::Result<Vec<u8>> {
    let msg_len = read_usize(&mut *stream).await.map_err(|e| match e {
        unsigned_varint::io::ReadError::Io(io_err) => io_err,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    })?;

    if msg_len > max_message_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {msg_len} bytes (max: {max_message_size})"),
        ));
    }

    let mut buf = vec![0u8; msg_len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Writes a protobuf message with unsigned varint length prefix to the stream.
///
/// Wire format: `[uvarint length][protobuf bytes]`
pub async fn write_protobuf<M: Message, S: AsyncWrite + Unpin>(
    stream: &mut S,
    msg: &M,
) -> io::Result<()> {
    let mut buf = Vec::with_capacity(msg.encoded_len());
    msg.encode(&mut buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_length_delimited(stream, &buf).await
}

/// Reads a protobuf message with unsigned varint length prefix from the stream.
///
/// Wire format: `[uvarint length][protobuf bytes]`
///
/// Returns an error if the message exceeds `MAX_MESSAGE_SIZE`.
pub async fn read_protobuf<M: Message + Default, S: AsyncRead + Unpin>(
    stream: &mut S,
) -> io::Result<M> {
    read_protobuf_with_max_size(stream, MAX_MESSAGE_SIZE).await
}

/// Reads a protobuf message with unsigned varint length prefix from the stream.
///
/// Wire format: `[uvarint length][protobuf bytes]`
///
/// Returns an error if the message exceeds `max_message_size`.
pub async fn read_protobuf_with_max_size<M: Message + Default, S: AsyncRead + Unpin>(
    stream: &mut S,
    max_message_size: usize,
) -> io::Result<M> {
    let buf = read_length_delimited(stream, max_message_size).await?;

    M::decode(&buf[..]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

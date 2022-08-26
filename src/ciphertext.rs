extern crate crypto;
extern crate dirs;
extern crate rand;

use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::{aes, blockmodes, buffer, symmetriccipher};
use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

// https://github.com/DaGenix/rust-crypto/blob/master/examples/symmetriccipher.rs
// Encrypt a buffer with the given key and iv using
// AES-256/CBC/Pkcs encryption.
fn encrypt(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    // Create an encryptor instance of the best performing
    // type available for the platform.
    let mut encryptor =
        aes::cbc_encryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    // Each encryption operation encrypts some data from
    // an input buffer into an output buffer. Those buffers
    // must be instances of RefReaderBuffer and RefWriteBuffer
    // (respectively) which keep track of how much data has been
    // read from or written to them.
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    // Each encryption operation will "make progress". "Making progress"
    // is a bit loosely defined, but basically, at the end of each operation
    // either BufferUnderflow or BufferOverflow will be returned (unless
    // there was an error). If the return value is BufferUnderflow, it means
    // that the operation ended while wanting more input data. If the return
    // value is BufferOverflow, it means that the operation ended because it
    // needed more space to output data. As long as the next call to the encryption
    // operation provides the space that was requested (either more input data
    // or more output space), the operation is guaranteed to get closer to
    // completing the full operation - ie: "make progress".
    //
    // Here, we pass the data to encrypt to the enryptor along with a fixed-size
    // output buffer. The 'true' flag indicates that the end of the data that
    // is to be encrypted is included in the input buffer (which is true, since
    // the input data includes all the data to encrypt). After each call, we copy
    // any output data to our result Vec. If we get a BufferOverflow, we keep
    // going in the loop since it means that there is more work to do. We can
    // complete as soon as we get a BufferUnderflow since the encryptor is telling
    // us that it stopped processing data due to not having any more data in the
    // input buffer.
    loop {
        let result = encryptor
            .encrypt(&mut read_buffer, &mut write_buffer, true)
            .expect("");

        // "write_buffer.take_read_buffer().take_remaining()" means:
        // from the writable buffer, create a new readable buffer which
        // contains all data that has been written, and then access all
        // of that data as a slice.
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

// Decrypts a buffer with the given key and iv using
// AES-256/CBC/Pkcs encryption.
//
// This function is very similar to encrypt(), so, please reference
// comments in that function. In non-example code, if desired, it is possible to
// share much of the implementation using closures to hide the operation
// being performed. However, such code would make this example less clear.
fn decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor =
        aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor
            .decrypt(&mut read_buffer, &mut write_buffer, true)
            .unwrap();

        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

pub fn get_mypasswd() -> Result<PathBuf, Box<dyn Error>> {
    let home = match dirs::home_dir() {
        Some(x) => x,
        _ => PathBuf::new(), //如果不存在,则使用当前目录
    };
    let file = Path::join(&home, ".mypasswd");
    if !file.exists() {
        //File::create=> only-write mode
        fs::File::create(file.clone())?;
    }

    Ok(file)
}

pub const THIS_KEY: &str = "passwd"; //32 bit
const THIS_IV: &str = "cnzwtzofghrjqkem"; //16 bit

// 加密
pub fn encrypt_text() {
    let mut text = String::new();
    // File::open=>read-only mode
    let mut file = fs::File::open(get_mypasswd().unwrap()).unwrap();
    file.read_to_string(&mut text).unwrap();
    if text.as_bytes().len() <= 0 {
        return;
    }

    let key = format!("{:0<32}", THIS_KEY);
    let iv = format!("{:0<16}", THIS_IV);
    let encrypted_data = encrypt(text.as_bytes(), key.as_bytes(), iv.as_bytes())
        .ok()
        .unwrap();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(get_mypasswd().unwrap())
        .unwrap();
    file.write_all(&encrypted_data).unwrap();
}

// 解密
pub fn decrypt_text() {
    let mut buf = Vec::new();
    // File::open => read-only model
    let mut file = fs::File::open(get_mypasswd().unwrap()).unwrap();
    file.read_to_end(&mut buf).unwrap();
    if buf.len() <= 0 {
        return;
    }

    let key = format!("{:0<32}", THIS_KEY);
    let iv = format!("{:0<16}", THIS_IV);
    let decrypted_data = decrypt(&buf[..], key.as_bytes(), iv.as_bytes())
        .ok()
        .unwrap();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(get_mypasswd().unwrap())
        .unwrap();
    file.write_all(&decrypted_data.to_vec()).unwrap();
}

#[test]
fn test_decrypt() {
    encrypt_text();
    // decrypt_text();
}

#[test]
fn test_get_file() {
    println!("{:?}", get_mypasswd().unwrap().to_str());
}

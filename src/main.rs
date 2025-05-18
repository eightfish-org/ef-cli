use clap::{App, Arg};
use hex;
use redis::{Client, Commands};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

const CHANNEL_ADMIN2VIN: &str = "admin2vin";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputOutputObject {
    proto: String,
    model: String,
    action: String,
    data: Vec<u8>,
    ext: Vec<u8>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let matches = App::new("ef-cli")
        .version("1.0")
        .author("Mike Tang")
        .about("The cli tool for EightFish.")
        .arg(
            Arg::with_name("proto")
                .long("proto")
                .value_name("PROTOCOL")
                .help("Sets the protocol")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("file")
                .long("file")
                .value_name("FILE")
                .help("Sets the input file")
                .takes_value(true),
        )
        .get_matches();

    // Handle the 'proto' argument
    let proto = matches.value_of("proto").expect("missing proto").to_owned();

    // Handle the 'file' argument
    if let Some(file_path) = matches.value_of("file") {
        let mut f = File::open(file_path)?;
        let mut file_content = Vec::new();
        match f.read_to_end(&mut file_content) {
            Ok(_) => {
                // calculate digest
                let digest = calculate_digest(&file_content);
                // send to redis
                send_to_redis(proto, file_content, digest, 10)
                    .expect("error sending msg to redis channel.")
            }

            Err(e) => eprintln!("Error reading file: {}", e),
        }
    }

    Ok(())
}

fn calculate_digest(binary_data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(binary_data);
    let result = hasher.finalize();
    hex::encode(result)
}

fn send_to_redis(
    proto: String,
    file_content: Vec<u8>,
    digest: String,
    afterblocks: usize,
) -> redis::RedisResult<()> {
    // Create a Redis client
    let client = Client::open("redis://127.0.0.1/")?;
    let mut con = client.get_connection()?;

    let unix_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    println!("Unix Timestamp: {}", unix_timestamp);

    let extinfo = serde_json::to_vec(&json!({
        "sql_file": "",
        "afterblocks": afterblocks,
        "digest": digest,
    }))
    .unwrap();

    // Create a message
    let message = InputOutputObject {
        proto,
        model: "".to_string(),
        action: "upload_wasm".to_string(),
        data: file_content,
        ext: extinfo,
    };

    // Serialize the message to JSON
    let json_vec = serde_json::to_vec(&message).unwrap();

    // Publish the JSON string to a Redis channel
    let result: i32 = con.publish(CHANNEL_ADMIN2VIN, &json_vec)?;

    println!("Message published to {} recipients", result);

    Ok(())
}

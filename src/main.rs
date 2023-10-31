extern crate clap;
use clap::{App, Arg};
use std::fs::File;
use std::io::{Read, Write};
    // Reference : https://datatracker.ietf.org/doc/html/draft-kaukonen-cipher-arcfour-03#appendix-A
   
    // Allocate 256 element array of bytes to be used as an s-box 
fn key_setup(key: &[u8], s_box: &mut [u8; 256]) {
    for i in 0..256 {
        s_box[i] = i as u8;
    }
    // Fill another array of the same size with the key + set j to 0 and initialize s-box 
    let key_len = key.len();
    let mut j = 0;
    for i in 0..256 {
        j = ((j as usize + s_box[i] as usize + key[i % key_len] as usize) % 256) as u8;
        s_box.swap(i as usize, j as usize);
    }
}
    // Stream generation ; Encryption is processed one bite at a time.
fn stream_generation(data: &mut [u8], s_box: &mut [u8; 256]) {
    let mut i = 0;
    let mut j = 0;
    let data_len = data.len();

    for index in 0..data_len {
        i = ((i as usize + 1) % 256) as u8;
        j = ((j as usize + s_box[i as usize] as usize) % 256) as u8;
        s_box.swap(i as usize, j as usize);

        let t = ((s_box[i as usize] as usize + s_box[j as usize] as usize) % 256) as u8;
        let k = s_box[t as usize];

        data[index] ^= k;
    }
}

fn main() {
    let matches = App::new("ARCFOUR Encryption/Decryption")
        .version("1.0")
        .author("Nidal Tahhar")
        .about("Encrypt or Decrypt a file using ARCFOUR")
        .arg(
            Arg::with_name("input")
                .short("i")
                .long("input")
                .value_name("INPUT")
                .help("Input file to encrypt/decrypt")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("key")
                .short("k")
                .long("key")
                .value_name("KEY")
                .help("File containing the encryption/decryption key")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("OUTPUT")
                .help("Target file for encrypted/decrypted output")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("skipbyte")
                .short("s")
                .long("skipbyte")
                .value_name("SKIPBYTE")
                .help("Number of bytes to skip at the beginning of the file")
                .takes_value(true)
                .required(false)
                .default_value("0"),
        )
        .get_matches();

    let input_file = matches.value_of("input").unwrap();
    let key_file = matches.value_of("key").unwrap();
    let output_file = matches.value_of("output").unwrap();
    let mut input_data = Vec::new();
    let mut key_data = Vec::new();

    // Read the input file
    match File::open(input_file) {
        Ok(mut file) => {
            file.read_to_end(&mut input_data).unwrap();
        }
        Err(_) => {
            eprintln!("Failed to open input file.");
            std::process::exit(1);
        }
    }
    // Read the key file
    match File::open(key_file) {
        Ok(mut file) => {
            file.read_to_end(&mut key_data).unwrap();
        }
        Err(_) => {
            eprintln!("Failed to open key file.");
            std::process::exit(1);
        }
    }
    // Skip bytes if specified
    if let Some(skip_bytes_str) = matches.value_of("skipbyte") {
        if let Ok(skip_bytes) = skip_bytes_str.parse::<usize>() {
            if skip_bytes > input_data.len() {
                eprintln!("Skip byte count exceeds file size.");
                std::process::exit(1);
            }

            // Preserve the specified number of bytes as clear (unencrypted)
            let clear_bytes = input_data[..skip_bytes].to_vec();
            input_data = input_data[skip_bytes..].to_vec();

            // Initialize the S-box with the key
            let mut s_box: [u8; 256] = [0; 256];
            key_setup(&key_data, &mut s_box);

            // Apply encryption to the remaining data
            stream_generation(&mut input_data, &mut s_box);

            // Combine the clear bytes with the encrypted data
            input_data = [clear_bytes, input_data].concat();
        } else {
            eprintln!("Failed to parse skipbyte as a number.");
            std::process::exit(1);
        }
    }

    // Write the result to the output file
    match File::create(output_file) {
        Ok(mut file) => {
            file.write_all(&input_data).unwrap();
        }
        Err(_) => {
            eprintln!("Failed to create the output file.");
            std::process::exit(1);
        }
    }
    println!("Encryption/Decryption completed successfully.");
}

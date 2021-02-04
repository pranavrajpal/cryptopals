use md4::{Digest, Md4};

fn main() {
    let mut h = Md4::new();
    h.update(b"a");
    let result = h.finalize();
    println!("{:X}", result);
    test_md4_hash();
}

fn test_md4_hash() {
    let message = b"a";
    let bytestring = add_md_padding(message);
    println!("{}", bytestring.len());
    let data = to_u32(&bytestring);
    println!("data: {:?}", data);
    let s = process_block(&data);
    println!("s: {:?}", s);
}

fn add_md_padding(message: &[u8]) -> Vec<u8> {
    let message_length_bytes = message.len();
    let message_length_bits = message_length_bytes * 8;
    let padding_length_bits = (448 - message_length_bits) % 512;
    let padding_length = padding_length_bits / 8;
    let mut padding = vec![0u8; padding_length];
    println!("bits: {}, bytes: {}", padding_length_bits, padding_length);
    // add 1 bit at beginning
    padding[0] = 0x80;
    let message_length_bytestring = (message_length_bits as u64).to_le_bytes();
    let mut padded_message = vec![0u8; message.len() + padding_length + 8];
    // println!("message: {}, length: {}",message, mess )
    padded_message[..message_length_bytes].clone_from_slice(message);
    padded_message[message_length_bytes..message_length_bytes + padding_length]
        .clone_from_slice(&padding);
    padded_message[message_length_bytes + padding_length..]
        .clone_from_slice(&message_length_bytestring);
    padded_message
}

fn to_u32(input: &[u8]) -> Vec<u32> {
    let length = input.len() / 4;
    let mut to_return = vec![0u32; length];
    for (index, nums) in input.chunks(4).enumerate() {
        let a = u32::from(nums[3]);
        let b = u32::from(nums[2]);
        let c = u32::from(nums[1]);
        let d = u32::from(nums[0]);
        let current_num = (a << 24) + (b << 16) + (c << 8) + d;
        to_return[index] = current_num;
    }
    to_return
}
fn process_block(data: &[u32]) -> [u32; 4] {
    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }

    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }

    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    fn op1(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
        a.wrapping_add(f(b, c, d)).wrapping_add(k).rotate_left(s)
    }

    fn op2(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
        a.wrapping_add(g(b, c, d))
            .wrapping_add(k)
            .wrapping_add(0x5A82_7999)
            .rotate_left(s)
    }

    fn op3(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
        a.wrapping_add(h(b, c, d))
            .wrapping_add(k)
            .wrapping_add(0x6ED9_EBA1)
            .rotate_left(s)
    }

    let mut s: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

    let mut a = s[0];
    let mut b = s[1];
    let mut c = s[2];
    let mut d = s[3];

    // round 1
    for &i in &[0, 4, 8, 12] {
        a = op1(a, b, c, d, data[i], 3);
        d = op1(d, a, b, c, data[i + 1], 7);
        c = op1(c, d, a, b, data[i + 2], 11);
        b = op1(b, c, d, a, data[i + 3], 19);
        println!("Inside Round 1 - a: {}, d: {}, c: {}, b: {}", a, d, c, b);
    }
    println!("Round 1 - a: {}, b: {}, c: {}, d: {}", a, b, c, d);

    // round 2
    for i in 0..4 {
        a = op2(a, b, c, d, data[i], 3);
        d = op2(d, a, b, c, data[i + 4], 5);
        c = op2(c, d, a, b, data[i + 8], 9);
        b = op2(b, c, d, a, data[i + 12], 13);
    }
    println!("Round 2 - a: {}, b: {}, c: {}, d: {}", a, b, c, d);

    // round 3
    for &i in &[0, 2, 1, 3] {
        a = op3(a, b, c, d, data[i], 3);
        d = op3(d, a, b, c, data[i + 8], 9);
        c = op3(c, d, a, b, data[i + 4], 11);
        b = op3(b, c, d, a, data[i + 12], 15);
    }
    println!("Round 3 - a: {}, b: {}, c: {}, d: {}", a, b, c, d);
    println!("Before adding: {:?}", s);
    s[0] = s[0].wrapping_add(a);
    s[1] = s[1].wrapping_add(b);
    s[2] = s[2].wrapping_add(c);
    s[3] = s[3].wrapping_add(d);
    println!("Final s: {:?}", s);
    s
}

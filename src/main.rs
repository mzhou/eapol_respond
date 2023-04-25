use std::fs::File;
use std::io::{BufRead, BufReader};

use anyhow::{Context, Result};
use clap::Parser;
use hex::{decode_to_slice, encode};
use nix::net::if_::if_nametoindex;
use nix::sys::socket::{
    bind, recvfrom, sendto, sockaddr_ll, socket, AddressFamily, LinkAddr, MsgFlags, SockFlag,
    SockProtocol, SockType,
};

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, required = true)]
    identity: String,
    #[arg(long, required = true)]
    interface: String,
    #[arg(long, required = true)]
    md5_csv: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut responses = [[0u8; 16]; 256];

    for line_result in
        BufReader::new(File::open(args.md5_csv).context("open failed for md5 csv")?).lines()
    {
        let line = line_result.context("read line failed for md5 csv")?;
        let comma_pos = line.find(',').context("line missing comma")?;
        let mut id_arr = [0u8];
        decode_to_slice(&line[..comma_pos], &mut id_arr)
            .context("decode_to_slice failed for id")?;
        let id = id_arr[0] as usize;
        decode_to_slice(&line[comma_pos + 1..], &mut responses[id])
            .context("decode_to_slice failed for value")?;
    }

    for id in 0..responses.len() {
        if responses[id] == [0u8; 16] {
            eprintln!("warning: value missing for {}", id);
        }
    }

    let ifindex = if_nametoindex(args.interface.as_str()).context("interface not found")?;

    eprintln!("interface index is {}", ifindex);

    let fd = socket(
        AddressFamily::Packet,
        SockType::Datagram,
        SockFlag::empty(),
        SockProtocol::EthPae,
    )
    .context("socket failed")?;

    bind(
        fd,
        &LinkAddr(sockaddr_ll {
            sll_addr: [0; 8],
            sll_halen: 0,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_family: AddressFamily::Packet as u16,
            sll_ifindex: ifindex as i32,
            sll_protocol: SockProtocol::EthPae as u16,
        }),
    )
    .context("bind failed")?;

    let addr = LinkAddr(sockaddr_ll {
        sll_addr: [0x01, 0x80, 0xc2, 0x00, 0x00, 0x03, 0, 0],
        sll_halen: 6,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_family: AddressFamily::Packet as u16,
        sll_ifindex: ifindex as i32,
        sll_protocol: SockProtocol::EthPae as u16,
    });

    sendto(
        fd,
        &[
            // 802.1x
            0x01, // version
            0x01, // type
            0x00, 0x00, // length
        ],
        &addr,
        MsgFlags::empty(),
    )
    .context("sendto failed for start")?;

    let identity = args.identity.as_bytes();

    loop {
        let mut buf = [0u8; 1500];
        let (len, src_opt) = recvfrom::<LinkAddr>(fd, &mut buf).context("recvfrom failed")?;
        // request identity
        if len >= 9 && buf[..5] == [0x01, 0x00, 0x00, 0x05, 0x01] && buf[6..9] == [0x00, 0x05, 0x01]
        {
            let id = buf[5];
            eprintln!(
                "recvfrom request identity id {} from {:?}",
                id,
                src_opt.map(|a| a.addr()).flatten().map(encode)
            );
            let length = 5 + identity.len();
            let mut response = vec![
                // 802.1x
                0x01, // version
                0x00, // type
                (length / 256) as u8,
                length as u8, // length
                // eap
                0x02, // code
                id,   // id
                (length / 256) as u8,
                length as u8, // length
                0x01,         // type
            ];
            response.extend_from_slice(identity);
            eprintln!("response identity {}", encode(&response));
            sendto(fd, &response, &addr, MsgFlags::empty())
                .context("sendto failed for response identity")?;
        }
        // request md5-challenge eap
        if len >= 26
            && buf[..5] == [0x01, 0x00, 0x00, 0x16, 0x01]
            && buf[6..10] == [0x00, 0x16, 0x04, 0x10]
        {
            let id = buf[5];
            let value = &buf[10..26];
            eprintln!(
                "recvfrom request md5-challenge eap id {} value {}",
                id,
                encode(value)
            );
            if value
                != [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ]
            {
                eprintln!(
                    "warning: md5 challenge was {} instead of the expected 000102030405060708090a0b0c0d0e0f",
                    encode(value)
                );
            }
            let v = &responses[id as usize];
            let response = [
                // 802.1x
                0x01, // version
                0x00, // type
                0x00, 0x16, // length
                // eap
                0x02, // code
                id,   // id
                0x00, 0x16, // length
                0x04, // type
                0x10, // eap-md5 value-size
                v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], // eap-md5 value 0..8
                v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15], // eap-md5 value 0..8
            ];
            eprintln!("response md5-challenge eap {}", encode(&response));
            sendto(fd, &response, &addr, MsgFlags::empty())
                .context("sendto failed for response md5-challenge eap")?;
        }
        // success
        if len >= 8 && buf[..5] == [0x01, 0x00, 0x00, 0x04, 0x03] && buf[6..8] == [0x00, 0x04] {
            let id = buf[5];
            eprintln!("recvfrom success id {}", id);
        }
        // failure
        if len >= 6 && buf[..2] == [0x01, 0x00] && buf[4] == 0x04 {
            let id = buf[5];
            eprintln!("recvfrom failure id {}", id);
        }
    }
}

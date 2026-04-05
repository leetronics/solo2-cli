use anyhow::anyhow;
use iso7816::Status;

pub use crate::{device::pcsc::Device, Error, Result};

impl Device {
    pub fn call(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let data = data.unwrap_or(&[]);
        let mut send_buffer = Vec::<u8>::with_capacity(data.len() + 16);

        send_buffer.push(cla);
        send_buffer.push(ins);
        send_buffer.push(p1);
        send_buffer.push(p2);

        // TODO: checks, chain, ...
        let l = data.len();
        if l > 0 {
            if l <= 255 {
                send_buffer.push(l as u8);
            } else {
                send_buffer.push(0);
                send_buffer.extend_from_slice(&(l as u16).to_be_bytes());
            }
            send_buffer.extend_from_slice(data);
        }

        send_buffer.push(0);
        if l > 255 {
            send_buffer.push(0);
        }

        debug!(">> {}", hex::encode(&send_buffer));

        let mut recv_buffer = vec![0; 3072];

        let l = self.device.transmit(&send_buffer, &mut recv_buffer)?.len();
        debug!("RECV {} bytes", l);
        recv_buffer.resize(l, 0);
        debug!("<< {}", hex::encode(&recv_buffer));

        if l < 2 {
            return Err(anyhow!(
                "response should end with two status bytes! received {}",
                hex::encode(recv_buffer)
            ));
        }
        let sw2 = recv_buffer.pop().unwrap();
        let sw1 = recv_buffer.pop().unwrap();

        let status: std::result::Result<Status, _> = (sw1, sw2).try_into();
        match status {
            Ok(Status::Success) => {}
            Ok(Status::MoreAvailable(remaining)) => {
                // Accumulate the initial chunk, then issue GET RESPONSE until 9000
                let mut response = recv_buffer;
                let mut more = remaining;
                loop {
                    let get_response = [cla, 0xC0, 0x00, 0x00, more];
                    debug!(">> {}", hex::encode(&get_response));
                    let mut buf = vec![0; 3072];
                    let n = self.device.transmit(&get_response, &mut buf)?.len();
                    buf.resize(n, 0);
                    debug!("<< {}", hex::encode(&buf));
                    if n < 2 {
                        return Err(anyhow!("short response during GET RESPONSE chaining"));
                    }
                    let sw2b = buf.pop().unwrap();
                    let sw1b = buf.pop().unwrap();
                    response.extend_from_slice(&buf);
                    let next: std::result::Result<Status, _> = (sw1b, sw2b).try_into();
                    match next {
                        Ok(Status::Success) => break,
                        Ok(Status::MoreAvailable(n)) => more = n,
                        other => return Err(anyhow!(
                            "GET RESPONSE error: {:?} ({:X}, {:X})",
                            other, sw1b, sw2b
                        )),
                    }
                }
                return Ok(response);
            }
            other => {
                return Err(if !recv_buffer.is_empty() {
                    anyhow!(
                        "card signaled error {:?} ({:X}, {:X}) with data {}",
                        other,
                        sw1,
                        sw2,
                        hex::encode(recv_buffer)
                    )
                } else {
                    anyhow!("card signaled error: {:?} ({:X}, {:X})", other, sw1, sw2)
                });
            }
        }

        Ok(recv_buffer)
    }
}

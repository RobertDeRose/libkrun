const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
const VIRTIO_NET_HDR_GSO_ECN: u8 = 0x80;

#[derive(Clone, Copy, Debug)]
pub(crate) struct VirtioTxHeader {
    flags: u8,
    gso_type: u8,
    gso_size: usize,
    csum_start: usize,
    csum_offset: usize,
}

impl VirtioTxHeader {
    pub(crate) fn parse(header: &[u8]) -> Result<Self, ()> {
        if header.len() < 10 {
            return Err(());
        }

        Ok(Self {
            flags: header[0],
            gso_type: header[1],
            gso_size: u16::from_le_bytes([header[4], header[5]]) as usize,
            csum_start: u16::from_le_bytes([header[6], header[7]]) as usize,
            csum_offset: u16::from_le_bytes([header[8], header[9]]) as usize,
        })
    }

    fn needs_checksum(self) -> bool {
        self.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0
    }

    pub(crate) fn gso_type(self) -> u8 {
        self.gso_type & !VIRTIO_NET_HDR_GSO_ECN
    }

    fn has_ecn(self) -> bool {
        self.gso_type & VIRTIO_NET_HDR_GSO_ECN != 0
    }

    pub(crate) fn is_plain(self) -> bool {
        self.gso_type() == VIRTIO_NET_HDR_GSO_NONE && !self.needs_checksum()
    }
}

pub(crate) fn complete_checksum(
    frame: &[u8],
    header: VirtioTxHeader,
    output: &mut Vec<u8>,
) -> Result<(), ()> {
    let checksum = header
        .csum_start
        .checked_add(header.csum_offset)
        .ok_or(())?;
    if checksum + 2 > frame.len() || header.csum_start >= frame.len() {
        return Err(());
    }

    // For CHECKSUM_PARTIAL the guest leaves the pseudo-header checksum in
    // the checksum field. Folding the transport bytes including that seed
    // produces the final checksum expected on the wire.
    output.clear();
    output.extend_from_slice(frame);
    let value = checksum_finish_wire(checksum_sum(0, &output[header.csum_start..]));
    output[checksum..checksum + 2].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

pub(crate) struct TcpV4GsoPacket {
    frame: Vec<u8>,
    header: VirtioTxHeader,
    ip_offset: usize,
    ip_header_len: usize,
    tcp_offset: usize,
    header_len: usize,
    base_ip_id: u16,
    base_sequence: u32,
    payload_offset: usize,
    segment_index: u16,
}

impl TcpV4GsoPacket {
    pub(crate) fn new(frame: &[u8], header: VirtioTxHeader) -> Result<Self, ()> {
        if !header.needs_checksum()
            || header.has_ecn()
            || header.gso_type() != VIRTIO_NET_HDR_GSO_TCPV4
            || header.gso_size == 0
        {
            return Err(());
        }

        let ip_offset = ethernet_payload_offset(frame, 0x0800)?;
        if ip_offset + 20 > frame.len() || frame[ip_offset] >> 4 != 4 {
            return Err(());
        }
        let ip_header_len = ((frame[ip_offset] & 0x0f) as usize) * 4;
        if ip_header_len < 20
            || ip_offset + ip_header_len > frame.len()
            || frame[ip_offset + 9] != 6
            || header.csum_start != ip_offset + ip_header_len
        {
            return Err(());
        }
        let fragment = u16::from_be_bytes([frame[ip_offset + 6], frame[ip_offset + 7]]);
        if fragment & 0x3fff != 0 {
            return Err(());
        }

        let tcp_offset = header.csum_start;
        if tcp_offset + 20 > frame.len() {
            return Err(());
        }
        let tcp_header_len = ((frame[tcp_offset + 12] >> 4) as usize) * 4;
        let header_len = tcp_offset.checked_add(tcp_header_len).ok_or(())?;
        if tcp_header_len < 20
            || header_len >= frame.len()
            || header.csum_offset != 16
        {
            return Err(());
        }

        Ok(Self {
            frame: frame.to_vec(),
            header,
            ip_offset,
            ip_header_len,
            tcp_offset,
            header_len,
            base_ip_id: u16::from_be_bytes([frame[ip_offset + 4], frame[ip_offset + 5]]),
            base_sequence: u32::from_be_bytes([
                frame[tcp_offset + 4],
                frame[tcp_offset + 5],
                frame[tcp_offset + 6],
                frame[tcp_offset + 7],
            ]),
            payload_offset: 0,
            segment_index: 0,
        })
    }

    pub(crate) fn build_next_segment(&self, output: &mut Vec<u8>) -> Result<usize, ()> {
        let payload = &self.frame[self.header_len..];
        if self.payload_offset >= payload.len() {
            return Err(());
        }
        let payload_len = self
            .header
            .gso_size
            .min(payload.len() - self.payload_offset);
        let is_last = self.payload_offset + payload_len == payload.len();

        output.clear();
        output.extend_from_slice(&self.frame[..self.header_len]);
        output.extend_from_slice(
            &payload[self.payload_offset..self.payload_offset + payload_len],
        );

        let ip_total_len = output.len().checked_sub(self.ip_offset).ok_or(())?;
        if ip_total_len > u16::MAX as usize {
            return Err(());
        }
        output[self.ip_offset + 2..self.ip_offset + 4]
            .copy_from_slice(&(ip_total_len as u16).to_be_bytes());
        let ip_id = self.base_ip_id.wrapping_add(self.segment_index);
        output[self.ip_offset + 4..self.ip_offset + 6].copy_from_slice(&ip_id.to_be_bytes());
        output[self.ip_offset + 10..self.ip_offset + 12].fill(0);
        let ip_checksum = checksum_fold(checksum_sum(
            0,
            &output[self.ip_offset..self.ip_offset + self.ip_header_len],
        ));
        output[self.ip_offset + 10..self.ip_offset + 12]
            .copy_from_slice(&ip_checksum.to_be_bytes());

        let sequence = self.base_sequence.wrapping_add(self.payload_offset as u32);
        output[self.tcp_offset + 4..self.tcp_offset + 8]
            .copy_from_slice(&sequence.to_be_bytes());
        // FIN and PSH describe the complete GSO packet, so only the final
        // segment may carry them. CWR applies only to the first segment.
        if !is_last {
            output[self.tcp_offset + 13] &= !(0x01 | 0x08);
        }
        if self.segment_index != 0 {
            output[self.tcp_offset + 13] &= !0x80;
        }

        let checksum = self.tcp_offset + self.header.csum_offset;
        output[checksum..checksum + 2].fill(0);
        let tcp_checksum = tcp_v4_checksum(output, self.ip_offset, self.tcp_offset)?;
        output[checksum..checksum + 2].copy_from_slice(&tcp_checksum.to_be_bytes());

        Ok(payload_len)
    }

    pub(crate) fn advance(&mut self, payload_len: usize) {
        self.payload_offset += payload_len;
        self.segment_index = self.segment_index.wrapping_add(1);
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.payload_offset >= self.frame.len() - self.header_len
    }
}

fn ethernet_payload_offset(frame: &[u8], expected_type: u16) -> Result<usize, ()> {
    if frame.len() < 14 {
        return Err(());
    }
    let mut offset = 14;
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    for _ in 0..2 {
        if ethertype != 0x8100 && ethertype != 0x88a8 {
            break;
        }
        if offset + 4 > frame.len() {
            return Err(());
        }
        ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }
    if ethertype != expected_type {
        return Err(());
    }
    Ok(offset)
}

fn tcp_v4_checksum(frame: &[u8], ip_offset: usize, tcp_offset: usize) -> Result<u16, ()> {
    if ip_offset + 20 > frame.len() || tcp_offset >= frame.len() {
        return Err(());
    }
    let tcp_len = frame.len() - tcp_offset;
    if tcp_len > u16::MAX as usize {
        return Err(());
    }

    let mut sum = 0;
    sum = checksum_sum(sum, &frame[ip_offset + 12..ip_offset + 20]);
    sum = checksum_sum(sum, &[0, frame[ip_offset + 9]]);
    sum = checksum_sum(sum, &(tcp_len as u16).to_be_bytes());
    sum = checksum_sum(sum, &frame[tcp_offset..]);
    Ok(checksum_finish_wire(sum))
}

fn checksum_sum(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += (*byte as u32) << 8;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

fn checksum_fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn checksum_finish_wire(sum: u32) -> u16 {
    match checksum_fold(sum) {
        0 => 0xffff,
        value => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_v4_frame(payload_len: usize) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 20 + 20 + payload_len];
        frame[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

        let ip = 14;
        frame[ip] = 0x45;
        let ip_len = (frame.len() - ip) as u16;
        frame[ip + 2..ip + 4].copy_from_slice(&ip_len.to_be_bytes());
        frame[ip + 4..ip + 6].copy_from_slice(&0x1234u16.to_be_bytes());
        frame[ip + 6..ip + 8].copy_from_slice(&0x4000u16.to_be_bytes());
        frame[ip + 8] = 64;
        frame[ip + 9] = 6;
        frame[ip + 12..ip + 16].copy_from_slice(&[192, 168, 64, 2]);
        frame[ip + 16..ip + 20].copy_from_slice(&[192, 168, 64, 1]);
        let ip_checksum = checksum_fold(checksum_sum(0, &frame[ip..ip + 20]));
        frame[ip + 10..ip + 12].copy_from_slice(&ip_checksum.to_be_bytes());

        let tcp = ip + 20;
        frame[tcp..tcp + 2].copy_from_slice(&12345u16.to_be_bytes());
        frame[tcp + 2..tcp + 4].copy_from_slice(&8080u16.to_be_bytes());
        frame[tcp + 4..tcp + 8].copy_from_slice(&0x10203040u32.to_be_bytes());
        frame[tcp + 12] = 5 << 4;
        frame[tcp + 13] = 0x99; // CWR + PSH + FIN.
        frame[tcp + 14..tcp + 16].copy_from_slice(&65535u16.to_be_bytes());
        for (index, byte) in frame[tcp + 20..].iter_mut().enumerate() {
            *byte = (index & 0xff) as u8;
        }
        frame
    }

    fn checksum_valid(sum: u32) -> bool {
        checksum_fold(sum) == 0
    }

    #[test]
    fn completes_partial_transport_checksum() {
        let mut frame = tcp_v4_frame(64);
        let ip = 14;
        let tcp = ip + 20;
        let tcp_len = frame.len() - tcp;
        let mut pseudo = 0;
        pseudo = checksum_sum(pseudo, &frame[ip + 12..ip + 20]);
        pseudo = checksum_sum(pseudo, &[0, 6]);
        pseudo = checksum_sum(pseudo, &(tcp_len as u16).to_be_bytes());
        let seed = !checksum_fold(pseudo);
        frame[tcp + 16..tcp + 18].copy_from_slice(&seed.to_be_bytes());

        let header = VirtioTxHeader {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_NONE,
            gso_size: 0,
            csum_start: tcp,
            csum_offset: 16,
        };
        let mut output = Vec::new();
        complete_checksum(&frame, header, &mut output).unwrap();

        let mut sum = 0;
        sum = checksum_sum(sum, &output[ip + 12..ip + 20]);
        sum = checksum_sum(sum, &[0, 6]);
        sum = checksum_sum(sum, &(tcp_len as u16).to_be_bytes());
        sum = checksum_sum(sum, &output[tcp..]);
        assert!(checksum_valid(sum));
    }

    #[test]
    fn segments_tcp_v4_and_recomputes_headers() {
        let frame = tcp_v4_frame(2500);
        let header = VirtioTxHeader {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            gso_size: 1000,
            csum_start: 34,
            csum_offset: 16,
        };
        let mut packet = TcpV4GsoPacket::new(&frame, header).unwrap();
        let mut segment = Vec::new();
        let expected_payloads = [1000usize, 1000, 500];

        for (index, expected_payload) in expected_payloads.iter().enumerate() {
            let payload = packet.build_next_segment(&mut segment).unwrap();
            assert_eq!(payload, *expected_payload);
            assert_eq!(segment.len(), 54 + expected_payload);
            assert_eq!(
                u16::from_be_bytes([segment[16], segment[17]]) as usize,
                40 + expected_payload
            );
            assert_eq!(
                u16::from_be_bytes([segment[18], segment[19]]),
                0x1234u16.wrapping_add(index as u16)
            );
            assert_eq!(
                u32::from_be_bytes([segment[38], segment[39], segment[40], segment[41]]),
                0x10203040u32.wrapping_add((index * 1000) as u32)
            );
            if index + 1 == expected_payloads.len() {
                assert_eq!(segment[47] & 0x09, 0x09);
            } else {
                assert_eq!(segment[47] & 0x09, 0);
            }
            if index == 0 {
                assert_eq!(segment[47] & 0x80, 0x80);
            } else {
                assert_eq!(segment[47] & 0x80, 0);
            }
            assert!(checksum_valid(checksum_sum(0, &segment[14..34])));

            let tcp_len = segment.len() - 34;
            let mut tcp_sum = 0;
            tcp_sum = checksum_sum(tcp_sum, &segment[26..34]);
            tcp_sum = checksum_sum(tcp_sum, &[0, 6]);
            tcp_sum = checksum_sum(tcp_sum, &(tcp_len as u16).to_be_bytes());
            tcp_sum = checksum_sum(tcp_sum, &segment[34..]);
            assert!(checksum_valid(tcp_sum));

            packet.advance(payload);
        }
        assert!(packet.is_complete());
    }
}

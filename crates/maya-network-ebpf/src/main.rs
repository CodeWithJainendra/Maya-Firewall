#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const ETH_HDR_LEN: usize = 14;
const IPV4_MIN_HDR_LEN: usize = 20;
const TCP_MIN_HDR_LEN: usize = 20;

#[repr(C, packed)]
struct EthernetHeader {
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    ethertype: u16,
}

#[repr(C, packed)]
struct Ipv4Header {
    version_ihl: u8,
    tos: u8,
    total_length: u16,
    identification: u16,
    flags_fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
}

#[repr(C, packed)]
struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    data_offset_reserved: u8,
    flags: u8,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
}

#[map(name = "MONITORED_PORTS")]
static MONITORED_PORTS: HashMap<u16, u8> = HashMap::<u16, u8>::with_max_entries(256, 0);

#[map(name = "PORT_HITS")]
static PORT_HITS: HashMap<u16, u64> = HashMap::<u16, u64>::with_max_entries(256, 0);

#[xdp]
pub fn maya_ingress(ctx: XdpContext) -> u32 {
    match try_maya_ingress(&ctx) {
        Ok(action) => action,
        Err(action) => action,
    }
}

fn try_maya_ingress(ctx: &XdpContext) -> Result<u32, u32> {
    let eth: *const EthernetHeader = ptr_at(ctx, 0)?;
    let ethertype = u16::from_be(unsafe { (*eth).ethertype });
    if ethertype != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4: *const Ipv4Header = ptr_at(ctx, ETH_HDR_LEN)?;
    let version_ihl = unsafe { (*ipv4).version_ihl };
    let version = version_ihl >> 4;
    if version != 4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_header_len = ((version_ihl & 0x0f) as usize) * 4;
    if ip_header_len < IPV4_MIN_HDR_LEN {
        return Ok(xdp_action::XDP_PASS);
    }

    if unsafe { (*ipv4).protocol } != IPPROTO_TCP {
        return Ok(xdp_action::XDP_PASS);
    }

    let tcp_offset = ETH_HDR_LEN + ip_header_len;
    let tcp: *const TcpHeader = ptr_at(ctx, tcp_offset)?;
    let data_offset = ((unsafe { (*tcp).data_offset_reserved } >> 4) as usize) * 4;
    if data_offset < TCP_MIN_HDR_LEN {
        return Ok(xdp_action::XDP_PASS);
    }

    let dest_port = u16::from_be(unsafe { (*tcp).dst_port });
    if unsafe { MONITORED_PORTS.get(&dest_port) }.is_some() {
        bump_counter(dest_port);
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn bump_counter(dest_port: u16) {
    if let Some(counter) = unsafe { PORT_HITS.get_ptr_mut(&dest_port) } {
        unsafe {
            *counter += 1;
        }
    } else {
        let initial: u64 = 1;
        let _ = unsafe { PORT_HITS.insert(&dest_port, &initial, 0) };
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(xdp_action::XDP_ABORTED);
    }

    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "license")]
pub static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
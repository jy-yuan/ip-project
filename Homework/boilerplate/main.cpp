#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern void buildRipPacket(RipPacket *resp, uint32_t if_index);
extern void printRoutingTable();

uint8_t packet[2048];
uint8_t output[2048];
// 0: 192.168.3.2
// 1: 192.168.4.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a,
                                     0x0103000a};

int main(int argc, char *argv[]) {
  // 0a.
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

  // 0b. Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
        .addr = addrs[i] & 0x00FFFFFF, // big endian
        .len = 24,        // small endian
        .if_index = i,    // small endian
        .nexthop = 0,      // big endian, means direct
        .metric = 0
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000) {
      // What to do?
      // send complete routing table to every interface
      // ref. RFC2453 3.8
      // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
      for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
        output[0] = 0x45;
        output[1] = 0x00;
        output[4] = 0x00;
        output[5] = 0x00;
        output[6] = 0x40;
        output[7] = 0x00;
        output[8] = 0x01;
        output[9] = 0x11;
        output[12] = (uint8_t)(addrs[i] & 0xff);
        output[13] = (uint8_t)((addrs[i] >> 8) & 0xff);
        output[14] = (uint8_t)((addrs[i] >> 16) & 0xff);
        output[15] = (uint8_t)((addrs[i] >> 24) & 0xff);
        output[16] = 0xe0;
        output[17] = 0x00;
        output[18] = 0x00;
        output[19] = 0x09;
        // ...
        // UDP
        // port = 520
        output[20] = 0x02;
        output[21] = 0x08;
        output[22] = 0x02;
        output[23] = 0x08;
        output[26] = 0x00;
        output[27] = 0x00;
        // ...
        // RIP
        RipPacket resp;
        buildRipPacket(&resp, i);
        uint32_t rip_len = assemble(&resp, &output[20 + 8]);
        output[2] = (uint8_t) ((rip_len + 28) >> 8);
        output[3] = (uint8_t) rip_len + 28;
        output[24] = (uint8_t) ((rip_len + 8) >> 8);
        output[25] = (uint8_t) rip_len + 8;
        unsigned long checksum = 0;
        for (uint8_t j = 0; j < 20; j += 2) {
          if (j != 10) {
            checksum += (((unsigned long)packet[j] << 8) + (unsigned long)packet[j + 1]);
          }
        }
        checksum = (checksum >> 16) + (checksum & 0xffff);
        checksum += checksum >> 16;
        output[10] = (uint8_t)((~checksum) >> 8);
        output[11] = (uint8_t)(~checksum);
        macaddr_t dst_mac;
        HAL_ArpGetMacAddress(0, 0x090000e0, dst_mac);
        HAL_SendIPPacket(i, output, rip_len + 20 + 8, dst_mac);
      }
      printf("5s Timer\n");
      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    // 1. validate
    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    src_addr = (in_addr_t)packet[12];
    src_addr += ((in_addr_t)packet[13]) << 8;
    src_addr += ((in_addr_t)packet[14]) << 16;
    src_addr += ((in_addr_t)packet[15]) << 24;
    dst_addr = (in_addr_t)packet[16];
    dst_addr += ((in_addr_t)packet[17]) << 8;
    dst_addr += ((in_addr_t)packet[18]) << 16;
    dst_addr += ((in_addr_t)packet[19]) << 24;
    // extract src_addr and dst_addr from packet
    // big endian

    // 2. check whether dst is me
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    // TODO: Handle rip multicast address(224.0.0.9)?
    if (dst_addr == 0x090000e0) {
      dst_is_me = true;
    }

    if (dst_is_me) {
      printf("dst is me...\n");
      // 3a.1
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) {
          printf("receive request...\n");
          // 3a.3 request, ref. RFC2453 3.9.1
          // only need to respond to whole table requests in the lab
          RipPacket resp;
          buildRipPacket(&resp, if_index);
          // TODO: fill resp
          // assemble
          // IP
          output[0] = 0x45;
          output[1] = 0x00;
          output[4] = 0x00;
          output[5] = 0x00;
          output[6] = 0x40;
          output[7] = 0x00;
          output[8] = 0x01;
          output[9] = 0x11;
          output[12] = (uint8_t)(dst_addr & 0xff);
          output[13] = (uint8_t)((dst_addr >> 8) & 0xff);
          output[14] = (uint8_t)((dst_addr >> 16) & 0xff);
          output[15] = (uint8_t)((dst_addr >> 24) & 0xff);
          output[16] = (uint8_t)(src_addr & 0xff);
          output[17] = (uint8_t)((src_addr >> 8) & 0xff);
          output[18] = (uint8_t)((src_addr >> 16) & 0xff);
          output[19] = (uint8_t)((src_addr >> 24) & 0xff);
          // ...
          // UDP
          // port = 520
          output[20] = 0x02;
          output[21] = 0x08;
          output[22] = 0x02;
          output[23] = 0x08;
          // ...
          // RIP
          uint32_t rip_len = assemble(&resp, &output[20 + 8]);
          output[2] = (uint8_t) ((rip_len + 28) >> 8);
          output[3] = (uint8_t) rip_len + 28;
          output[24] = (uint8_t) ((rip_len + 8) >> 8);
          output[25] = (uint8_t) rip_len + 8;
          // TODO: checksum
          // checksum calculation for ip and udp
          unsigned long checksum = 0;
          for (uint8_t i = 0; i < 20; i += 2) {
            if (i != 10) {
              checksum += (((unsigned long)packet[i] << 8) + (unsigned long)packet[i + 1]);
            }
          }
          checksum = (checksum >> 16) + (checksum & 0xffff);
          checksum += checksum >> 16;
          output[10] = (uint8_t)((~checksum) >> 8);
          output[11] = (uint8_t)~checksum;
          output[26] = 0x00;
          output[27] = 0x00;
          // if you don't want to calculate udp checksum, set it to zero
          // send it back
          HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
        } else {
          printf("receive response...\n");
          // 3a.2 response, ref. RFC2453 3.9.2
          // update routing table
          // new metric = ?
          // update metric, if_index, nexthop
          // what is missing from RoutingTableEntry?
          // TODO: use query and update
          // triggered updates? ref. RFC2453 3.10.1
          uint32_t count = rip.numEntries;
          for (uint32_t i = 0; i < count; i++) {
            uint32_t nexthop, dest_if, metric;
            uint32_t len = 0;
            uint32_t seMask = ntohl(rip.entries[i].mask);
            for (int j = 0; j < 32; j++) {
              if((seMask >> j) % 2 == 1) {
                len = 32 - j;
                break;
              }
            }
            RoutingTableEntry tableEntry = {
                .addr = rip.entries[i].addr,
                .len = len,
                .if_index = (uint32_t) if_index,
                .nexthop = src_addr,
                .metric = rip.entries[i].metric
            };
            if (rip.entries[i].metric > 0x10000000) {
              update(false, tableEntry);
            }
            if (query(rip.entries[i].addr, &nexthop, &dest_if, &metric)) {
              if(rip.entries[i].metric < metric) {
                update(true, tableEntry);
              }
            } else {
              update(true, tableEntry);
            }
          }
          printRoutingTable();
        }
      }
    } else {
      printf("dst is not me...\n");
      // 3b.1 dst is not me
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if, metric;
      if (query(dst_addr, &nexthop, &dest_if, &metric)) {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          // found
          memcpy(output, packet, res);
          // update ttl and checksum
          if (forward(output, res)) {
            printf("forwarding...\n");
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
          }
        } else {
          // not found
          // you can drop it
          printf("ARP not found for %x\n", nexthop);
        }
      } else {
        // not found
        // optionally you can send ICMP Host Unreachable
        printf("IP not found for %x\n", src_addr);
      }
    }
  }
  return 0;
}

#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  uint32_t headlength = 4 * (packet[0] & 0xf) + 8;
  uint8_t command = packet[headlength];
  uint8_t version = packet[headlength+1];
  uint32_t TotalLength = ((uint32_t)packet[2] << 8) + packet[3];
  if(TotalLength > len) {
    return false;
  }
  if((command != 0x1 && command != 0x2) || version != 0x2 || packet[headlength+2] != 0x0 || packet[headlength+3] != 0x0) {
    return false;
  }
  uint32_t count = (len - headlength - 4) / 20;
  for(uint32_t i = 0; i < count; i++) {
    if((command == 0x2 && packet[headlength + 4 + i*20 + 1] != 0x2) || (command == 0x1 && packet[headlength + 4 + i*20 + 1] != 0x0)) {
      return false;
    }
    if(packet[headlength + 4 + i*20 + 2] != 0x0 || packet[headlength + 4 + i*20 + 3] != 0x0) {
      return false;
    }
    uint32_t addr = packet[headlength + 4 + i*20 + 4] + ((uint32_t)packet[headlength + 4 + i*20 + 5] << 8) + ((uint32_t)packet[headlength + 4 + i*20 + 6] << 16) + ((uint32_t)packet[headlength + 4 + i*20 + 7] << 24);
    uint32_t mask = packet[headlength + 4 + i*20 + 8] + ((uint32_t)packet[headlength + 4 + i*20 + 9] << 8) + ((uint32_t)packet[headlength + 4 + i*20 + 10] << 16) + ((uint32_t)packet[headlength + 4 + i*20 + 11] << 24);
    uint32_t nexthop = packet[headlength + 4 + i*20 + 12] + ((uint32_t)packet[headlength + 4 + i*20 + 13] << 8) + ((uint32_t)packet[headlength + 4 + i*20 + 14] << 16) + ((uint32_t)packet[headlength + 4 + i*20 + 15] << 24);
    uint32_t metric = packet[headlength + 4 + i*20 + 16] + ((uint32_t)packet[headlength + 4 + i*20 + 17] << 8) + ((uint32_t)packet[headlength + 4 + i*20 + 18] << 16) + ((uint32_t)packet[headlength + 4 + i*20 + 19] << 24);
    uint32_t flag = mask % 2;
    for(int j = 1; j < 32; j++) {
      if (((mask >> j) % 2) != flag) {
        if(flag == 0) {
          return false;
        } else {
          flag = 0;
        }
      }
    }
    if(ntohl(metric) < 1 || ntohl(metric) > 16) {
      return false;
    }
    output->entries[i].addr = addr;
    output->entries[i].mask = mask;
    output->entries[i].nexthop = nexthop;
    output->entries[i].metric = metric;
  }
  output->numEntries = count;
  output->command = command;
  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  uint32_t count = rip->numEntries;
  buffer[0] = rip->command;
  buffer[1] = 0x2;
  buffer[2] = 0x0;
  buffer[3] = 0x0;
  for(uint32_t i = 0; i < count; i++) {
    buffer[4 + i*20] = 0x0;
    buffer[4 + i*20 + 1] = (rip->command == 0x2) ? 0x2 : 0x0;
    buffer[4 + i*20 + 2] = 0x0;
    buffer[4 + i*20 + 3] = 0x0;
    buffer[4 + i*20 + 4] = (uint8_t)(rip->entries[i].addr & 0xff);
    buffer[4 + i*20 + 5] = (uint8_t)((rip->entries[i].addr >> 8) & 0xff);
    buffer[4 + i*20 + 6] = (uint8_t)((rip->entries[i].addr >> 16) & 0xff);
    buffer[4 + i*20 + 7] = (uint8_t)((rip->entries[i].addr >> 24) & 0xff);
    buffer[4 + i*20 + 8] = (uint8_t)(rip->entries[i].mask & 0xff);
    buffer[4 + i*20 + 9] = (uint8_t)((rip->entries[i].mask >> 8) & 0xff);
    buffer[4 + i*20 + 10] = (uint8_t)((rip->entries[i].mask >> 16) & 0xff);
    buffer[4 + i*20 + 11] = (uint8_t)((rip->entries[i].mask >> 24) & 0xff);
    buffer[4 + i*20 + 12] = (uint8_t)(rip->entries[i].nexthop & 0xff);
    buffer[4 + i*20 + 13] = (uint8_t)((rip->entries[i].nexthop >> 8) & 0xff);
    buffer[4 + i*20 + 14] = (uint8_t)((rip->entries[i].nexthop >> 16) & 0xff);
    buffer[4 + i*20 + 15] = (uint8_t)((rip->entries[i].nexthop >> 24) & 0xff);
    buffer[4 + i*20 + 16] = (uint8_t)(rip->entries[i].metric & 0xff);
    buffer[4 + i*20 + 17] = (uint8_t)((rip->entries[i].metric >> 8) & 0xff);
    buffer[4 + i*20 + 18] = (uint8_t)((rip->entries[i].metric >> 16) & 0xff);
    buffer[4 + i*20 + 19] = (uint8_t)((rip->entries[i].metric >> 24) & 0xff);
  }
  return 4 + 20*count;
}

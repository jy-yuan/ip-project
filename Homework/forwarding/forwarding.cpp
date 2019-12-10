#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len)
{
  uint8_t length = 4 * (packet[0] & 0xf);
  unsigned long checksum = 0;
  unsigned short realchecksum = 0;
  for (uint8_t i = 0; i < length; i += 2)
  {
    if (i == 10)
    {
      realchecksum = ((unsigned short)packet[i] << 8) + (unsigned short)packet[i + 1];
    }
    else
    {
      checksum += (((unsigned long)packet[i] << 8) + (unsigned long)packet[i + 1]);
    }
  }
  checksum = (checksum >> 16) + (checksum & 0xffff);
  checksum += checksum >> 16;
  if (realchecksum == ((unsigned short)~checksum))
  {
    packet[8] -= 1;
    checksum = 0;
    for (uint8_t i = 0; i < length; i += 2)
    {
      if (i != 10)
      {
        checksum += (((unsigned long)packet[i] << 8) + (unsigned long)packet[i + 1]);
      }
    }
    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum += checksum >> 16;
    packet[10] = (uint8_t)((~checksum) >> 8);
    packet[11] = (uint8_t)~checksum;
    return true;
  }
  else
  {
    return false;
  }
}

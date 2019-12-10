#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len)
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
  if (realchecksum == ((unsigned short) ~checksum))
  {
    return true;
  }
  else
  {
    return false;
  }
}

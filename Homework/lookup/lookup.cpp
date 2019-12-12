#include "rip.h"
#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <vector>
using std::vector;

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
    uint32_t metric;
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

vector<RoutingTableEntry> RouteTable;

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool insert, RoutingTableEntry entry)
{
  for (auto it = RouteTable.begin(); it != RouteTable.end(); it++) {
    if ((*it).addr == entry.addr && (*it).len == entry.len) {
      RouteTable.erase(it);
      break;
    }
  }
  if (insert)
    RouteTable.push_back(entry);
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric)
{
  *nexthop = 0;
  *if_index = 0;
  bool flag = false;
  uint32_t maxlen = 0;
  uint32_t laddr = ntohl(addr);
  for(auto it = RouteTable.begin(); it != RouteTable.end(); it++) {
    uint32_t tmpaddr = ntohl((*it).addr);
    int mov = 32 - (*it).len;
    if((laddr >> mov) == (tmpaddr >> mov)) {
      flag = true;
      if(maxlen < (*it).len) {
        maxlen = (*it).len;
        *nexthop = (*it).nexthop;
        *if_index = (*it).if_index;
        *metric = (*it).metric;
      }
    }
  }
  return flag;
}

void buidRipPacket(RipPacket *resp, uint32_t if_index) {
  *resp.numEntries = RouteTable.size();
  *resp.command = 2;
  int i = 0;
  for (auto tableEntry : RouteTable) {
    if(tableEntry.if_index == if_index){
      continue;
    }
    uint32_t mask = ntohl(((1 << tableEntry.len) - 1) << (32 - tableEntry.len));
    RipEntry ripEntry = {
        .addr = tableEntry.addr,
        .mask = mask,
        .nexthop = tableEntry.nexthop,
        .metric = tableEntry.metric + 0x01000000
    };
    *resp.entries[i] = ripEntry;
    i++;
  }
}

void printRoutingTable() {
  printf("RouteTable:\n");
  for (auto it = RouteTable.begin(); it != RouteTable.end(); it++) {
    printf("%x/%x,%x,%x,%x\n", (*it).addr, (*it).len, (*it).if_index, (*it).nexthop, (*it).metric);
  }
}
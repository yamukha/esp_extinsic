#include  "../libraries/RpcRobonomics/Data.h"
#include  "../libraries/RpcRobonomics/Call.h"

void test () {
  auto record = "42";
  Data head_dr = Data{0x33,0};
  Data call = callDatalogRecord(head_dr, record);
}

int main () {
  test ();
}

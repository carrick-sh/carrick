import struct
p='/private/tmp/el1-ipc-lldb-8177.core'
b=open(p,'rb').read(); n=struct.unpack_from('<I',b,16)[0]; at=32
for _ in range(n):
 cmd,size=struct.unpack_from('<II',b,at)
 if cmd==0x19:
  va,vsz,off,fsz=struct.unpack_from('<QQQQ',b,at+24)
  data=b[off:off+fsz]; start=0
  while True:
   pos=data.find(b'CRKIPC\0\3',start)
   if pos<0:break
   print('IPC magic',hex(va+pos),'file',hex(off+pos),'header',data[pos:pos+32].hex())
   start=pos+8
 at+=size
base=0x25a000
assert struct.unpack_from('<Q',b,base+8)[0]==0xdb76683c8df6451e
objects=base+147648
for i in range(1024):
 at=objects+192*i
 lock,kind=struct.unpack_from('<II',b,at)
 if kind:
  print('object',i,'kind',kind,'lock',lock,'gen/readseq/writeseq',struct.unpack_from('<QQQ',b,at+8),'sub/owed',struct.unpack_from('<II',b,at+32),'state',struct.unpack_from('<9Q',b,at+80))
for i in range(1024):
 at=base+344320+136*i
 gen,live=struct.unpack_from('<II',b,at)
 if live:
  op=at+16
  print('operation',i,'generation',gen,'live',live,'kind',struct.unpack_from('<I',b,op)[0],'object',struct.unpack_from('<II',b,op+32),'task/mm/buf/len/written/park/value/fd',struct.unpack_from('<8Q',b,op+40),'nr',struct.unpack_from('<I',b,op+104)[0])

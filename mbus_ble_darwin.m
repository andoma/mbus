#include "mbus_i.h"

#import <Foundation/Foundation.h>
#import <CoreBluetooth/CoreBluetooth.h>

typedef struct mbus_ble mbus_ble_t;

@interface L2CAPClient : NSObject<CBCentralManagerDelegate, CBPeripheralDelegate, NSStreamDelegate>
{
  mbus_ble_t *mbus;
  uint8_t rxbuf[256];
  size_t rxlen;
}

-(id)initWithMbus:(mbus_ble_t *)mbus;
@property (strong, nonatomic) CBCentralManager *centralManager;
@property (strong, nonatomic) CBPeripheral *discoveredPeripheral;
@property (strong, nonatomic) NSOutputStream* outputStream;
@property (strong, nonatomic) NSInputStream* inputStream;
@property (strong, nonatomic) CBL2CAPChannel *l2capChannel;
@end


struct mbus_ble {
  mbus_t m;
  char *name;
  pthread_t tid;
  L2CAPClient *l2cap;
};


@implementation L2CAPClient


-(id)initWithMbus:(mbus_ble_t *)mbus_ {
  self->mbus = mbus_;
  self.centralManager = [[CBCentralManager alloc] initWithDelegate:self queue:nil];
  rxlen = 0;
  return [self init];
}

- (void)startScan
{
  if(self.discoveredPeripheral)
    return;
  NSArray * uuidList = nil;
  [self.centralManager scanForPeripheralsWithServices:uuidList
                                              options:@{ CBCentralManagerScanOptionAllowDuplicatesKey : @NO }];
  NSLog(@"Scanning started");
}


- (void)centralManagerDidUpdateState:(CBCentralManager *)central
{
  NSLog(@"State %ld", central.state);

  switch(central.state) {
  case CBManagerStatePoweredOn:
    [self startScan];
    break;
  case CBManagerStatePoweredOff:
    [self.centralManager stopScan];
    break;
  default:
    break;
  }
}

- (void)centralManager:(CBCentralManager *)central
 didDiscoverPeripheral:(CBPeripheral *)peripheral
     advertisementData:(NSDictionary *)advertisementData
                  RSSI:(NSNumber *)RSSI
{
  if(!peripheral.name.UTF8String)
    return;

  if(!strcmp(peripheral.name.UTF8String, mbus->name)) {
    NSLog(@"Discovered %@ at %@ dBm, adv %@", peripheral.name, RSSI, advertisementData);

    if(self.discoveredPeripheral != peripheral) {

      self.discoveredPeripheral = peripheral;
      [self.centralManager connectPeripheral:peripheral options:nil];
    }
  }
}

    - (void)centralManager:(CBCentralManager *)central
didFailToConnectPeripheral:(CBPeripheral *)peripheral
                     error:(NSError *)error
{
  NSLog(@"Failed to connect to %@. (%@)", peripheral, [error localizedDescription]);
}

- (void)centralManager:(CBCentralManager *)central
  didConnectPeripheral:(CBPeripheral *)peripheral
{
  NSLog(@"Peripheral Connected");
  [self.centralManager stopScan];
  self.discoveredPeripheral.delegate = self;
  [self.discoveredPeripheral openL2CAPChannel:0xc3];
}

- (void)centralManager:(CBCentralManager *)central
didDisconnectPeripheral:(CBPeripheral *)peripheral
                 error:(NSError *)error {
  NSLog(@"Device disconnected%@. (%@)", peripheral, [error localizedDescription]);

  self.discoveredPeripheral = nil;
  [self startScan];
}


-(void)peripheral:(CBPeripheral *)peripheral
didOpenL2CAPChannel:(CBL2CAPChannel *)channel
            error:(NSError *)error
{
  if(error) {
    NSLog(@"didOpenL2CAPChannel: %@", error);

  } else {
    NSLog(@"Connected to peripheral %@", self.discoveredPeripheral);
    self.l2capChannel = channel;

    [self.l2capChannel.outputStream open];
    [self.l2capChannel.inputStream open];

    self.inputStream = self.l2capChannel.inputStream;
    self.outputStream = self.l2capChannel.outputStream;
    self.inputStream.delegate = self;

    NSRunLoop *runLoop = [NSRunLoop currentRunLoop];

    [self.inputStream scheduleInRunLoop:runLoop
                                forMode:NSDefaultRunLoopMode];

  }
}


-(void)stream:(NSStream *)aStream handleEvent:(NSStreamEvent)eventCode
{
  switch(eventCode) {
  default:
    printf("stream event %ld\n", eventCode);
    break;

  case NSStreamEventErrorOccurred:
    printf("Stream error\n");
  case NSStreamEventEndEncountered:
    [self.inputStream close];
    [self.inputStream removeFromRunLoop:[NSRunLoop currentRunLoop]
                                forMode:NSDefaultRunLoopMode];
    [self.outputStream close];

    self.inputStream = nil;
    self.outputStream = nil;
    self.l2capChannel = nil;
    printf("Stream closed\n");
    break;

  case NSStreamEventHasBytesAvailable:
    while(rxlen < sizeof(rxbuf)) {
      NSInteger n = [self.inputStream read:rxbuf maxLength:sizeof(rxbuf) - rxlen];
      if(n < 1)
        break;

      rxlen += n;
      while(rxlen >= 2) {
        int plen = rxbuf[0] | (rxbuf[1] << 8);
        int tlen = plen + 2;
        if(tlen > rxlen)
          break;
        pthread_mutex_lock(&mbus->m.m_mutex);
        mbus_rx_handle_pkt(&mbus->m, rxbuf + 2, plen, 1);
        pthread_mutex_unlock(&mbus->m.m_mutex);

        memmove(rxbuf, rxbuf + tlen, rxlen - tlen);
        rxlen -= tlen;
      }
    }
    break;
  }
}

@end


static mbus_error_t
mbus_ble_send(mbus_t *m, const void *data,
              size_t len, const struct timespec *deadline)
{
  mbus_ble_t *mb = (mbus_ble_t *)m;

  if(!mb->l2cap.l2capChannel) {
    printf("Not open\n");
    return 0;
  }

  uint8_t pkt[2 + len + 4];
  memcpy(pkt + 2, data, len);
  uint32_t crc = ~mbus_crc32(0, pkt + 2, len);
  memcpy(pkt + 2 + len, &crc, 4);
  mbus_pkt_trace(m, "TX", pkt + 2, len + 4);
  pkt[0] = (len + 4);
  pkt[1] = (len + 4) >> 8;
  [mb->l2cap.outputStream write:pkt maxLength:len + 2 + 4];
  return 0;
}

mbus_t *
mbus_create_ble(const char *name, uint8_t local_addr,
                mbus_log_cb_t *log_cb, void *aux)
{

  mbus_ble_t *mb = calloc(1, sizeof(mbus_ble_t));

  mb->name = strdup(name);

  mb->m.m_our_addr = local_addr;
  mb->m.m_send = mbus_ble_send;

  mbus_init_common(&mb->m, log_cb, aux);

  mb->l2cap = [[L2CAPClient alloc] initWithMbus:mb];
  return &mb->m;
}

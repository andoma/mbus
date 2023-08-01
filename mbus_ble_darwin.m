#include "mbus_i.h"

#import <Foundation/Foundation.h>
#import <CoreBluetooth/CoreBluetooth.h>

TAILQ_HEAD(pkt_queue, pkt);

typedef struct mbus_ble mbus_ble_t;

@class BleGateway;

@interface Connection : NSObject<NSStreamDelegate>
{
  uint8_t rxbuf[256];
  size_t rxlen;
}

-(id)initWithGateway:(BleGateway *)gw l2cap:(CBL2CAPChannel *)channel;

@property (strong, nonatomic) CBL2CAPChannel *channel;
@property (strong, nonatomic) BleGateway *gateway;
@end



@interface BleGateway : NSObject<CBCentralManagerDelegate, CBPeripheralDelegate>
{
}

-(id)initWithMbus:(mbus_ble_t *)m;

@property (assign, nonatomic) mbus_ble_t *mbus;
@property (strong, nonatomic) CBCentralManager *centralManager;
@property (strong, nonatomic) CBPeripheral *discoveredPeripheral;
@property (strong, nonatomic) NSMutableArray *connections;
@property (strong, nonatomic) Connection *primary;
@end




struct mbus_ble {
  mbus_t m;
  char *name;
  BleGateway *gateway;
};


@implementation BleGateway

-(id)initWithMbus:(mbus_ble_t *)m {
  self.mbus = m;
  self.centralManager = [[CBCentralManager alloc] initWithDelegate:self queue:nil];
  self.connections = [[NSMutableArray alloc] init];
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

  if(!strcmp(peripheral.name.UTF8String, self.mbus->name)) {
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
  NSLog(@"Failed to connect to %@. (%@)",
        peripheral, [error localizedDescription]);
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
  NSLog(@"Device disconnected: %@. (%@)",
        peripheral, [error localizedDescription]);

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
    Connection *c = [[Connection alloc] initWithGateway:self l2cap:channel];
    printf("concreate:%ld\n", CFGetRetainCount(c));
    [self.connections addObject: c];

    if(channel.PSM == 0xc3) {
      self.primary = c;
      NSLog(@"Primary connection established");
    }
    [c release];
    printf("concreate:%ld\n", CFGetRetainCount(c));
  }
}

-(void)deleteConnection:(Connection *)c
{
  pthread_mutex_lock(&self.mbus->m.m_mutex);
  if(self.primary == c)
    self.primary = nil;

  [self.connections removeObject:c];
  pthread_mutex_unlock(&self.mbus->m.m_mutex);
}


@end

@implementation Connection

-(id)initWithGateway:(BleGateway *)gw l2cap:(CBL2CAPChannel *)c
{
  rxlen = 0;

  self.gateway = gw;
  self.channel = c;
  [c.inputStream open];
  [c.outputStream open];

  c.inputStream.delegate = self;

  NSRunLoop *runLoop = [NSRunLoop currentRunLoop];

  [c.inputStream scheduleInRunLoop:runLoop
                           forMode:NSDefaultRunLoopMode];
  [c.outputStream scheduleInRunLoop:runLoop
                            forMode:NSDefaultRunLoopMode];

  return [self init];
}


-(void)destroy
{
  self.channel.inputStream.delegate = nil;
  [self.channel.inputStream close];
  [self.channel.inputStream removeFromRunLoop:[NSRunLoop currentRunLoop]
                                      forMode:NSDefaultRunLoopMode];

  [self.channel.outputStream close];
  [self.channel.outputStream removeFromRunLoop:[NSRunLoop currentRunLoop]
                                       forMode:NSDefaultRunLoopMode];
  [self.gateway deleteConnection:self];
}


-(void)stream:(NSStream *)aStream handleEvent:(NSStreamEvent)eventCode
{
  mbus_ble_t *mb = self.gateway.mbus;

  switch(eventCode) {
  default:
    printf("stream event %ld\n", eventCode);
    break;

  case NSStreamEventErrorOccurred:
    printf("Stream error\n");
    [self destroy];
    break;
  case NSStreamEventEndEncountered:
    printf("Stream end\n");
    [self destroy];
    break;

  case NSStreamEventHasBytesAvailable:
    while(rxlen < sizeof(rxbuf)) {
      if(![self.channel.inputStream hasBytesAvailable])
        break;

      NSInteger n = [self.channel.inputStream read:rxbuf+rxlen maxLength:sizeof(rxbuf) - rxlen];
      if(n < 1)
        break;
      rxlen += n;
      while(rxlen >= 2) {
        int plen = rxbuf[0] | (rxbuf[1] << 8);
        int tlen = plen + 2;
        if(tlen > 80) {
          abort();
        }
        if(tlen > rxlen)
          break;
        pthread_mutex_lock(&mb->m.m_mutex);
        mbus_rx_handle_pkt(&mb->m, rxbuf + 2, plen, 1);
        pthread_mutex_unlock(&mb->m.m_mutex);

        memmove(rxbuf, rxbuf + tlen, rxlen - tlen);
        assert(rxlen >= tlen);
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
  size_t pktlen = 2 + len + 4;

  uint8_t *pkt = malloc(pktlen);

  memcpy(pkt + 2, data, len);
  uint32_t crc = ~mbus_crc32(0, pkt + 2, len);
  memcpy(pkt + 2 + len, &crc, 4);
  mbus_pkt_trace(m, "TX", pkt + 2, len + 4, 2);
  pkt[0] = (len + 4);
  pkt[1] = (len + 4) >> 8;

  dispatch_async(dispatch_get_main_queue(), ^{
      Connection *c = mb->gateway.primary;
      if(c) {
        printf("Attempt to transmit\n");
        int n = [c.channel.outputStream write:pkt maxLength:pktlen];
        printf("xmit:%d\n", n);
        if(n != pktlen) {
          fprintf(stderr, "BLE Short send tried:%zd did:%d\n", pktlen, n);
          abort();
        }
      }
      free(pkt);
    });
#if 0
  [c retain];

  pthread_mutex_unlock(&m->m_mutex);
#if 1
  while(![c.channel.outputStream hasSpaceAvailable]) {
    usleep(100000);
    printf("WAT LOL NO SPACE HEH\n");
  }
#endif
  int n = [c.channel.outputStream write:pkt maxLength:pktlen];
  if(n != pktlen) {
    fprintf(stderr, "BLE Short send tried:%zd did:%d\n", pktlen, n);
    abort();
  }
  pthread_mutex_lock(&m->m_mutex);
  [c release];
#endif
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
  mb->m.m_connect_locked = mbus_gdpkt_connect_locked;

  mbus_init_common(&mb->m, log_cb, aux);

  mb->gateway = [[BleGateway alloc] initWithMbus:mb];
  return &mb->m;
}

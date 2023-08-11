#include "mbus_i.h"

#import <Foundation/Foundation.h>
#import <CoreBluetooth/CoreBluetooth.h>

TAILQ_HEAD(pkt_queue, pkt);

typedef struct pkt {
  TAILQ_ENTRY(pkt) link;
  size_t len;
  uint8_t data[0];
} pkt_t;


typedef struct mbus_ble mbus_ble_t;

@class BleGateway;

@interface Connection : NSObject<NSStreamDelegate>
{
  uint8_t rxbuf[256];
  size_t rxlen;
  bool maytx;
  struct pkt_queue txq;
  size_t txqlen;
}

-(id)initWithGateway:(BleGateway *)gw l2cap:(CBL2CAPChannel *)channel;

@property (strong, nonatomic) CBL2CAPChannel *channel;
@property (strong, nonatomic) BleGateway *gateway;
@end



@interface BleGateway : NSObject<CBCentralManagerDelegate, CBPeripheralDelegate>
{
  pthread_cond_t primary_cond;
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
  pthread_cond_init(&primary_cond, NULL);
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
  mbus_t *m = &self.mbus->m;
  if(m->m_status_cb)
    m->m_status_cb(m->m_aux, MBUS_SCANNING);
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
    [self.connections addObject: c];

    if(channel.PSM == 0xc3) {
      mbus_t *m = &self.mbus->m;
      if(m->m_status_cb)
        m->m_status_cb(m->m_aux, MBUS_CONNECTED);

      pthread_mutex_lock(&self.mbus->m.m_mutex);
      self.primary = c;
      pthread_cond_signal(&primary_cond);
      pthread_mutex_unlock(&self.mbus->m.m_mutex);

      NSLog(@"Primary connection established");
    }
    [c release];
  }
}

-(void)deleteConnection:(Connection *)c
{
  pthread_mutex_lock(&self.mbus->m.m_mutex);
  if(self.primary == c)
    self.primary = nil;

  [self.connections removeObject:c];
  pthread_mutex_unlock(&self.mbus->m.m_mutex);

  mbus_t *m = &self.mbus->m;
  if(m->m_status_cb)
    m->m_status_cb(m->m_aux, MBUS_DISCONNECTED);

}

-(Connection *)getConnection:(const struct timespec *)deadline
{
  while(self.primary == nil) {
    if(pthread_cond_timedwait(&primary_cond, &self.mbus->m.m_mutex,
                              deadline) == ETIMEDOUT) {
      return nil;
    }
  }
  return self.primary;
}


@end

@implementation Connection

-(id)initWithGateway:(BleGateway *)gw l2cap:(CBL2CAPChannel *)c
{
  rxlen = 0;
  maytx = false;
  TAILQ_INIT(&txq);
  txqlen = 0;
  self.gateway = gw;
  self.channel = c;
  [c.inputStream open];
  [c.outputStream open];

  c.inputStream.delegate = self;
  c.outputStream.delegate = self;

  NSRunLoop *runLoop = [NSRunLoop currentRunLoop];

  [c.inputStream scheduleInRunLoop:runLoop
                           forMode:NSDefaultRunLoopMode];
  [c.outputStream scheduleInRunLoop:runLoop
                            forMode:NSDefaultRunLoopMode];

  return [self init];
}


-(void)destroy
{
  mbus_ble_t *mb = self.gateway.mbus;
  mbus_gateway_disconnect(&mb->m);

  self.channel.inputStream.delegate = nil;
  [self.channel.inputStream close];
  [self.channel.inputStream removeFromRunLoop:[NSRunLoop currentRunLoop]
                                      forMode:NSDefaultRunLoopMode];

  [self.channel.outputStream close];
  [self.channel.outputStream removeFromRunLoop:[NSRunLoop currentRunLoop]
                                       forMode:NSDefaultRunLoopMode];
  [self.gateway deleteConnection:self];
}

-(void)maybeTx
{
  if(!maytx)
    return;

  mbus_ble_t *mb = self.gateway.mbus;
  mbus_t *m = &mb->m;

  pthread_mutex_lock(&m->m_mutex);
  pkt_t *pkt = TAILQ_FIRST(&txq);
  if(pkt != NULL) {
    maytx = false;
    TAILQ_REMOVE(&txq, pkt, link);
    txqlen--;

    mbus_pkt_trace(m, "TX", pkt->data + 2, pkt->len - 2, 2);

    int n = [self.channel.outputStream write:pkt->data maxLength:pkt->len];
    if(n != pkt->len) {
      fprintf(stderr, "BLE send failed\n");
    }
    free(pkt);
  }
  pthread_mutex_unlock(&m->m_mutex);
}

-(void)enqTx:(pkt_t *)pkt
{
  TAILQ_INSERT_TAIL(&txq, pkt, link);
  txqlen++;
  dispatch_async(dispatch_get_main_queue(), ^{
      [self maybeTx];
    });
}

-(void)stream:(NSStream *)aStream handleEvent:(NSStreamEvent)eventCode
{
  mbus_ble_t *mb = self.gateway.mbus;

  if(aStream == self.channel.outputStream) {
    if(eventCode == 4) {
      maytx = true;
      [self maybeTx];
    }
    return;
  }

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

  pkt_t *pkt = malloc(sizeof(pkt_t) + pktlen);
  pkt->len = pktlen;
  uint8_t *pd = pkt->data;

  memcpy(pd + 2, data, len);
  uint32_t crc = ~mbus_crc32(0, pd + 2, len);
  memcpy(pd + 2 + len, &crc, 4);
  pd[0] = (len + 4);
  pd[1] = (len + 4) >> 8;


  Connection *c = [mb->gateway getConnection:deadline];
  if(c) {
    [c enqTx:pkt];
    return 0;
  } else {
    free(pkt);
    return  MBUS_ERR_NOT_CONNECTED;
  }

}

mbus_t *
mbus_create_ble(const char *name, uint8_t local_addr,
                mbus_log_cb_t *log_cb, mbus_status_cb_t *status_cb, void *aux)
{
  mbus_ble_t *mb = calloc(1, sizeof(mbus_ble_t));

  mb->name = strdup(name);

  mb->m.m_our_addr = local_addr;
  mb->m.m_send = mbus_ble_send;
  mb->m.m_connect_locked = mbus_gdpkt_connect_locked;
  mb->m.m_connect_flowtype = 3;
  mbus_init_common(&mb->m, log_cb, status_cb, aux);

  mb->gateway = [[BleGateway alloc] initWithMbus:mb];
  return &mb->m;
}

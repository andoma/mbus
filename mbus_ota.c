#include "mbus_i.h"

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/param.h>
#include <errno.h>
#include <unistd.h>
#include <libelf.h>


typedef struct {
  uint32_t src_offset;
  uint32_t dst_offset;
  uint32_t length;
} flash_multi_write_chunk_t;


typedef struct {
  uint32_t num_chunks;
  flash_multi_write_chunk_t chunks[0];
} flash_multi_write_chunks_t;


static mbus_error_t
mbus_ota_xfer(mbus_t *m, mbus_seqpkt_con_t *msc,
              const void *image, size_t image_size,
              int blocksize)
{
  mbus_log(m, "OTA: Transfer starting %zd bytes, blocksize:%d",
           image_size, blocksize);

  uint32_t header[2] = { image_size / blocksize,
    ~mbus_crc32(0, image, image_size)};
  mbus_seqpkt_send(msc, &header[0], 8);

  for(size_t i = 0; i < image_size; i += blocksize) {
    printf("Xfer: %zd / %zd\r", i, image_size);
    fflush(stdout);
    mbus_seqpkt_send(msc, image + i, blocksize);
  }
  printf("Waiting for confirmation\n");
  // Wait for final reply
  void *data;
  int len = mbus_seqpkt_recv(msc, &data);
  if(len <= 0)
    return MBUS_ERR_OPERATION_FAILED;
  const uint8_t *info = data;
  mbus_error_t err = 0;
  if(info[0] && len > 0) {
    err = -info[0];
    mbus_log(m, "OTA: FAILED -- Target returned: %s",
             mbus_error_to_string(err));
  } else {
    mbus_log(m, "OTA: OK");
  }
  free(data);

  return err;
}


// Transmit sections
static mbus_error_t
mbus_ota_elf_perform_s(mbus_t *m, mbus_seqpkt_con_t *msc, Elf *elf, int fd,
                       int blocksize)
{
  size_t count = 0;
  int r = elf_getphdrnum(elf, &count);
  if(r) {
    return MBUS_ERR_MISMATCH;
  }

  Elf32_Phdr *phdr = elf32_getphdr(elf);

  size_t total_load_size = 0;

  int output_chunks = 0;
  for(size_t i = 0; i < count; i++) {
    if(phdr[i].p_type != 1)
      continue;
    total_load_size += phdr[i].p_filesz;
    output_chunks++;
  }

  const uint32_t header_size =
    sizeof(flash_multi_write_chunks_t) +
    sizeof(flash_multi_write_chunk_t) * output_chunks;

  uint32_t image_size = header_size + total_load_size;

  image_size = (image_size + blocksize - 1) & ~(blocksize - 1);

  mbus_log(m, "OTA: Total image size:0x%x (Multiple sections)", image_size);

  void *image = calloc(1, image_size);

  flash_multi_write_chunks_t *c = image;

  uint32_t src_offset = header_size;
  c->num_chunks = output_chunks;
  int fail = 0;
  int j = 0;
  for(size_t i = 0; i < count; i++) {
    if(phdr[i].p_type != 1)
      continue;
    c->chunks[j].src_offset = src_offset;
    c->chunks[j].dst_offset = phdr[i].p_paddr;
    c->chunks[j].length = phdr[i].p_filesz;
    src_offset += phdr[i].p_filesz;
    mbus_log(m, "OTA: Section %zd From 0x%08x to 0x%08x size:0x%08x | %x %x",
             i,
             c->chunks[j].src_offset,
             c->chunks[j].dst_offset,
             c->chunks[j].length,
             phdr[i].p_type,
             phdr[i].p_flags);
    if(pread(fd, image + c->chunks[j].src_offset,
             c->chunks[j].length, phdr[i].p_offset) != c->chunks[j].length) {
      mbus_log(m, "Failed to load data into memory from file");
      fail = 1;
    }
    j++;
  }

  if(fail) {
    return MBUS_ERR_OPERATION_FAILED;
  }

  mbus_error_t err = mbus_ota_xfer(m, msc, image, image_size, blocksize);
  free(image);
  return err;
}




// Transmit single raw image
static mbus_error_t
mbus_ota_elf_perform_r(mbus_t *m, mbus_seqpkt_con_t *msc, Elf *elf, int fd,
                       int blocksize, int offset)
{
  size_t count = 0;
  int r = elf_getphdrnum(elf, &count);
  if(r) {
    return MBUS_ERR_MISMATCH;
  }

  Elf32_Phdr *phdr = elf32_getphdr(elf);

  uint32_t start_addr = 0xffffffff;
  uint32_t end_addr = 0;
  for(size_t i = 0; i < count; i++) {
    start_addr = MIN(start_addr, phdr[i].p_paddr);
    end_addr = MAX(end_addr, phdr[i].p_paddr + phdr[i].p_filesz);
  }

  if(end_addr < start_addr) {
    return MBUS_ERR_OPERATION_FAILED;
  }

  end_addr = (end_addr + blocksize - 1) & ~(blocksize - 1);
  uint32_t image_size = end_addr - start_addr;

  void *image = malloc(image_size);
  memset(image, 0xff, image_size);
  mbus_log(m, "OTA: Image size: 0x%08x", image_size);

  int fail = 0;
  for(size_t i = 0; i < count; i++) {
    uint32_t offset = phdr[i].p_paddr - start_addr;
    uint32_t len = phdr[i].p_filesz;

    mbus_log(m, "OTA: Section %zd at 0x%08x size:0x08%x",
           i, phdr[i].p_paddr, len);

    if(pread(fd, image + offset,
             len, phdr[i].p_offset) != len)
      fail = 1;
  }

  if(fail)
    return MBUS_ERR_OPERATION_FAILED;

  mbus_error_t err = mbus_ota_xfer(m, msc,
                                   image + offset, image_size - offset,
                                   blocksize);
  free(image);
  return err;
}







static mbus_error_t
mbus_ota_elf_perform(mbus_t *m, mbus_seqpkt_con_t *msc,
                     Elf *elf, int fd, char otamode, int blocksize,
                     int offset)
{
  if(otamode == 's') {
    return mbus_ota_elf_perform_s(m, msc, elf, fd, blocksize);
  } else if(otamode == 'r') {
    return mbus_ota_elf_perform_r(m, msc, elf, fd, blocksize, offset);
  } else {
    return MBUS_ERR_MISMATCH;
  }
}



static void
bin2hex(char *out, const uint8_t *src, size_t len)
{
  for(size_t i = 0; i < len; i++) {
    out[i * 2 + 0] = "0123456789abcdef"[src[i] >> 4];
    out[i * 2 + 1] = "0123456789abcdef"[src[i] & 15];
  }
  out[len * 2] = 0;
}

mbus_error_t
mbus_ota_prepare(mbus_t *m, mbus_seqpkt_con_t *msc,
                 const char *running_appname,
                 const uint8_t *running_build_id,
                 Elf *elf, int force_upgrade, char mode, int fd,
                 int blocksize, int offset)
{
  uint8_t loaded_build_id[20] = {0};
  char loaded_appname[32] = {'?'};

  Elf_Scn *scn = NULL;

  size_t shstrndx;
  if(elf_getshdrstrndx(elf, &shstrndx)) {
    return MBUS_ERR_MISMATCH;
  }

  while((scn = elf_nextscn(elf, scn)) != NULL) {
    Elf32_Shdr *shdr = elf32_getshdr(scn);
    const char *name = elf_strptr(elf, shstrndx, shdr->sh_name);
    if(!strcmp(name, ".build_id")) {
      Elf_Data *data = elf_getdata(scn, NULL);
      if(data->d_size == 0x24) {
        memcpy(loaded_build_id, data->d_buf + 0x10, 20);
      }
    } else if(!strcmp(name, ".appname")) {
      Elf_Data *data = elf_getdata(scn, NULL);
      if(data->d_size < 32) {
        memcpy(loaded_appname, data->d_buf, data->d_size);
      }
    }
  }

  char hex[41];
  bin2hex(hex, loaded_build_id, 20);

  mbus_log(m, "OTA: Loaded:  App:%s buildid:%s",
           loaded_appname, hex);

  if(strcmp(running_appname, loaded_appname)) {
    mbus_log(m, "OTA: Update rejected, appname mismatches");
    return MBUS_ERR_MISMATCH;
  }

  mbus_error_t err = 0;

  if(memcmp(loaded_build_id, running_build_id, 20) || force_upgrade) {
    // Build-id differs, do upgrade
    err = mbus_ota_elf_perform(m, msc, elf, fd, mode, blocksize, offset);
  }

  return err;
}



mbus_error_t
mbus_ota_open_elf(mbus_t *m, mbus_seqpkt_con_t *msc,
                  const char *path, const char *appname,
                  const uint8_t *buildid, int force, int mode,
                  int blocksize, int offset)
{
  int fd = open(path, O_RDONLY);
  if(fd == -1) {
    mbus_log(m, "Unable to open %s -- %s", path, strerror(errno));
    return MBUS_ERR_OPERATION_FAILED;
  }

  elf_version(EV_CURRENT);

  Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
  if(elf == NULL) {
    close(fd);
    return MBUS_ERR_MISMATCH;
  }


  mbus_error_t err = mbus_ota_prepare(m, msc, appname, buildid, elf,
                                      force, mode, fd, blocksize,
                                      offset);

  elf_end(elf);
  close(fd);
  return err;
}



mbus_error_t
mbus_ota(mbus_t *m, uint8_t target_addr, const char *path,
         int force_upgrade)
{
  mbus_seqpkt_con_t *msc = mbus_seqpkt_connect(m, target_addr, "ota");
  void *data;
  int len = mbus_seqpkt_recv(msc, &data);
  if(len <= 0) {
    mbus_log(m, "OTA: Failed to receive current running info");
    return MBUS_ERR_OPERATION_FAILED;
  }

  if(len < 4 + 21) {
    mbus_log(m, "OTA: Current running info is too sohrt");
    free(data);
    return MBUS_ERR_OPERATION_FAILED;
  }

  const uint8_t *pkt = data;
  char hex[41];
  bin2hex(hex, pkt + 4, 20);
  int appnamelen = len - 4 - 20;

  char *appname = malloc(appnamelen + 1);
  memcpy(appname, pkt + 4 + 20, appnamelen);
  appname[appnamelen] = 0;

  mbus_log(m, "OTA: Running: App:%s buildid:%s Mode:%c",
           appname, hex, pkt[1]);

  uint8_t mode = pkt[1];
  uint8_t blocksize = pkt[2];
  uint32_t offset = pkt[3] * 1024;

  mbus_error_t err = mbus_ota_open_elf(m, msc, path, appname, pkt + 4,
                                       force_upgrade, mode, blocksize,
                                       offset);

  free(data);
  free(appname);
  mbus_seqpkt_close(msc, 0);
  return err;

}

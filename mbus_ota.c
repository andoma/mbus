#include "mbus_i.h"

#include <stdio.h>
#include <string.h>
#include <libelf.h>
#include <unistd.h>
#include <stdlib.h>

#include <fcntl.h>


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
mbus_ota_elf_perform(mbus_t *m, uint8_t target_addr, Elf *elf, int fd)
{
  size_t count = 0;
  int r = elf_getphdrnum(elf, &count);
  if(r) {
    return MBUS_ERR_MISMATCH;
  }

  Elf32_Phdr *phdr = elf32_getphdr(elf);

  size_t total_load_size = 0;
  for(size_t i = 0; i < count; i++) {
    total_load_size += phdr[i].p_filesz;
  }

  const uint32_t header_size =
    sizeof(flash_multi_write_chunks_t) +
    sizeof(flash_multi_write_chunk_t) * count;

  uint32_t image_size = header_size + total_load_size;

  image_size = (image_size + 15) & ~15;

  mbus_log(m, "OTA: Total image size:0x%x (Multiple sections)", image_size);

  void *image = calloc(1, image_size);

  flash_multi_write_chunks_t *c = image;

  uint32_t src_offset = header_size;
  c->num_chunks = count;
  int fail = 0;
  for(size_t i = 0; i < count; i++) {
    c->chunks[i].src_offset = src_offset;
    c->chunks[i].dst_offset = phdr[i].p_paddr;
    c->chunks[i].length = phdr[i].p_filesz;
    src_offset += phdr[i].p_filesz;
    mbus_log(m, "OTA: Section %zd From 0x%08x to 0x%08x size:0x%x",
           i,
           c->chunks[i].src_offset,
           c->chunks[i].dst_offset,
           c->chunks[i].length);
    if(pread(fd, image + c->chunks[i].src_offset,
             c->chunks[i].length, phdr[i].p_offset) != c->chunks[i].length)
      fail = 1;
  }

  if(fail)
    return MBUS_ERR_OPERATION_FAILED;

  mbus_error_t err = mbus_ota(m, target_addr, image, image_size, 's');
  free(image);
  return err;
}




mbus_error_t
mbus_ota_elf(mbus_t *m, uint8_t target_addr, const char *path)
{
  mbus_error_t err;

  uint8_t loaded_build_id[20] = {0};

  uint8_t running_build_id[20];
  size_t running_build_id_size = sizeof(running_build_id);
  err = mbus_invoke(m, target_addr, "buildid", NULL, 0,
                    running_build_id, &running_build_id_size, 1000);
  if(err)
    return err;

  char otamode;
  size_t otamode_size = sizeof(otamode);
  err = mbus_invoke(m, target_addr, "otamode", NULL, 0,
                    &otamode, &otamode_size, 1000);
  if(err)
    return err;

  mbus_log(m, "OTA: Running build-id: %02x%02x%02x%02x%02x%02x%02x%02x"
           "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x Mode:'%c'",
           running_build_id[0],
           running_build_id[1],
           running_build_id[2],
           running_build_id[3],
           running_build_id[4],
           running_build_id[5],
           running_build_id[6],
           running_build_id[7],
           running_build_id[8],
           running_build_id[9],
           running_build_id[10],
           running_build_id[11],
           running_build_id[12],
           running_build_id[13],
           running_build_id[14],
           running_build_id[15],
           running_build_id[16],
           running_build_id[17],
           running_build_id[18],
           running_build_id[19],
           otamode);

  int fd = open(path, O_RDONLY);
  if(fd == -1)
    return MBUS_ERR_OPERATION_FAILED;

  elf_version(EV_CURRENT);

  Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
  if(elf == NULL) {
    close(fd);
    return MBUS_ERR_MISMATCH;
  }

  size_t shstrndx;
  if(elf_getshdrstrndx(elf, &shstrndx)) {
    elf_end(elf);
    close(fd);
    return MBUS_ERR_MISMATCH;
  }

  Elf_Scn *scn = NULL;

  while((scn = elf_nextscn(elf, scn)) != NULL) {
    Elf32_Shdr *shdr = elf32_getshdr(scn);
    const char *name = elf_strptr(elf, shstrndx, shdr->sh_name);
    if(!strcmp(name, ".build_id")) {
      Elf_Data *data = elf_getdata(scn, NULL);
      if(data->d_size == 0x24) {
        memcpy(loaded_build_id, data->d_buf + 0x10, 20);
      }
    }
  }
  mbus_log(m, "OTA:  Loaded build-id: %02x%02x%02x%02x%02x%02x%02x%02x"
           "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
           loaded_build_id[0],
           loaded_build_id[1],
           loaded_build_id[2],
           loaded_build_id[3],
           loaded_build_id[4],
           loaded_build_id[5],
           loaded_build_id[6],
           loaded_build_id[7],
           loaded_build_id[8],
           loaded_build_id[9],
           loaded_build_id[10],
           loaded_build_id[11],
           loaded_build_id[12],
           loaded_build_id[13],
           loaded_build_id[14],
           loaded_build_id[15],
           loaded_build_id[16],
           loaded_build_id[17],
           loaded_build_id[18],
           loaded_build_id[19]);


  err = 0;
  if(memcmp(loaded_build_id, running_build_id, 20)) {
    // Build-id differs, do upgrade
    err = mbus_ota_elf_perform(m, target_addr, elf, fd);
  } else {
    mbus_log(m, "OTA: Image already running");
  }
  elf_end(elf);
  close(fd);
  return err;
}


typedef struct {
  uint32_t blocks;
  uint32_t crc;
  uint8_t hostaddr;
  char image_type;
} ota_req_t;


mbus_error_t
mbus_ota(mbus_t *m, uint8_t target_addr,
         const void *image, size_t image_size, char type)
{
  // Size must be multiple of 16
  if(image_size & 15)
    return MBUS_ERR_MISMATCH;

  pthread_mutex_lock(&m->m_mutex);

  if(m->m_ota_image != NULL) {
    pthread_mutex_unlock(&m->m_mutex);
    return MBUS_ERR_NOT_IDLE;
  }

  m->m_ota_image = image;
  m->m_ota_image_size = image_size;
  m->m_ota_completed = 0;

  ota_req_t req = { image_size / 16, ~mbus_crc32(0, image, image_size),
                    mbus_get_local_addr(m), type};

  struct timespec deadline = mbus_deadline_from_timeout(1000);

  mbus_error_t err = mbus_invoke_locked(m, target_addr,
                                        "ota", &req, sizeof(req),
                                        NULL, 0, &deadline);
  if(!err) {

    while(!m->m_ota_completed) {
      pthread_cond_wait(&m->m_ota_cond, &m->m_mutex);
    }
    err = m->m_ota_xfer_error;
  }

  m->m_ota_image = NULL;
  pthread_mutex_unlock(&m->m_mutex);
  return err;
}


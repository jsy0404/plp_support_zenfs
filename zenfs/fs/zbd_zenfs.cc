// Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved.
// Copyright (c) 2019-present, Western Digital Corporation
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#if !defined(ROCKSDB_LITE) && !defined(OS_WIN)
#define NVME_IOCTL_ID _IO('N', 0x40)
#define NVME_IOCTL_IO64_CMD _IOWR('N', 0x43, struct nvme_passthru_cmd64)
#define NVME_IOCTL_SUBMIT_IO	_IOW('N', 0x42, struct nvme_user_io)

#include <stdlib.h>
#include <fcntl.h>
#include <libzbd/zbd.h>
#include <linux/nvme_ioctl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "zbd_zenfs.h"
#include <iostream>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libzbd/zbd.h>
#include <linux/blkzoned.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <string>
#include <sstream>
#include <fstream>
#include <utility>
#include <vector>

#include "io_zenfs.h"
#include "rocksdb/env.h"

#define KB (1024)
#define MB (1024 * KB)

/* Number of reserved zones for metadata
 * Two non-offline meta zones are needed to be able
 * to roll the metadata log safely. One extra
 * is allocated to cover for one zone going offline.
 */
#define ZENFS_META_ZONES (3)

/* Minimum of number of zones that makes sense */
#define ZENFS_MIN_ZONES (32)

namespace ROCKSDB_NAMESPACE {

Zone::Zone(ZonedBlockDevice *zbd, struct zbd_zone *z)
    : zbd_(zbd),
      start_(zbd_zone_start(z)),
      max_capacity_(zbd_zone_capacity(z)),
      wp_(zbd_zone_wp(z)),
      open_for_write_(false)
  {
  lifetime_ = Env::WLTH_NOT_SET;
  used_capacity_ = 0;
  capacity_ = 0;
  plp_ = false;
  if (!(zbd_zone_full(z) || zbd_zone_offline(z) || zbd_zone_rdonly(z)))
    capacity_ = zbd_zone_capacity(z) - (zbd_zone_wp(z) - zbd_zone_start(z));
}

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef unsigned long int uintptr_t;

bool Zone::IsUsed() { return (used_capacity_ > 0) || open_for_write_; }
uint64_t Zone::GetCapacityLeft() { return capacity_; }
bool Zone::IsFull() { return (capacity_ == 0); }
bool Zone::IsEmpty() { return (wp_ == start_); }
uint64_t Zone::GetZoneNr() { return start_ / zbd_->GetZoneSize(); }

void Zone::CloseWR() {
  assert(open_for_write_);
  open_for_write_ = false;

  if (Close().ok()) {
    zbd_->NotifyIOZoneClosed();
  }

  if (capacity_ == 0) zbd_->NotifyIOZoneFull();
}

IOStatus Zone::Reset() {
  size_t zone_sz = zbd_->GetZoneSize();
  unsigned int report = 1;
  struct zbd_zone z;
  int ret;
  plp_ = false;
  assert(!IsUsed());

  ret = zbd_reset_zones(zbd_->GetWriteFD(), start_, zone_sz);
  if (ret) return IOStatus::IOError("Zone reset failed\n");

  ret = zbd_report_zones(zbd_->GetReadFD(), start_, zone_sz, ZBD_RO_ALL, &z, &report);

  if (ret || (report != 1)) return IOStatus::IOError("Zone report failed\n");

  if (zbd_zone_offline(&z))
    capacity_ = 0;
  else
    max_capacity_ = capacity_ = zbd_zone_capacity(&z);

  wp_ = start_;
  lifetime_ = Env::WLTH_NOT_SET;

  return IOStatus::OK();
}

IOStatus Zone::Finish() {
  size_t zone_sz = zbd_->GetZoneSize();
  int fd = zbd_->GetWriteFD();
  int ret;

  assert(!open_for_write_);

  ret = zbd_finish_zones(fd, start_, zone_sz);
  if (ret) return IOStatus::IOError("Zone finish failed\n");

  capacity_ = 0;
  wp_ = start_ + zone_sz;

  return IOStatus::OK();
}

IOStatus Zone::Close() {
  size_t zone_sz = zbd_->GetZoneSize();
  int fd = zbd_->GetWriteFD();
  int ret;

  assert(!open_for_write_);

  if (!(IsEmpty() || IsFull())) {
    ret = zbd_close_zones(fd, start_, zone_sz);
    if (ret) return IOStatus::IOError("Zone close failed\n");
  }

  return IOStatus::OK();
}

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef unsigned long int uintptr_t;

__u32 Zone::Pwrite2Ioctl(int fd, void *data, uint32_t size, uint64_t wp, bool plp=false)
{
	struct nvme_passthru_cmd64 cmd;
	int err;

	__u16 nblocks = (size/zbd_->GetBlockSize()) -1;
	__u64 slba = wp / zbd_->GetBlockSize();
	
	__u32 cdw10 = slba & 0xffffffff;
	__u32 cdw11 = slba >> 32;
	__u32 cdw12 = nblocks;

	memset(&cmd, 0, sizeof(struct nvme_passthru_cmd64));

	cmd.opcode = 0x01;
	cmd.nsid   = ioctl(fd, NVME_IOCTL_ID);
	cmd.cdw3   = plp;
	cmd.addr = (__u64)/*(uintptr_t)*/data;
	cmd.data_len = size;
	cmd.cdw10  = cdw10;
	cmd.cdw11  = cdw11;
	cmd.cdw12  = cdw12;
	
	err = ioctl(fd, NVME_IOCTL_IO64_CMD, &cmd);
	if (err < 0) {
		perror("ioctl error");
		return err;
	}
	return size;
}


IOStatus Zone::Append(char *data, uint32_t size) {
  char *ptr = data;
  uint32_t left = size;
  uint32_t write_size = zbd_->GetZasl();
  int fd = zbd_->GetWriteFD();
  int ret;

  if (capacity_ < size)
    return IOStatus::NoSpace("Not enough capacity for append");

  assert((size % zbd_->GetBlockSize()) == 0);

  while (left) {
	//ret = pwrite(fd, ptr, size, wp_);
	size = left > write_size ? write_size : left;
	ret = Pwrite2Ioctl(fd, ptr, size, wp_, plp_);
    if (ret < 0) return IOStatus::IOError("Write failed");
    ptr += ret;
    wp_ += ret;
    capacity_ -= ret;
    left -= ret;
  }
  return IOStatus::OK();
}

ZoneExtent::ZoneExtent(uint64_t start, uint32_t length, Zone *zone)
    : start_(start), length_(length), zone_(zone) {}

Zone *ZonedBlockDevice::GetIOZone(uint64_t offset) {
  for (const auto z : io_zones)
    if (z->start_ <= offset && offset < (z->start_ + zone_sz_)) return z;
  return nullptr;
}

ZonedBlockDevice::ZonedBlockDevice(std::string bdevname,
                                   std::shared_ptr<Logger> logger)
    : filename_("/dev/" + bdevname), logger_(logger) {
  Info(logger_, "New Zoned Block Device: %s", filename_.c_str());
};


std::string ZonedBlockDevice::ErrorToString(int err) {
  char *err_str = strerror(err);
  if (err_str != nullptr)
    return std::string(err_str);
  return "";
}

IOStatus ZonedBlockDevice::CheckScheduler() {
  std::ostringstream path;
  std::string s = filename_;
  std::fstream f;

  s.erase(0, 5); // Remove "/dev/" from /dev/nvmeXnY
  path << "/sys/block/" << s << "/queue/scheduler";
  f.open(path.str(), std::fstream::in);
  if (!f.is_open()) {
    return IOStatus::InvalidArgument("Failed to open " + path.str());
  }

  std::string buf;
  getline(f, buf);
  if (buf.find("[mq-deadline]") == std::string::npos) {
    f.close();
    return IOStatus::InvalidArgument("Current ZBD scheduler is not mq-deadline, set it to mq-deadline.");
  }

  f.close();
  return IOStatus::OK();
}

#define __force
#define NVME_IOCTL_IO_CMD _IOWR('N', 0x43, struct nvme_passthru_cmd)
#define NVME_IOCTL_ADMIN_CMD    _IOWR('N', 0x41, struct nvme_admin_cmd)

#define msg(lvl, format, ...)                       \
    do {                                \
        if ((lvl) <= MAX_LOGLEVEL)              \
            __msg(lvl, _log_func, format, ##__VA_ARGS__);   \
    } while (0)

void __attribute__((format(printf, 3, 4)))
__msg(int lvl, const char *func, const char *format, ...);

static inline uint64_t le64_to_cpu(__le64 x)
{
    return le64toh((__force __u64)x);
}

struct nvme_zone_report {
    __le64          nr_zones;
    __u8            resv8[56];
    void            *entries;
};

void nvme_free(void *p)
{
    free(p);
}

static void *__nvme_alloc(size_t len, bool *huge)
{
    void *p;

    if (!posix_memalign(&p, getpagesize(), len)) {
        *huge = false;
        memset(p, 0, len);
        return p;
    }
    return NULL;
}

void *nvme_alloc(size_t len, bool *huge)
{
    return __nvme_alloc(len, huge);
}

int nvme_zns_mgmt_recv(int fd, __u32 nsid, __u64 slba,
               __u32 zra, __u8 zrasf,
               bool zras_feat, __u32 data_len, void *data)
{
    __u32 cdw10 = slba & 0xffffffff;
    __u32 cdw11 = slba >> 32;
    __u32 cdw12 = (data_len >> 2) - 1;
    __u32 cdw13 = zra | zrasf << 8 | zras_feat << 16;

    struct nvme_passthru_cmd cmd = {
        .opcode     = 0x7a,
        .nsid       = nsid,
        .addr       = (__u64)(uintptr_t)data,
        .data_len   = data_len,
        .cdw10      = cdw10,
        .cdw11      = cdw11,
        .cdw12      = cdw12,
        .cdw13      = cdw13,
    };

    return ioctl(fd,NVME_IOCTL_IO_CMD, &cmd);
}

IOStatus ZonedBlockDevice::Open(bool readonly) {
  struct zbd_zone *zone_rep;
  unsigned int reported_zones;
  size_t addr_space_sz;
  zbd_info info;
  Status s;
  uint64_t i = 0;
  uint64_t m = 0;
  int ret;
  __u32 report_size;
  __u8 pg_sz[2];
  __u16 page_size;
  void *report;
  bool huge = false;

  read_f_ = zbd_open(filename_.c_str(), O_RDONLY, &info);
  if (read_f_ < 0) {
    return IOStatus::InvalidArgument("Failed to open zoned block device: " + ErrorToString(errno));
  }

  read_direct_f_ = zbd_open(filename_.c_str(), O_RDONLY | O_DIRECT, &info);
  if (read_direct_f_ < 0) {
    return IOStatus::InvalidArgument("Failed to open zoned block device: " + ErrorToString(errno));
  }

  if (readonly) {
    write_f_ = -1;
  } else {
    write_f_ = zbd_open(filename_.c_str(), O_WRONLY | O_DIRECT | O_EXCL, &info);
    if (write_f_ < 0) {
      return IOStatus::InvalidArgument("Failed to open zoned block device: " + ErrorToString(errno));
    }
  }

  if (info.model != ZBD_DM_HOST_MANAGED) {
    return IOStatus::NotSupported("Not a host managed block device");
  }

  if (info.nr_zones < ZENFS_MIN_ZONES) {
    return IOStatus::NotSupported(
        "To few zones on zoned block device (32 required)");
  }

  IOStatus ios = CheckScheduler();
  if (ios != IOStatus::OK())
    return ios;

  block_sz_ = info.pblock_size;
  zone_sz_ = info.zone_size;
  nr_zones_ = info.nr_zones;

  /* We need one open zone for meta data writes, the rest can be used for files
   */
  if (info.max_nr_active_zones == 0)
    max_nr_active_io_zones_ = info.nr_zones;
  else
    max_nr_active_io_zones_ = info.max_nr_active_zones - 1;

  if (info.max_nr_open_zones == 0)
    max_nr_open_io_zones_ = info.nr_zones;
  else
    max_nr_open_io_zones_ = info.max_nr_open_zones - 1;

  Info(logger_, "Zone block device nr zones: %u max active: %u max open: %u \n",
       info.nr_zones, info.max_nr_active_zones, info.max_nr_open_zones);

  addr_space_sz = (uint64_t)nr_zones_ * zone_sz_;

  ret = zbd_list_zones(read_f_, 0, addr_space_sz, ZBD_RO_ALL, &zone_rep,
                       &reported_zones);

  if (ret || reported_zones != nr_zones_) {
    Error(logger_, "Failed to list zones, err: %d", ret);
    return IOStatus::IOError("Failed to list zones");
  }

  while (m < ZENFS_META_ZONES && i < reported_zones) {
    struct zbd_zone *z = &zone_rep[i++];
    /* Only use sequential write required zones */
    if (zbd_zone_type(z) == ZBD_ZONE_TYPE_SWR) {
      if (!zbd_zone_offline(z)) {
        meta_zones.push_back(new Zone(this, z));
		meta_zones[meta_zones.size()-1]->plp_ = true;
      }
      m++;
    }
  }

  report_size = sizeof(struct nvme_zone_report);
  report = nvme_alloc(report_size, &huge);
  nvme_zns_mgmt_recv(write_f_, ioctl(write_f_, NVME_IOCTL_ID), 0, 0, 0, 0, report_size, report);
  nr_plp_zones_ = (uint64_t)le64_to_cpu(((struct nvme_zone_report *)report)->resv8[0]) - m;

  pg_sz[0] = ((struct nvme_zone_report *)report)->resv8[2];
  pg_sz[1] = ((struct nvme_zone_report *)report)->resv8[3];
  page_size = pg_sz[1]<<8 | pg_sz[0];
  zasl_ = page_size << ((struct nvme_zone_report *)report)->resv8[1];
  nvme_free(report);
  active_io_zones_ = 0;
  open_io_zones_ = 0;

  for (; i < reported_zones; i++) {
    struct zbd_zone *z = &zone_rep[i];
    /* Only use sequential write required zones */
    if (zbd_zone_type(z) == ZBD_ZONE_TYPE_SWR) {
      if (!zbd_zone_offline(z)) {
        Zone *newZone = new Zone(this, z);
        io_zones.push_back(newZone);
        if (zbd_zone_imp_open(z) || zbd_zone_exp_open(z) ||
            zbd_zone_closed(z)) {
          active_io_zones_++;
          if (zbd_zone_imp_open(z) || zbd_zone_exp_open(z)) {
            if (!readonly) {
              newZone->Close();
            }
          }
        }
      }
    }
  }

  free(zone_rep);
  start_time_ = time(NULL);
  BufferFlush();
  return IOStatus::OK();
}

void ZonedBlockDevice::NotifyIOZoneFull() {
  const std::lock_guard<std::mutex> lock(zone_resources_mtx_);
  active_io_zones_--;
  zone_resources_.notify_one();
}

void ZonedBlockDevice::NotifyIOZoneClosed() {
  const std::lock_guard<std::mutex> lock(zone_resources_mtx_);
  open_io_zones_--;
  zone_resources_.notify_one();
}

uint64_t ZonedBlockDevice::GetFreeSpace() {
  uint64_t free = 0;
  for (const auto z : io_zones) {
    free += z->capacity_;
  }
  return free;
}

uint64_t ZonedBlockDevice::GetUsedSpace() {
  uint64_t used = 0;
  for (const auto z : io_zones) {
    used += z->used_capacity_;
  }
  return used;
}

uint64_t ZonedBlockDevice::GetReclaimableSpace() {
  uint64_t reclaimable= 0;
  for (const auto z : io_zones) {
    if (z->IsFull())
      reclaimable += (z->max_capacity_ - z->used_capacity_);
  }
  return reclaimable;
}

void ZonedBlockDevice::LogZoneStats() {
  uint64_t used_capacity = 0;
  uint64_t reclaimable_capacity = 0;
  uint64_t reclaimables_max_capacity = 0;
  uint64_t active = 0;
  io_zones_mtx.lock();

  for (const auto z : io_zones) {
    used_capacity += z->used_capacity_;

    if (z->used_capacity_) {
      reclaimable_capacity += z->max_capacity_ - z->used_capacity_;
      reclaimables_max_capacity += z->max_capacity_;
    }

    if (!(z->IsFull() || z->IsEmpty())) active++;
  }

  if (reclaimables_max_capacity == 0) reclaimables_max_capacity = 1;

  Info(logger_,
       "[Zonestats:time(s),used_cap(MB),reclaimable_cap(MB), "
       "avg_reclaimable(%%), active(#), active_zones(#), open_zones(#)] %ld "
       "%lu %lu %lu %lu %ld %ld\n",
       time(NULL) - start_time_, used_capacity / MB, reclaimable_capacity / MB,
       100 * reclaimable_capacity / reclaimables_max_capacity, active,
       active_io_zones_.load(), open_io_zones_.load());

  io_zones_mtx.unlock();
}

void ZonedBlockDevice::LogZoneUsage() {
  for (const auto z : io_zones) {
    int64_t used = z->used_capacity_;

    if (used > 0) {
      Debug(logger_, "Zone 0x%lX used capacity: %ld bytes (%ld MB)\n",
            z->start_, used, used / MB);
    }
  }
}

ZonedBlockDevice::~ZonedBlockDevice() {
  for (const auto z : meta_zones) {
    delete z;
  }

  for (const auto z : io_zones) {
    delete z;
  }

  zbd_close(read_f_);
  zbd_close(read_direct_f_);
  zbd_close(write_f_);
}

#define LIFETIME_DIFF_NOT_GOOD (100)

unsigned int GetLifeTimeDiff(Env::WriteLifeTimeHint zone_lifetime,
                             Env::WriteLifeTimeHint file_lifetime) {
  assert(file_lifetime <= Env::WLTH_EXTREME);

  if ((file_lifetime == Env::WLTH_NOT_SET) ||
      (file_lifetime == Env::WLTH_NONE)) {
    if (file_lifetime == zone_lifetime) {
      return 0;
    } else {
      return LIFETIME_DIFF_NOT_GOOD;
    }
  }

  if (zone_lifetime > file_lifetime) return zone_lifetime - file_lifetime;

  return LIFETIME_DIFF_NOT_GOOD;
}

Zone *ZonedBlockDevice::AllocateMetaZone() {
  for (const auto z : meta_zones) {
    /* If the zone is not used, reset and use it */
    if (!z->IsUsed()) {
      if (!z->IsEmpty()) {
        if (!z->Reset().ok()) {
          Warn(logger_, "Failed resetting zone!");
          continue;
        }
      }
	  std::cout << z->start_ / GetZoneSize() << "\n";
	  //z->plp_ = true;
      return z;
    }
  }
  return nullptr;
}

void ZonedBlockDevice::ResetUnusedIOZones() {
  const std::lock_guard<std::mutex> lock(zone_resources_mtx_);
  /* Reset any unused zones */
  for (const auto z : io_zones) {
    if (!z->IsUsed() && !z->IsEmpty()) {
      if (!z->IsFull()) active_io_zones_--;
      if (!z->Reset().ok()) Warn(logger_, "Failed reseting zone");
    }
  }
}

void ZonedBlockDevice::BufferFlush() {
	__u32 nsid = ioctl(write_f_, NVME_IOCTL_ID);
	struct nvme_passthru_cmd cmd = {
		.opcode		= 0x0,
		.nsid		= nsid,
	};

	ioctl(write_f_, NVME_IOCTL_IO_CMD, &cmd);
}

Zone *ZonedBlockDevice::AllocateZone(Env::WriteLifeTimeHint file_lifetime, bool plp_flag) {
  Zone *allocated_zone = nullptr;
  Zone *finish_victim = nullptr;
  unsigned int best_diff = LIFETIME_DIFF_NOT_GOOD;
  int new_zone = 0;
  bool plp=plp_flag;
  Status s;
  //std::cout<<"plp: " << plp << std::endl;
  io_zones_mtx.lock();
  /* Make sure we are below the zone open limit */
  {
    std::unique_lock<std::mutex> lk(zone_resources_mtx_);
    zone_resources_.wait(lk, [this] {
      if (open_io_zones_.load() < max_nr_open_io_zones_) return true;
      return false;
    });
  }

  /* Reset any unused zones and finish used zones under capacity treshold*/
  for (const auto z : io_zones) {
    if (z->open_for_write_ || z->IsEmpty() || (z->IsFull() && z->IsUsed()))
      continue;

    if (!z->IsUsed()) {
      if (!z->IsFull()) active_io_zones_--;
      s = z->Reset();
      if (!s.ok()) {
        Debug(logger_, "Failed resetting zone !");
      }
      continue;
    }

    if ((z->capacity_ < (z->max_capacity_ * finish_threshold_ / 100))) {
      /* If there is less than finish_threshold_% remaining capacity in a
       * non-open-zone, finish the zone */
      s = z->Finish();
      if (!s.ok()) {
        Debug(logger_, "Failed finishing zone");
      }
      active_io_zones_--;
    }

    if (!z->IsFull()) {
      if (finish_victim == nullptr) {
        finish_victim = z;
      } else if (finish_victim->capacity_ > z->capacity_) {
        finish_victim = z;
      }
    }
  }
  if (plp == true) {
    for (const auto z : plp_zones) {
	  if ((!z->open_for_write_) && (z->used_capacity_ > 0) && !z->IsFull()) {
		allocated_zone = z;
		z->plp_ = true;
		break;
	  } else if (z->IsFull()) {
		BufferFlush();
		z->plp_ = false;
	  }
	}

	if (allocated_zone == nullptr) {
	  if (plp_zones.size() == nr_plp_zones_) {
		BufferFlush();
		for (const auto z : plp_zones) {
		  z->plp_ = false;
		}
		plp_zones.clear();
	  }
	  if (active_io_zones_.load() == max_nr_active_io_zones_ && finish_victim != nullptr) {
	    s = finish_victim->Finish();
	    if (!s.ok()) {
	      Debug(logger_, "Failed finishing zone");
	    }
	    active_io_zones_--;
	  }

	  if (active_io_zones_.load() < max_nr_active_io_zones_) {
		for (const auto z : io_zones) {
		  if ((!z->open_for_write_) && z->IsEmpty()) {
			z->lifetime_ = file_lifetime;
			z->plp_ = true;
			allocated_zone = z;
			active_io_zones_++;
			plp_zones.push_back(z);
			new_zone = 1;
			break;
		  }
		}
	  }
	}
  } else {
	  /* Try to fill an already open zone(with the best life time diff) */
	  for (const auto z : io_zones) {
		if ((!z->open_for_write_) && (z->used_capacity_ > 0) && !z->IsFull()) {
		  unsigned int diff = GetLifeTimeDiff(z->lifetime_, file_lifetime);
		  if (diff <= best_diff) {
			allocated_zone = z;
			best_diff = diff;
		  }
		}
	  }

	  /* If we did not find a good match, allocate an empty one */
	  if (best_diff >= LIFETIME_DIFF_NOT_GOOD) {
		/* If we at the active io zone limit, finish an open zone(if available) with
		 * least capacity left */
		if (active_io_zones_.load() == max_nr_active_io_zones_ &&
			finish_victim != nullptr) {
		  s = finish_victim->Finish();
		  if (!s.ok()) {
			Debug(logger_, "Failed finishing zone");
		  }
		  active_io_zones_--;
		}

		if (active_io_zones_.load() < max_nr_active_io_zones_) {
		  for (const auto z : io_zones) {
			if ((!z->open_for_write_) && z->IsEmpty()) {
			  z->lifetime_ = file_lifetime;
			  allocated_zone = z;
			  active_io_zones_++;
			  new_zone = 1;
			  break;
			}
		  }
		}
	  }
  }

  if (allocated_zone) {
    assert(!allocated_zone->open_for_write_);
    allocated_zone->open_for_write_ = true;
    open_io_zones_++;
    Debug(logger_,
          "Allocating zone(new=%d) start: 0x%lx wp: 0x%lx lt: %d file lt: %d\n",
          new_zone, allocated_zone->start_, allocated_zone->wp_,
          allocated_zone->lifetime_, file_lifetime);
  }

  io_zones_mtx.unlock();
  LogZoneStats();

  return allocated_zone;
}

std::string ZonedBlockDevice::GetFilename() { return filename_; }
uint32_t ZonedBlockDevice::GetBlockSize() { return block_sz_; }

}  // namespace ROCKSDB_NAMESPACE

#endif  // !defined(ROCKSDB_LITE) && !defined(OS_WIN)

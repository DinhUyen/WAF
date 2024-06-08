import psutil

def get_system_info():
    # Lấy thông tin CPU
    cpu_usage = psutil.cpu_percent(interval=1)
    cpu_count = psutil.cpu_count()
    
    # Lấy thông tin RAM
    virtual_mem = psutil.virtual_memory()
    ram_total = virtual_mem.total
    ram_used = virtual_mem.used
    ram_free = virtual_mem.free
    ram_percent = virtual_mem.percent
    
    # Lấy thông tin lưu trữ
    disk_usage = psutil.disk_usage('/')
    storage_total = disk_usage.total
    storage_used = disk_usage.used
    storage_free = disk_usage.free
    storage_percent = disk_usage.percent
    
    # Trả về thông tin dưới dạng JSON
    return {
        "cpu": {
            "usage_percent": cpu_usage,
            "core": cpu_count,
        },
        "ram": {
            "total": ram_total,
            "used": ram_used,
            "free": ram_free,
            "percent": ram_percent,
        },
        "storage": {
            "total": storage_total,
            "used": storage_used,
            "free": storage_free,
            "percent": storage_percent,
        }
    }
#print performance
print(get_system_info())

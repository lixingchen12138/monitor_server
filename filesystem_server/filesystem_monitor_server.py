# coding: utf-8
import os
import sys
import web
import time,datetime
import logging
import threading

from filesystem_monitor_settings import *
from Registry import Registry
from log import getlogger
from hash import *
import Queue

logger = getlogger("monitor")

web.config.debug = False

# 数据库连接
db = web.database(dbn=db_engine, host=db_server, db=db_database, 
                               user=db_username, pw=db_password)
# 全局变量存储虚拟机元数据
ret = db.select('cloud_vhost',what='uuid,name,allocation,windows,profile')
profiles = {}
for line in ret:
    profiles[line['uuid']] = (line['windows'], line['name'], line['profile'], line['allocation'])


files_list = [] # 单虚拟节点文件监控列表
files_dict = {} # 全虚拟节点文件监控字典，键为虚拟机id

registry_dict = {} # 单虚拟机注册表字典
registries_dict = {} # 全虚拟节点注册表监控字典，键为虚拟机id

# 全局变量存储文件监控列表
for (uuid,(win,name,profile,allocation)) in profiles.items():
    files_list = [] 
    ret = db.select('monitor_file_list',where="`uuid`='%s'" % uuid)
    for line in ret:
        files_list.append(line['filename'])
    files_dict[line['uuid']] = files_list



# 队列用于一生产者多消费者的情况
q = Queue.Queue(maxsize = 5)


class file_mount(threading.Thread):
    def __init__(self, uuid, allocation, win, name):
        super(file_mount, self).__init__()
        self.daemon = True
        self.uuid = uuid
        self.allocation = allocation
        self.win = win
        self.name = name

    def run(self):
        global files_dict
        global q
        cmd = 'qemu-nbd -c /dev/%s /mnt/disk/%s.qcow2' % (self.allocation,self.name)
        os.popen(cmd)
        if self.win == 0:
            cmd = 'mount /dev/%sp1 /tmp/%s' % (self.allocation, self.uuid)
            os.popen(cmd)
        else:
            cmd = 'mount /dev/%sp2 /tmp/%s' % (self.allocation, self.uuid)
            os.popen(cmd)

        monitor_file_list = files_dict[self.uuid]
        for monitor_file in monitor_file_list:
            cmd = 'cat /tmp/%s%s' % (self.uuid, monitor_file)
            try:
                res = os.popen(cmd).read()
            except:
                continue
            file_mount_change(self.uuid, monitor_file, res)

        # 注册表打印
        if q.qsize() < 5 and self.win == 1:
            ctime = time.strftime('%Y-%m-%d-%H:%M:%S', time.localtime())
            registrypath = '%s_%s_SYSTEM' % (self.uuid, ctime)
            cmd = 'cp /tmp/%s/Windows/System32/config/SYSTEM registry/' % (self.uuid)
            os.popen(cmd)
            cmd = 'mv registry/SYSTEM registry/%s' % (registrypath)
            os.popen(cmd)

            q.put(registrypath)
            logger.debug(registrypath)


        cmd = 'umount /tmp/%s' % (self.uuid)
        os.popen(cmd)
        cmd = 'qemu-nbd -d /dev/%s' % (self.allocation)
        os.popen(cmd)


class registry(threading.Thread):
    def __init__(self):
        super(registry, self).__init__()
        self.daemon = True

    def run(self):
        global q
        global registry_dict
        global registris_dict
        table = 'registry_list'
        if q.empty():
            time.sleep(2)
        else:
            registry_name = q.get()
            uuid = registry_name.split('_')[0]
            ctime = registry_name.split('_')[1]
            registry = registry_name.split('_')[2]
            md5_new = GetFileMd5('registry/%s' % registry_name)

            ret = db.select(table, where="`uuid`='%s' and `registry`='%s'" % (uuid, registry))
            if len(ret) == 0:
                registry_dict = {}
                registry_analyze('registry/%s' % registry_name)
                db.insert(table,uuid = uuid,
                        registry= registry,
                        time = ctime,
                        md5 = md5_new
                        )
            else:
                registry_dict = {}
                md5_old = list(ret)[0]['md5']
                if md5_old != md5_new:
                    registry_analyze('registry/%s' % registry_name)
                    compare(uuid, registry, registry_dict, registries_dict[uuid])

                    # 更新数据库hash值
                    db.update(table,where="`uuid`='%s' and `registry`='%s'" % (uuid, registry),
                        md5 = md5_new,
                        time = ctime
                        )
            
            registries_dict[uuid] = registry_dict
            cmd = 'rm registry/%s' % (registry_name)
            os.popen(cmd)
            logger.debug('rm success')



def registry_analyze(filename):
    if not os.path.isfile(filename):
        return
    reg = Registry.Registry(filename)
    rec(reg.root())


def rec(key):
    global registry_dict
    element_list = []
    if key.values() == []:
      registry_dict[key.path()] = []
    for element in key.values():
        element_tuple = (element.name(), element.value_type_str(), element.value())
        element_list.append(element_tuple)
    registry_dict[key.path()] = element_list
    for subkey in key.subkeys():
        rec(subkey)


def compare(uuid, registry, old_dict, new_dict):
    table = 'registry_change'
    for k,v in new_dict.items():
      if k in old_dict:
        if v != old_dict[k]:
            for element_tuple in v:
                if element_tuple not in old_dict[k]:
                    name = element_tuple[0]
                    value_type = element_tuple[1]
                    ctime = time.strftime('%Y-%m-%d-%H:%M:%S', time.localtime())
                    db.insert(table,uuid = uuid,
                            registry = registry,
                            path = k,
                            key_name = name,
                            key_type = value_type,
                            time = ctime,
                            )


def file_mount_change(uuid, monitor_file, res):
    table = 'monitor_file_change'
    ret = db.select(table, where="`uuid`='%s' and `filename`='%s' order by time desc" % (uuid, monitor_file))

    size = len(res)
    md5_new = GetMd5(res)
    ctime = time.strftime('%Y-%m-%d-%H:%M:%S', time.localtime())

    filepath = monitor_file.split('/')[-1]
    filepath = 'files/%s_%s_%s' % (uuid, ctime, filepath)

    if len(ret) == 0:
        db.insert(table, uuid = uuid,
                        filename = monitor_file,
                        size = size,
                        md5 = md5_new,
                        time = ctime)

        file_object = open(filepath, 'w')
        file_object.write(res)
        file_object.close( )

    else:
        md5_old = list(ret)[0]['md5']
        if md5_old != md5_new:
            db.insert(table, uuid = uuid,
                            filename = monitor_file,
                            size = size,
                            md5 = md5_new,
                            time = ctime)

            file_object = open(filepath, 'w')
            file_object.write(res)
            file_object.close( )
    logger.debug(ctime + ' ' + uuid+ ' ' + filepath)


class mount_thread(threading.Thread):
    def __init__(self, uuid, allocation, win, name):
        super(mount_thread, self).__init__()
        self.daemon = True
        self.uuid = uuid
        self.allocation = allocation
        self.win = win
        self.name = name
        
    def run(self):
        while True:
            t = file_mount(self.uuid, self.allocation, self.win, self.name)
            t.setDaemon(True)
            t.start()
            t.join()
            time.sleep(1)


class registry_thread(threading.Thread):
    def __init__(self):
        super(registry_thread, self).__init__()
        self.daemon = True
        
    def run(self):
        while True:
            t = registry()
            t.setDaemon(True)
            t.start()
            t.join()
            time.sleep(1)


def main():
    logger.debug("============[OK] server start up!=============")
    # 加载nbd模块
    cmd = 'modprobe nbd max_part=16'
    os.popen(cmd)
    while True:
        threads = []
        for (uuid,(win,name,profile,allocation)) in profiles.items():
            # 创建挂载目录
            mount_dir = '/tmp/%s' % (uuid)
            if not os.path.exists(mount_dir):
                cmd = 'mkdir /tmp/%s' % (uuid)
                os.popen(cmd)
            t = mount_thread(uuid, allocation, win, name)
            threads.append(t)
            if win == 1:
                t = registry_thread()
                threads.append(t)

        for t in threads:
            t.setDaemon(True)
            t.start()

        for t in threads:
            t.join()


if __name__ == '__main__':
    main()

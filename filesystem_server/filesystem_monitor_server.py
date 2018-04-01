# coding: utf-8
import os
import sys
import web
import time,datetime
import logging
import threading

from filesystem_monitor_settings import *
from log import getlogger
from hash import *


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

# 全局变量存储文件监控列表
for (uuid,(win,name,profile,allocation)) in profiles.items():
    files_list = [] 
    ret = db.select('monitor_file_list',where="`uuid`='%s'" % uuid)
    for line in ret:
        files_list.append(line['filename'])
    files_dict[line['uuid']] = files_list


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
        cmd = 'umount /tmp/%s' % (self.uuid)
        os.popen(cmd)
        cmd = 'qemu-nbd -d /dev/%s' % (self.allocation)
        os.popen(cmd)


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


def main():
    logger.debug("============[OK] server start up!=============")
    # 加载nbd模块
    cmd = 'modprobe nbd max_part=16'
    os.popen(cmd)
    while True:
        mount_threads = []
        for (uuid,(win,name,profile,allocation)) in profiles.items():
            # 创建挂载目录
            mount_dir = '/tmp/%s' % (uuid)
            if not os.path.exists(mount_dir):
                cmd = 'mkdir /tmp/%s' % (uuid)
                os.popen(cmd)
            t = file_mount(uuid, allocation, win,name)
            mount_threads.append(t)

        for t in mount_threads:
            t.setDaemon(True)
            t.start()

        for t in mount_threads:
            t.join()

	time.sleep(1)

if __name__ == '__main__':
    main()

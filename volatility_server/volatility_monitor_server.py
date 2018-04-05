# coding: utf-8
import os
import sys
import web
import time,datetime
import logging
# import threadpool
import threading
# import Queue

# from Registry import Registry
from volatility_monitor_settings import *
from log import getlogger
from hash import *

# import volatility.plugins.taskmods as taskmods
# import libapi

logger = getlogger("CloudMonitor")

web.config.debug = False

# 数据库连接
db = web.database(dbn=db_engine, host=db_server, db=db_database, 
                               user=db_username, pw=db_password)
# 全局变量存储虚拟机元数据
ret = db.select('cloud_vhost',what='uuid,name,allocation,windows,profile')
profiles = {}
for line in ret:
    profiles[line['uuid']] = (line['windows'], line['name'], line['profile'], line['allocation'])


# 注册表监控已经合并至文件系统
# registry_dict = {} # 注册表字典
# registries = {} # 全注册表字典，键为各文件名
# all_registries = {} # 全虚拟节点注册表字典，键为虚拟机id

# 队列用于一生产者多消费者的情况
# q = Queue.Queue(maxsize = 5)



class linux_ifconfig(threading.Thread):
    def __init__(self, uuid):
        super(linux_ifconfig, self).__init__()
        self.daemon = True
        self.uuid = uuid
        
    def run(self):
        (win, name, profile, allocation) = profiles[self.uuid]
        cmd = 'python vol.py -l vmi://%s --profile=%s linux_ifconfig' % (name, profile)
        res = os.popen(cmd).read()

        ctime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        table = 'linux_ifconfig'
        ifconfig_list = res.split('\n')

        for ifconfig in ifconfig_list:
            if ifconfig == '':
                continue
            ifconfiglist = ifconfig.split()
            # 去除噪音
            interface = ifconfiglist[0]
            ip = ifconfiglist[1]
            mac = ifconfiglist[2]
            promiscuous = ifconfiglist[3]
            if ip.find('.') == -1 :
                continue     
            ret = db.select(table, where="`uuid`='%s' and `Interface`='%s' and `Ip`='%s' and `Mac`='%s' and `Mode`='%s'" % (self.uuid, interface, ip, mac, promiscuous))
            if len(ret) == 0:
                db.insert(table,uuid = self.uuid,
                                Interface = interface,
                                Ip = ip,
                                Mac = mac,
                                Mode = promiscuous,
                                time = ctime)
            else:
                db.update(table, where="`uuid`='%s' and `Interface`='%s' and `Ip`='%s' and `Mac`='%s' and `Mode`='%s'" % (self.uuid, interface, ip, mac, promiscuous),
                                    time = ctime)
        # 删除之前的记录
        db.delete(table,where="`time`<>'%s'" % ctime)
        logger.debug(ctime + ' ' + self.uuid + ' ' + 'linux_ifconfig')
 

class linux_arp(threading.Thread):
    def __init__(self, uuid):
        super(linux_arp, self).__init__()
        self.daemon = True
        self.uuid = uuid

    def run(self):
        (win, name, profile, allocation) = profiles[self.uuid]
        cmd = 'python vol.py -l vmi://%s --profile=%s linux_arp' % (name, profile)
        res = os.popen(cmd).read()
        ctime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        table = 'linux_arp'
        arp_list = res.split('\n')
        for arp in arp_list:
            if arp == '':
                continue
            arplist = arp.split()
            # 去除噪音
            cIp = arplist[0]
            cIp = cIp[1:]
            cMac = arplist[3]
            cInterface = arplist[5]
            if cIp.find(':') != -1 :
                continue        
            ret = db.select(table, where="`uuid`='%s' and `Interface`='%s' and `Ip`='%s' and `Mac`='%s' " % (self.uuid, cInterface, cIp, cMac))
            if len(ret) == 0:
                db.insert(table,uuid = self.uuid,
                                Interface = cInterface,
                                Ip = cIp,
                                Mac = cMac,
                                time = ctime)
            else:
                db.update(table, where="`uuid`='%s' and `Interface`='%s' and `Ip`='%s' and `Mac`='%s'" % (self.uuid, cInterface, cIp, cMac),
                                   time = ctime)
        # 删除之前的记录
        db.delete(table,where="`time`<>'%s'" % ctime)
        logger.debug(ctime + ' ' + self.uuid + ' ' + 'linux_arp')


class pslist(threading.Thread):
    def __init__(self, uuid):
        super(pslist, self).__init__()
        self.daemon = True
        self.uuid = uuid

    def run(self):
        (win, name, profile, allocation) = profiles[self.uuid]
        cmd = './../libvmi-master/examples/process-list %s' % (name)
        res = os.popen(cmd).read()
        ctime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        if win == 0:
            table = 'linux_pslist'
        else:
            table = 'windows_pslist'
        ps_list = res.split('\n')
        for ps in ps_list:
            if ps =='':
                continue
            pslist = ps.split()
            if pslist[0] != '[':
                continue
            pid = pslist[1].rstrip(']')
            psname = pslist[2]
            offset = pslist[4].lstrip('addr:')
            offset = offset.rstrip(')')
            ret = db.select(table, where="`uuid`='%s' and `Offset`='%s' and `Name`='%s' and `Pid`='%s' " % (self.uuid, offset, psname, pid))
            if len(ret) == 0:
                db.insert(table,uuid = self.uuid,
                        Offset = offset,
                        Name = psname,
                        Pid = pid,
                        time = ctime)
            else:
                db.update(table, where="`uuid`='%s' and `Offset`='%s' and `Name`='%s' and `Pid`='%s'" % (self.uuid, offset, psname, pid),
                                    time = ctime)
        # 删除之前的记录
        db.delete(table,where="`time`<>'%s'" % ctime)
        logger.debug(ctime + ' ' + self.uuid + ' pslist')


class lsmod(threading.Thread):
    def __init__(self, uuid):
        super(lsmod, self).__init__()
        self.daemon = True
        self.uuid = uuid

    def run(self):
        (win, name, profile, allocation) = profiles[self.uuid]
        cmd = './../libvmi-master/examples/module-list %s' % (name)
        res = os.popen(cmd).read()
        ctime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        if win == 0:
            table = 'linux_lsmod'
        else:
            table = 'windows_lsmod'
        mod_list = res.split('\n')
        for mod in mod_list:
            if mod =='':
                continue
            module = mod
            ret = db.select(table, where="`uuid`='%s' and `Module`='%s' " % (self.uuid, module))
            if len(ret) == 0:
                db.insert(table,uuid = self.uuid,
                        Module = module,
                        time = ctime)
            else:
                db.update(table, where="`uuid`='%s' and `Module`='%s'" % (self.uuid, module),
                                    time = ctime)
        # 删除之前的记录
        db.delete(table,where="`time`<>'%s'" % ctime)
        logger.debug(ctime + ' ' + self.uuid + ' lsmod')


# 早期的版本，因为pyvmi的该功能延时太大而放弃
'''
class windows_vmi(threading.Thread):
    def __init__(self, uuid, command):
        super(windows_vmi, self).__init__()
        self.daemon = True
        self.uuid = uuid
        self.command = command
        
    def run(self):
        (win, name, profile, allocation) = profiles[self.uuid]
        memory = 'memory/' + name + '.dd'
        config = libapi.get_config(profile, memory)

        if self.command == 'netscan':
            data = libapi.get_json(config, taskmods.Netscan)
            ctime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            table = 'windows_netscan'
            proto_index = data['columns'].index('Proto')
            localaddress_index = data['columns'].index('LocalAddr')
            foreignaddress_index = data['columns'].index('ForeignAddr')
            state_index = data['columns'].index('State')
            pid_index = data['columns'].index('PID')
            owner_index = data['columns'].index('Owner')
            created_index = data['columns'].index('Created')
            for row in data['rows']:
                ret = db.select(table, where="`uuid`='%s' and `Proto`='%s' and `Localaddress`='%s' and `Foreignaddress`='%s' and `State`='%s' and `Pid`='%s' and `Process`='%s' and `Create_time`='%s'" % (self.uuid, row[proto_index], row[localaddress_index], row[foreignaddress_index], row[state_index], row[pid_index], row[owner_index], row[created_index]))
                if len(ret) == 0:
                    db.insert(table,uuid = self.uuid,
                                        Proto = row[proto_index],
                                        Localaddress = row[localaddress_index],
                                        Foreignaddress = row[foreignaddress_index],
                                        State = row[state_index],
                                        Pid = row[pid_index],
                                        Process = row[owner_index],
                                        Create_time = row[created_index],
                                        time = ctime)
                else:
                    db.update(table, where="`uuid`='%s' and `Proto`='%s' and `Localaddress`='%s' and `Foreignaddress`='%s' and `State`='%s' and `Pid`='%s' and `Process`='%s' and `Create_time`='%s'" % (self.uuid, row[proto_index], row[localaddress_index], row[foreignaddress_index], row[state_index], row[pid_index], row[owner_index], row[created_index]),
                                        time = ctime)
            # 删除之前的记录
            db.delete(table,where="`time`<>'%s'" % ctime)
            logger.debug(ctime + ' ' + self.uuid + ' ' + self.command)


class linux_netstat(threading.Thread):
    def __init__(self, uuid, memory_name):
        super(linux_netstat, self).__init__()
        self.daemon = True
        self.uuid = uuid
        self.memory_name = memory_name

    def run(self):
        (win, name, profile, allocation) = profiles[self.uuid]
        cmd = 'python vol.py -f memory/%s.dd --profile=%s linux_netstat -U' % (self.memory_name, profile)
        res = os.popen(cmd).read()
        ctime = self.memory_name.split('_')[1]
        table = 'linux_netstat'
        netstat_list = res.split('\n')
        for netstat in netstat_list:
            # 去除噪音
            if netstat == '':
                continue
            cProto = netstat[0:3]
            cLocaladdress = netstat[9:31]
            cForeignaddress = netstat[32:54]
            cState = netstat[55:68].strip()
            cProcess = netstat[70:].strip()
            # ret = db.select(table, where="`uuid`='%s' and `Proto`='%s' and `Localaddress`='%s' and `Foreignaddress`='%s' and `State`='%s' and `Process`='%s'" % (self.uuid, cProto, cLocaladdress, cForeignaddress, cState, cProcess))
            # if len(ret) == 0:
            db.insert(table,uuid = self.uuid,
                                Proto = cProto,
                                Localaddress = cLocaladdress,
                                Foreignaddress = cForeignaddress,
                                State = cState,
                                Process = cProcess,
                                time = ctime)
            # else:
              #   db.update(table, where="`uuid`='%s' and `Proto`='%s' and `Localaddress`='%s' and `Foreignaddress`='%s' and `State`='%s' and `Process`='%s'" % (self.uuid, cProto, cLocaladdress, cForeignaddress, cState, cProcess),
                                     # time = ctime)
        # 删除之前的记录
        # db.delete(table,where="`time`<>'%s'" % ctime)
        logger.debug(ctime + ' ' + self.uuid + ' ' + 'linux_netstat')
'''

# 文件系统监控，原本使用监控内存缓存的方法，后来被磁盘监控替代
'''
def linux_file_list(uuid, dir_path):
    global files
    global all_files
    (win, name, profile, allocation) = profiles[uuid]
    memory = 'memory/' + name + '.dd'
    config = libapi.get_config(profile, memory)

    data = libapi.get_json(config, taskmods.linux_enumerate_files)
    ctime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    inode_address_index = data['columns'].index('Inode Address')
    path_index = data['columns'].index('Path')
    args_list = [] # 用于线程池的参数集合
    files = {}
    for row in data['rows']:
        if not row[path_index].startswith(dir_path):
            continue
        if row[inode_address_index] == 0:
            continue
        files[row[path_index]] = row[inode_address_index]
        tuples = ((uuid, hex(row[inode_address_index]), row[path_index], ctime),{})
        args_list.append(tuples)
    all_files[uuid] = files
    return args_list


def linux_file_list_sql(uuid, Iaddress, filepath, ctime):
    table = 'linux_file_list'
    ret = db.select(table, where="`uuid`='%s' and `Inodeaddress`='%s' and `path`='%s'" % (uuid, Iaddress, filepath))
    if len(ret) == 0:
        db.insert(table,uuid = uuid,
                    Inodeaddress = Iaddress,
                    path = filepath,
                    time = ctime)
    else:
        db.update(table, where="`uuid`='%s' and `Inodeaddress`='%s' and `path`='%s'" % (uuid, Iaddress, filepath),
                    time = ctime)
    # 删除之前的记录
    db.delete(table,where="`time`<>'%s'" % ctime)


def linux_file_change(uuid, path, Inodeaddress):
    table = 'linux_file_change'
    (win, name, profile, allocation) = profiles[uuid]
    ctime = time.strftime('%Y-%m-%d-%H:%M:%S', time.localtime())
    filename = path.split('/')[-1]
    filename = '%s_%s_%s' % (uuid, ctime, filename)

    cmd = 'touch files/%s' % (filename)
    os.popen(cmd)

    cmd = 'python vol.py -f memory/%s.dd --profile=%s linux_find_file -i %s -O files/%s' % (name, profile, Inodeaddress, filename)
    os.popen(cmd)

    cmd = 'ls -l files/%s' % filename
    res = os.popen(cmd).read()

    c = res.split()
    size = c[4]

    ret = db.select(table, where="`uuid`='%s' and `path`='%s' order by time desc" % (uuid, path))

    md5_new = GetFileMd5('files/%s' % filename)
            
    if len(ret) == 0:
        db.insert(table,uuid = uuid,
                        path = path,
                        size = size,
                        time = ctime,
                        filename = filename,
                        md5 = md5_new
                        )
    else:
        md5_old = list(ret)[0]['md5']

        if md5_old != md5_new:
            db.insert(table,uuid = uuid,
                            path = path,
                            size = size,
                            time = ctime,
                            filename = filename,
                            md5 = md5_new
                            )
        else:
            cmd = 'rm -rf files/%s' % filename
            res = os.popen(cmd)
    logger.debug(ctime + ' '+ uuid + ' ' + path)


def windows_file_list(uuid, dir_path):
    global files
    global all_files
    (win, name, profile, allocation) = profiles[uuid]
    memory = 'memory/' + name + '.dd'
    config = libapi.get_config(profile, memory)

    data = libapi.get_json(config, taskmods.FileScan)
    ctime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    offset_index = data['columns'].index('Offset(P)')
    access_index = data['columns'].index('Access')
    name_index = data['columns'].index('Name')
    args_list = [] # 用于线程池的参数集合
    files = {}
    for row in data['rows']:
        if row[name_index].find(dir_path) == -1:
            continue
        files[row[name_index]] = (hex(row[offset_index]), row[access_index])
        tuples = ((uuid, hex(row[offset_index]), row[access_index], row[name_index], ctime),{})
        args_list.append(tuples)
    all_files[uuid] = files
    return args_list


def windows_file_list_sql(uuid, Offset, Access, Name, ctime):
    table = 'windows_file_list'
    ret = db.select(table, where="`uuid`='%s' and `Offset`='%s' and `Access`='%s' and `Name`='%s'" % (uuid, Offset, Access, Name))
    if len(ret) == 0:
        db.insert(table,uuid = uuid,
                    Offset = Offset,
                    Access = Access,
                    Name = Name,
                    time = ctime)
    else:
        db.update(table, where="`uuid`='%s' and `Offset`='%s' and `Access`='%s' and `Name`='%s'" % (uuid, Offset, Access, Name),
                    time = ctime)
    # 删除之前的记录
    db.delete(table,where="`time`<>'%s'" % ctime)


def windows_file_change(uuid, path, Offset, Access):
    table = 'windows_file_change'
    (win, name, profile, allocation) = profiles[uuid]
    ctime = time.strftime('%Y-%m-%d-%H:%M:%S', time.localtime())
    filename = path.split('\\')[-1]
    filename = '%s_%s_%s' % (uuid, ctime, filename)
    cmd = 'python vol.py -f memory/%s.dd --profile=%s dumpfiles -Q %s -D files/ --filter=DataSectionObject' % (name, profile, Offset)
    os.popen(cmd)
    # 若路径不存在，则返回，dump文件失败
    if os.path.exists('files/' + name + '_' + path) == False:
        return

    path = path.replace('\\', '\\\\')
    cmd = 'mv files/%s_%s files/%s' % (name, path, filename)
    os.popen(cmd)

    cmd = 'ls -l files/%s' % filename
    res = os.popen(cmd).read()
    
    access = Access

    c = res.split()
    size = c[4]

    path = path.replace('\\\\', '\\')
    ret = db.select(table, where="`uuid`='%s' and `Offset`='%s' order by time desc" % (uuid, Offset))

    md5_new = GetFileMd5('files/%s' % filename)
            
    if len(ret) == 0:
        db.insert(table,uuid = uuid,
                        Offset = Offset,
                        path = path,
                        size = size,
                        access = access,
                        time = ctime,
                        filename = filename,
                        md5 = md5_new
                        )
    else:
        md5_old = list(ret)[0]['md5']
        
        if md5_old != md5_new:
            db.insert(table,uuid = uuid,
                            Offset = Offset,
                            path = path,
                            size = size,
                            access = access,
                            time = ctime,
                            filename = filename,
                            md5 = md5_new
                            )
        else:
            cmd = 'rm -rf files/%s' % filename
            res = os.popen(cmd)
    logger.debug(ctime + ' ' + uuid+ ' ' + path)

'''

# 内存打印方法，因为过程会暂停虚拟机而放弃
'''
class dump_memory(threading.Thread):
    def __init__(self, uuid, memory_name):
        super(dump_memory, self).__init__()
        self.daemon = True
        self.uuid = uuid
        self.memory_name = memory_name

    def run(self):
        (win, name, profile, allocation) = profiles[self.uuid]
        cmd = 'virsh dump %s memory/%s.dd --memory-only --live' % (name, self.memory_name)
        os.popen(cmd)
'''

# 注册表监控方法，已经全部移动到filesystem_monitor_server
'''
class registry(threading.Thread):
    def __init__(self, uuid):
        super(registry, self).__init__()
        self.daemon = True
        self.uuid = uuid

    def run(self):
        global registries
        global all_registries
        global registry_dict
        table = 'registry_list'
        (win, name, profile, allocation) = profiles[self.uuid]
        ctime = time.strftime('%Y-%m-%d-%H:%M:%S', time.localtime())
        cmd = 'python vol.py -f memory/%s.dd --profile=%s dumpregistry -D registry/' % (name, profile)
        res = os.popen(cmd).read()

        registry_list = res.split('\n')
        for registry in registry_list:
            if registry != '' and registry.startswith('registry') == True:
                registry_name = name + '_' + registry
                md5_new = GetFileMd5('registry/%s' % registry_name)

                ret = db.select(table, where="`uuid`='%s' and `registry`='%s'" % (self.uuid, registry))
                if len(ret) == 0:
                    registry_dict = {}
                    # 解析失败则继续下一个注册表的解析
                    try:
                        registry_analyze('registry/%s' % registry_name)
                    except Exception,e: 
                        continue
                    registries[registry] = registry_dict
                    db.insert(table,uuid = self.uuid,
                            registry= registry,
                            time = ctime,
                            md5 = md5_new
                            )
                elif all_registries.has_key(self.uuid) == False:
                    registry_dict = {}
                    # 解析失败则继续下一个注册表的解析
                    try:
                        registry_analyze('registry/%s' % registry_name)
                    except Exception,e: 
                        continue
                    registries[registry] = registry_dict
                elif all_registries.has_key(self.uuid) == True:
                    md5_old = list(ret)[0]['md5']
                    if md5_old == md5_new:
                        continue
                    else:
                        registry_dict = {}
                        # 解析失败则继续下一个注册表的解析
                        try:
                            registry_analyze('registry/%s' % registry_name)
                        except Exception,e: 
                            continue
                        compare(self.uuid, registry, registry_dict, all_registries[self.uuid][registry])
                        # 更新变量
                        registries[registry] = registry_dict
                        # 更新数据库hash值
                        db.update(table,where="`uuid`='%s' and `registry`='%s'" % (self.uuid, registry),
                            md5 = md5_new,
                            time = ctime
                            )

        all_registries[self.uuid] = registries
        logger.debug(ctime + ' ' + self.uuid + ' ' + 'registry')


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


'''
class arp_thread(threading.Thread):
    def __init__(self, uuid):
        super(arp_thread, self).__init__()
        self.daemon = True
        self.uuid = uuid

    def run(self):
        while True:
            t = linux_arp(self.uuid)
            t.setDaemon(True)
            t.start()
            t.join()
            time.sleep(1)


class ifconfig_thread(threading.Thread):
    def __init__(self, uuid):
        super(ifconfig_thread, self).__init__()
        self.daemon = True
        self.uuid = uuid
        
    def run(self):
        while True:
            t = linux_ifconfig(self.uuid)
            t.setDaemon(True)
            t.start()
            t.join()
            time.sleep(1)


class pslist_thread(threading.Thread):
    def __init__(self, uuid):
        super(pslist_thread, self).__init__()
        self.daemon = True
        self.uuid = uuid

    def run(self):
        while(True):
            t = pslist(self.uuid)
            t.setDaemon(True)
            t.start()
            t.join()
            time.sleep(1)


class lsmod_thread(threading.Thread):
    def __init__(self, uuid):
        super(lsmod_thread, self).__init__()
        self.daemon = True
        self.uuid = uuid

    def run(self):
        while(True):
            t = lsmod(self.uuid)
            t.setDaemon(True)
            t.start()
            t.join()
            time.sleep(1)


def main():
    logger.debug("============[OK] server start up!=============")
    threads = []
    for (uuid,(win,name,profile,allocation)) in profiles.items():
        if win == 0:
            t = arp_thread(uuid)
            threads.append(t)
            t = ifconfig_thread(uuid)
            threads.append(t)
        t = pslist_thread(uuid)
        threads.append(t)
        t = lsmod_thread(uuid)
        threads.append(t)

    for t in threads:
        t.setDaemon(True)
        t.start()


    for t in threads:
        t.join()



    '''
        # 内存文件监控，目前由挂载文件监控替代
        # 定义线程池
        # 线程池1负责数据库的并行写入
        # 线程池2负责文件变化的并行监测
        pool_sql = threadpool.ThreadPool(10)
        pool_file = threadpool.ThreadPool(10)
        for (uuid,(win,name,profile,allocation)) in profiles.items():
            args_list = []
            if win == 0:
                # linux 文件列表
                file_args_list = linux_file_list(uuid, '/home/lxc/')
                requests = threadpool.makeRequests(linux_file_list_sql, file_args_list)
                for req in requests:
                    pool_sql.putRequest(req)
                pool_sql.wait()
                # linux 文件变化
                for key, value in all_files[uuid].items():
                    tuples = ((uuid, key, value), {})
                    args_list.append(tuples)
                requests = threadpool.makeRequests(linux_file_change, args_list)
                for req in requests:
                    pool_file.putRequest(req)
                pool_file.wait()
            if win == 1:
                # windows 文件列表
                file_args_list = windows_file_list(uuid, '\windows\Desktop\\')
                requests = threadpool.makeRequests(windows_file_list_sql, file_args_list)
                for req in requests:
                    pool_sql.putRequest(req)
                pool_sql.wait()
                # windows文件变化
                for key, value in all_files[uuid].items():
                    tuples = ((uuid, key, value[0], value[1]), {})
                    args_list.append(tuples)
                requests = threadpool.makeRequests(windows_file_change, args_list)
                for req in requests:
                    pool_file.putRequest(req)
                pool_file.wait()
    '''

if __name__ == '__main__':
    main()

# coding: utf-8
import hashlib
import os
import sys


def GetFileMd5(filename):
    if not os.path.isfile(filename):
        return
    myhash = hashlib.md5()
    f = file(filename,'rb')
    while True:
        b = f.read(8096)
        if not b :
            break
        myhash.update(b)
    f.close()
    return myhash.hexdigest()

def GetMd5(string):
    myhash = hashlib.md5()
    myhash.update(string)
    return myhash.hexdigest()
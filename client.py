#!/usr/bin/env python

"""
Deuce Client Sample

:author:  Xuan Yu
:date:  2014/01/22
"""

from __future__ import print_function

import json
import sys
import requests
import subprocess
import commands
import os
import io
import hashlib
from rabin import RabinFingerprint


# -*- coding: utf-8 -*-
#import sqlite3
#import subprocess
#from collections import namedtuple
#def from_utf8(data):
#    """
#    Short-hand function decoding utf8-encoded strings.
#    """
#    return data.decode('utf8')

      
file_url = ''
verify_list = ''

'''
class Configuration:
'''
class Configuration:
  def __init__(self, configuration_file_name):
    if not os.path.exists(configuration_file_name):
      raise IOError('File {} does not exist.'.format(configuration_file_name))
    with open(configuration_file_name) as file_data: 
      self.config = json.load(file_data)

  def GetApiHost(self):
    return  self.config["ApiHostName"]

  def GetVaultId(self):
    return  self.config["VaultId"]

class BlockIds:
  def __init__(self):
    self.blockIds = list()
  
  ''' 
    Read Block ids from string to a list.
  '''
  def Read(self, stringdata, removes, splitter):
    for i in range(0, len(removes)):
      stringdata = stringdata.replace(removes[i], "")
    if stringdata:
      self.blockIds = stringdata.split(splitter)
      



'''
class Blocks:
  A list of blocks. 
'''
class Blocks:
  def __init__(self):
    self.blocks = list()

  def Insert(self, blockId, blocksize, fileoffset):
    self.blocks.append((blockId, blocksize, fileoffset))

  def DecodeBlocks(self):
    names = ["id", "size", "offset"]
    data = {'blocks':[]}
    for block in self.blocks:
      data['blocks'].append(dict(zip(names, block)))

    self.DumpId() #For demo verification.

    return json.dumps(data)

  def FindBlock(self, blockId):
    block = [v for v in self.blocks if v[0] == blockId]
    return block

  #YUDEBUG
  def Dump(self):
    for block in self.blocks:
      print (block[0], repr(block[1]).rjust(10), repr(block[2]).rjust(12))
      
  #YUDEBUG
  def DumpId(self):
    global verify_list
    verify_list = ' /tmp/block_storage/' + ' /tmp/block_storage/'.join([block[0] for block in self.blocks])


backup_blocks = Blocks()  

class FileBlocks:
  global backup_blocks
  global file_url
  
  def __init__(self, file_name):
    if not os.path.exists(file_name):
      raise IOError('File {} does not exist.'.format(file_name))
    self.fd = io.open(file_name, 'rb', buffering=4096*4)
    global config
    self.config = config
    file_url = ''

  def __del__(self):
    try:
      self.fd.close()
    except Exception, e:
      pass


  '''
    Run 
  '''
  def Run(self):
    # Create blocks and Calculate hashes
    self.RabinFile()
    # Upload file manifest
    missing_blocks = self.UploadFileManifest()
    # Upload blocks
    self.UploadBlocks(missing_blocks)
    # @TODO!! Finalize File
    #missing_blocks = self.FinalizeFile()


  '''
    RabinFile 
  '''
  def RabinFile(self):
    print('\n\tDivide File to Blocks...')
    total_bytes_in_blocks = 0
    min_block_size = 50 * 1024
    fingerprint = RabinFingerprint(0x39392FAAAAAAAE)
    block_size = 0
    sha1 = hashlib.sha1()

    while True:
        buff = self.fd.read(4096)
        bytes_read = len(buff)

        if bytes_read == 0:
            if block_size > 0:
                # Finish off the last part of the file as a block
                backup_blocks.Insert(sha1.hexdigest(), 
                      block_size, total_bytes_in_blocks)
                total_bytes_in_blocks += block_size
            break

        for i in range(0, bytes_read):
            fp = fingerprint.update(buff[i])
            sha1.update(buff[i:i + 1])

            block_size += 1

            if fp == 0x04 and block_size > min_block_size:
                backup_blocks.Insert(sha1.hexdigest(), 
                      block_size, total_bytes_in_blocks)
                total_bytes_in_blocks += block_size

                # Reset everything
                block_size = 0
                sha1 = hashlib.sha1()
                fingerprint.clear()


  '''
    UploadFileManifest
  '''
  def UploadFileManifest(self):
    print('\n\tUpload File Manifest...')
    global file_url
    if file_url == '':
      # Create a file
      url = self.config.GetApiHost() + '/v1.0/' + self.config.GetVaultId() + '/files'
      response = requests.post(url)
      file_url = response.headers['location']

    #Submit the assigned blocks.
    hdrs = {'content-type': 'application/x-deuce-block-list'}
    params = {}
    data = backup_blocks.DecodeBlocks()
    response = requests.post(file_url, params=params, data=data, headers=hdrs)

    print ("\t\tResp.text (Server needs these blocks) : " +response.text)

    missing_blocks = BlockIds()
    missing_blocks.Read(response.text, "[]\" ", ',')
    return missing_blocks


  '''
    UploadBlock 
  '''
  def UploadBlocks(self, missing_blocks):
    print('\n\tUpload Blocks...')
    global backup_blocks
    blocks_url = self.config.GetApiHost() + '/v1.0/' + self.config.GetVaultId() + '/blocks'  
    hdrs = {'content-type': 'application/octet-stream'}
    params = {}
    for block_id in missing_blocks.blockIds:
      url = blocks_url + '/' + block_id
      block = backup_blocks.FindBlock(block_id)
      block = block[0]
      hdrs['content-length'] = block[1]
      if self.fd.tell() != block[2]:
        self.fd.seek(block[2], os.SEEK_SET)
      data = self.fd.read(block[1])
      response = requests.put(url, params=params, data=data, headers=hdrs)
      print ("\tBlock : " + block_id)
      print ("\t\tResp : %d" %response.status_code)




class Restore:
  global file_url

  def __init__(self, restore_filename):
    self.fd = io.open(restore_filename, 'wb+')


  def Run(self):
    global file_url
    print ("\tTo Download the file from : "+file_url)
    response = requests.get(file_url, stream=True)
    if response.status_code == 200:
      for chunk in response.iter_content():
        self.fd.write(chunk)
    return True


  def __del__(self):
    try:
      self.fd.close()
    except Exception, e:
      pass


"""
Execute the program.
"""
def main():
  if len(sys.argv) < 3:
    print('Usage: {}   Configuration_File_Name_json Backup_File_Name'.format(sys.argv[0]))
    print('   Configuration_File_Name_json ... Configuration file name in json, e.g., bootstrap.json')
    print('   Backup_File_Name ... The file to backup.')
    quit()

  try:
    # Load Configuration.
    global config
    config = Configuration(sys.argv[1])

    # Back up the File.
    print('Backup File '+sys.argv[2])
    backup = FileBlocks(sys.argv[2])
    backup.Run()
    
    # Demo verification.
    cmd = 'cat' + verify_list + '> ./file_from_storage'
    print ("\nVerify the uploaded file.")
    print ("\tcmd: "+cmd)
    retval = commands.getoutput(cmd)
    cmd = 'diff ./file_from_storage '+sys.argv[2]
    print ("\n\tcmd: "+cmd)
    retval = commands.getoutput(cmd)
    print ('\t\tcmd returns : ' + retval) 
    

    # Restorethe File.
    print ('\nRestore the file to : '+ sys.argv[2]+".restore")
    restore = Restore(sys.argv[2]+".restore")
    restore.Run()

    # Demo verification.
    cmd = 'diff '+sys.argv[2] + ' ' + sys.argv[2]+'.restore'
    print ("\n\tcmd: "+cmd)
    retval = commands.getoutput(cmd)
    print ('\t\tcmd returns : ' + retval) 
    

    print ('[DONE]')
  except Exception, e:
    print ("Exception: ", e)
  

if __name__ == '__main__':
  main()


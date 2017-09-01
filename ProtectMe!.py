import subprocess
import optparse
import magic
import os
import logging
import binascii
import md5
import linecache
import sqlite3
import psutil
import signal
import time
import re
import pwnlib.constants
from capstone import *
from capstone.x86_const import *
import pwnlib.gdb
import pwnlib.elf.elf
import sched
from logging import Logger as logger
import sys
import zipfile
import itertools
#from docx import Document
#from docx.shared import Inches
import socket
import tempfile

HOST = '127.0.0.1'
PORT = 80
PROGRAM = raw_input('Program to be analyzed')

class ProgramScanned:
    FILE = 'virus_signature.txt'
    def __init__(self):
            logger = logging.getLogger('antivirus')
            hdlr = logging.FileHandler('antivirus.log')
            formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
            hdlr.setFormatter(formatter)
            logger.addHandler(hdlr) 
            logger.setLevel(logging.WARNING)
            logger.setLevel(logging.INFO)
            try:
                self.fisier = raw_input('What file do you want to scan>?')
                if  (magic.from_file(self.fisier)[0:3] in 'PE32') or (magic.from_file(self.fisier)[0:3] in 'ELF'):
                    if os.path.getsize(self.fisier) > 524288000:
                        logger.warning('file bigger than 500 mb')
                    else:
                        conn = sqlite3.connect('/home/cyberghostkid/Desktop/antivirus/hash_signature.db')
                        c = conn.cursor()
                        c.fetchone()
                        try:
                            fisiez = open('virus_signature.txt','r')
                            #if md5.new(self.fisier).hexdigest() in c.execute('SELECT * FROM hashsignature where hash=?',(str(md5.new(self.fisier).hexdigest()), )):
                            if md5.new(self.fisier).hexdigest() in fisiez.read():
                                print 'we may have found a possible thread!'
                                logger.critical('Possible thread found')
                            else:
                                print "sorry we weren't' able to see if it was a thread,so we say it's safe "
                                fisiez = open('virus_signature.txt','w+r')
                                c.executemany('INSERT INTO hashsignature(hash) VALUES (?)',str(md5.new(self.fisier).hexdigest()))
                                conn.commit()
                                fisiez.write(str(md5.new(self.fisier).hexdigest()))
                                fisiez.seek(0)
                                fisiez.close()
                                logger.info('updated database after scanning {} programms name'.format(self.fisier))
                        except NameError:
                            print 'error 404 file not found'
                            logger.warning('app not found')
                else:
                    pass
                    print 'file not an executable'
                    logger.warning('file not an executable')
            except IOError:
                logger.error('IOError: [Errno 9] Bad file descriptor')
                
    '''Start another process of antivirus'''
    def analyze(self):
        a = True
        self.fisier = raw_input('what program do you want to break and see its content?')
        filez = open(self.fisier,'r')
        counter = 0
        lisz = []
        a = True
        for i in filez:
            lisz.append(i)
        for i in lisz:
            while a:
                s = re.match(r'(.*) virus (.*?)',i,re.M)
                if s:
                    print counter
                else:
                    a = False
                    counter+=1
                    print counter
                
    '''Start looking for CPU,NIC,GPU'''
    def look_up(self):
        self.x = raw_input()
        while True:
            '''CPU INFO'''
            #print psutil.cpu_times()
            #print psutil.cpu_percent(percpu=True)
            #print psutil.cpu_freq()
            #print psutil.cpu_count(logical=False)
            #print psutil.cpu_stats()
            #if mem taken by process bigger than > size kill 
            
            '''memory info'''
            #process = psutil.Process(self.x)
            #print process.memory_percent()
            #print psutil.virtual_memory()
            #print psutil.swap_memory()
            x = psutil.pids()
            for i in x:
                p = psutil.Process(i)
                print p.name()
                #print p.parent()
                print '\n'
                print '\n'
                #print p.children()
            
            '''NIC info'''
            #print psutil.net_io_counters(pernic=True)
            #print psutil.net_connections()
            #print psutil.net_if_addrs()
            '''PID INFO ALSO HERE WILL BE HAPPENING SOME MAGIC'''
            #print psutil.pids():
                
                
            time.sleep(3)
        
    def companion_infect(self):
        for dirname, dirnames, filenames in os.walk('.'):
            print filenames
        for i in filenames:
            if ('.COM' in i):
                os.system("rm -rf *.COM")
                
    def disassemble_programm(self):
        self.program = raw_input('program to dis')
        hex_array = "hexdump -x {} | cut -f2- -d' ' ".format(self.program)
        result = subprocess.check_output(hex_array, shell=True)
        new_result = re.split('\s+',result)
        new_string = ""
        #e = pwnlib.elf.elf.ELF('a.out')
        #print pwnlib.elf.elf.disasm(file('a.out','rb').read())
        for i in new_result:
            new_string+='b'+'\\x'+i[0:2]+'\\x'+i[2:]
        new_string = new_string[:len(new_string)-4]
        try:
            if sys.maxsize > 2 ** 32:
                if sys.byteorder == 'little':
                    md = Cs(CS_ARCH_X86, CS_MODE_64+CS_MODE_LITTLE_ENDIAN)
                    md.detail = True
                elif sys.byteorder == 'big':
                    md = Cs(CS_ARCH_X86, CS_MODE_64+CS_MODE_BIG_ENDIAN)
                    md.detail = True
                else:
                    print "error detecting the architecture of your PC.\
                    Please talk to your sysadmin"
                    logger.error('cant detect endian architecture')
            else:
                if sys.byteorder == 'little':
                    md = Cs(CS_ARCH_X86, CS_MODE_32+CS_MODE_LITTLE_ENDIAN)
                    md.detail = True
                elif sys.byteorder == 'big':
                    md = Cs(CS_ARCH_X86, CS_MODE_32+CS_MODE_BIG_ENDIAN)
                    md.detail = True
                else:
                    print "error detecting the architecture of your PC.\
                    Please talk to your sysadmin"
                    logger.error('cant detect endian architecture')
                for i in md.disasm(new_string,0x080483db):
                      print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        except ImportError:
            print "We are sorry for the inconvenience,you may have\
            not installed all dependencies!"
            logger.error('cant import capstone,unsatisfied dependencies')
            
    def heuritics():
        pass
    
    def recive_md5(self):
        try:
            self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            self.s.connect((HOST,PORT))
            while 1:
                self.s.sendall('Hi there, is there any update?')
                self.data = self.s.recv(3072)
                if not self.data:
                    self.s.close()
                    sys.exit()
                print self.data
        except socket.error:
            print "sorry no data send!"
        except socket.gaierror:
            print "sorry host unreachable!"

    
    def parse_doc_windows(self):
        k = []
        self.input = raw_input('windows document to be scanned')
        try:
            docx = zipfile.ZipFile('{}'.format(self.input))
            for i in docx.infolist():
                k.append(docx.read(i))
        except IOError:
            print 'error'
        pre,ext = os.path.splitext(self.input)
        os.rename(self.input,pre+'.zip')
        tmp_dir = tempfile.mkdtemp()
        print('created temporary directory', tmp_dir)
        zip_ref = zipfile.ZipFile(os.getcwd(), 'r')
        zip_ref.extractall(tmp_dir)
        tmp_dir.close()
        
    def final_raport(self):
        self.input = ""
        raport = Document()
        document.add_heading('Final diagnose based on out analysis for your document:{}'.format(self.input), 0)
        p = document.add_paragraph()

        
        
def main():
    x = ProgramScanned()
    #x.companion_infect()
    #x.analyze()
    #x.disassemble_programm()
    #x.look_up()
    x.parse_doc_windows()
    #x.recive_md5()
main()









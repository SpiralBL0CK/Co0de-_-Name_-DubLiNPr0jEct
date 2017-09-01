import socket
import optparse
import sqlite3
import re
import md5
import random
parser = optparse.OptionParser()
parser.add_option("-v", action="store_true", dest="update")
parser.add_option("-q", action="store_false", dest="update")
(data,args) = parser.parse_args()
update = data.update
HOST = '127.0.0.1'
PORT = 80
def update():
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind((HOST,PORT))
    s.listen(1)
    x = True
    try:
        while 1:
            final_string = []
            conn, addr = s.accept()
            data = conn.recv(3072)
            print data
            
            if not update:
                conn.sendall('no')
            else:
                print 'conected host: {} with ip: {}'.format(socket.gethostname(),socket.gethostbyaddr(socket.gethostname())[2])
                conn.sendall('yes')
                db_connect = sqlite3.connect('/home/cyberghostkid/Desktop/antivirus/hash_signature.db')
                c = db_connect.cursor()
                c.fetchone()
                try:
                    for i in db_connect.execute('SELECT * FROM hashsignature'):
                        for z in re.sub('[^\w]',' ',str(i).replace('u', ' ')).strip():
                            final_string.append(z)
                        
                    conn.sendall(str(final_string[::2]))
                    
                except sqlite3.Error:
                    print 'error occured when oppening database'
    
    except socket.error:
        print "cant connect to clien!"
        
def compare():
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind((HOST,PORT))
    s.listen(1)
    conn, addr = s.accept()
    data = conn.recv(3072)
    try:
        db_connect = sqlite3.connect('/home/cyberghostkid/Desktop/antivirus/hash_signature.db')
        c = db_connect.cursor()
        c.fetchone()
        for i in c.execute('SELECT * FROM hashsignature'):
            if str(md5.new('ac').hexdigest()) in re.sub('[^\w]',' ',str(i).replace('u', ' ')).strip():
                conn.sendall('malicous file found,what would you wish to do with it?')
    except sqlite3.Error:
        print 'error occured when oppening database'

def encode():
    '''
        Generate public key
    '''
    max_nr =10
    first_number = []
    second_number = []
    for i in range(1024):
        first_number.append(random.choice(range(max_nr)))
    first_number = re.sub('[^\w]','',str(first_number))
    
    for z in range(1024):
        second_number.append(random.choice(range(max_nr)))
    second_number = re.sub('[^\w]','',str(second_number))
    
    n = int(first_number)*int(second_number)
    phi = int((int(first_number)-1)*(int(second_number)-1))
    e = 3
    #d = 
encode()
    
        

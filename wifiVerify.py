#!/usr/bin/env python
# $Author: eric.zhong $
# $Id: wifiVerify.py zhong@hp.com $
#


import re
import os
import time
import argparse
import sys
import datetime
import subprocess
import itertools
import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
from compiler.ast import flatten

#import pyshark
# wlan.sa Source address: HonHaiPr_55:fe:c3 (08:3e:8e:55:fe:c3)
# BSS Id: 96:57:a5:09:97:ac (96:57:a5:09:97:ac)


# The following code includes a class that manages command line functionality
description =   "wifiVerify.py : This program performs filters on pcap captures and parses information to summarize " \
                "two network devices connectivity into consise summary of connects and disconnects with optional DHCP highlighting. " \
                "The script verifies the IEEE 802.11 open authentication and associastion managment frames. " 
epilog =    "Author: Eric Zhong; Email: zhong@hp.com; " \
            "Last Updated: July 14, 2017"

class wifiVerifyparseCmd(object):
    def __init__(self):
        
        self.parser = argparse.ArgumentParser(description=description,epilog=epilog,prefix_chars="-/")    

        self.parser.add_argument("-d","-D","/d","/D","--dhcp", action="store_true", dest="dhcp", help="show the analysis for dhcp packets")
        self.parser.add_argument("-c","-C","/c","/C","--client",dest="client",required=True ,help="client mac address: device which is connecting to the accesspoint")
        self.parser.add_argument("-a","-A","/a","/A","--accesspoint",dest="ap",required=True ,help="accesspoint mac address: device acknowledging connection")
        self.parser.add_argument("-p","-P","/p","/P","--filename",dest="path",help="System Path to pcap file captured from client device")
        self.parser.add_argument("-v","-V","/v","/V","--verbose",dest="verbose",action="store_true",help="print out lines that are begin searched")


        self._args = self.parser.parse_args()
        new = WifiConnparse(self._args.client, self._args.ap, self._args.path, self._args.dhcp, self._args.verbose )
    
        
class WifiConnparse():
    def __init__(self, client, ap, path, dhcp, verbose):
        self.client = client
        self.ap = ap
        self.verbose = verbose
        self.path = path
        self.dhcp = dhcp
        if sys.platform.startswith('win'):
            self.tshark = "C:\\Program Files\\Wireshark\\tshark.exe"
            self.mergcap = "C:\\Program Files\\Wireshark\\mergecap.exe"
        elif sys.platform.startswith('linux') or sys.platform.startswith('cygwin'):
            # this excludes your current terminal "/dev/tty"
            ports = glob.glob('/dev/tty[A-Za-z]*')
        elif sys.platform.startswith('darwin'):
            self.tshark = "/Applications/Wireshark.app/Contents/MacOS/tshark"
            self.mergcap = "/Applications/Wireshark.app/Contents/MacOS/mergecap"
        else:
            raise EnvironmentError('Unsupported platform')
        
        if self.path is not None:
            if '.txt' in self.path:
                self.pcap_summary(self.path)
            else:
                if self.checkMACaddr(self.ap) and self.checkMACaddr(self.client):
                    self.filterWificonn(self.path)
                    self.filterManagement(self.path)
                    self.filterControl(self.path)
                    self.filterData(self.path)
                    self.merge([self.connfn, self.mgtsubfn,self.ctrlfn,self.datafn])
                    self.convertPcap2Txt(self.mergedfn)
                    self.processfile()
                    
                else:
                    print 'invalid mac address'

      
    def convertPcap2Txt(self, fn):
        #self.changeWiresharkSettings()
        self.textfile = fn.split('.pcap')[0]+'_text.txt'
        tsharkCall = ["tshark", "-r", fn,"-t", "r"]
        if os.path.isfile(self.textfile):
            print 'Text File from PCAP file already exists!'
            pass
        else:
            tsharkOut  = open(self.textfile, "wb")
            tsharkProc = subprocess.Popen(tsharkCall,
                                stdout=tsharkOut, 
                                executable=self.tshark)
            print 'Starting to process pcap to text file:  ' + (time.strftime("%I:%M:%S"))
            print '<Hit Enter Key if Time stops moving>'
            while tsharkProc.poll() is None:
                print 'Processing pcap to text file:  ' + (time.strftime("%I:%M:%S")) + '\r',
                time.sleep(2)
            print 'Finished process pcap to text file:  ' + (time.strftime("%I:%M:%S"))
            time.sleep(3)

    def checkMACaddr(self, mac):
        chk = re.search("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$",mac)
        if chk:
            return True
        else:
            return False
            
    def filterWificonn(self, file):
        mgmt_sub = ("((wlan.fc.type eq 0 && wlan.bssid eq "+ self.ap +") && !wlan.fc.type_subtype == 8"
        "&& !wlan.fc.type_subtype == 4 && !wlan.fc.type_subtype == 5 && !wlan.fc.type_subtype == 13)")
        #managment frames minus beacons, probe req and res framaes and action frames
        nullFrames = "(((wlan.fc.type eq 2 && (wlan.ra eq "+ self.ap +" || wlan.bssid eq " + self.ap + ")) && wlan.fc.type_subtype ==36))"
        self.connfn = file.split('.pcap')[0]+'_conn.pcap'
        tsharkCall = ["tshark", "-r", file,"-Y", mgmt_sub + '||' + nullFrames, "-w", self.connfn]
        if os.path.isfile(self.connfn):
            print 'PCAP file already exists!'
            pass
        else:
            self.startfilter(tsharkCall)
    
    def filterManagement(self, file):
        mgmt_sub = ("(wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 4 || wlan.fc.type_subtype == 5 || wlan.fc.type_subtype == 13) && wlan.bssid eq "+ self.ap)        
        self.mgtsubfn = file.split('.pcap')[0]+'_mgntsub.pcap'
        tsharkCall = ["tshark", "-r", file,"-Y", mgmt_sub, "-w", self.mgtsubfn]
        if os.path.isfile(self.mgtsubfn):
            print 'PCAP file already exists!'
            pass
        else:
            self.startfilter(tsharkCall)
    def filterData(self, file):
        data = "wlan.fc.type == 2 && wlan.bssid eq "+ self.ap
        self.datafn = file.split('.pcap')[0]+'_data.pcap'
        tsharkCall = ["tshark", "-r", file,"-Y", data, "-w", self.datafn]
        if os.path.isfile(self.datafn):
            print 'PCAP file already exists!'
            pass
        else:
            self.startfilter(tsharkCall)
            
    def filterControl(self, file):
        ctrl = ("wlan.fc.type == 1 && (wlan.ra eq "+ self.ap +" || wlan.ra eq "+ self.client+ ")")
        self.ctrlfn = file.split('.pcap')[0]+'_ctrl.pcap'        
        tsharkCall = ["tshark", "-r", file,"-Y", ctrl, "-w", self.ctrlfn]
        if os.path.isfile(self.ctrlfn):
            print 'PCAP file already exists!'
            pass
        else:
            self.startfilter(tsharkCall)
            
    def startfilter(self, args):
        tsharkProc = subprocess.Popen(args,
                                stdout=subprocess.PIPE, 
                                executable=self.tshark)
        print 'Starting to process pcap:  ' + (time.strftime("%I:%M:%S"))
        print '<Hit Enter Key if Time stops moving>'
        while tsharkProc.poll() is None:
            print 'filtering pcap:  ' + (time.strftime("%I:%M:%S")) + '\r',
            time.sleep(2)
        print 'Finished:  ' + (time.strftime("%I:%M:%S"))
        
    def merge(self, files):
        self.mergedfn = self.path.split('.pcap')[0]+'_merged.pcap' 
        args = ["mergecap", "-w", self.mergedfn]
        for i in files:
            args.append(i)
        if os.path.isfile(self.mergedfn):
            print 'Already merged!'
            pass
        else:
            tsharkProc = subprocess.Popen(args,
                                stdout=subprocess.PIPE, 
                                executable=self.mergcap)
    def processfile(self):
        def summary():
            print 'average beacons: ', np.mean(cntbeac)
            print 'skipped beacons: ', len(beacon_errors)
            print 'authentication seq1'
            print auth1
            print 'authentication seq2'
            print auth2
            print 'association request'
            print auth1
            print 'association response'
            print auth2
            print 'disassociation'
            for key, value in sorted(disaRe.iteritems(), key=lambda (k,v): (v,k)):
                print "%s: %s" % (key, value)
            print 'deauthentication'
            for key, value in sorted(deauth.iteritems(), key=lambda (k,v): (v,k)):
                print "%s: %s" % (key, value)
        beacons = []
        beacons_chk = -1
        beacon_errors = {}
        auth1 = []
        auth2 = []
        authRe = []
        asso1 = []
        asso2 = []
        assoRe = []
        disa = {}        
        disaRe = {}
        deauth = {}
        deauthRe = {}
        powersave = []
        with open(self.textfile) as f:
            for line in f:
                if 'Beacon frame' in line:
                    seg = line.split()
                    beacons.append(float(seg[1]))
                    newSN = seg[9].strip(',').split('=')[1]
                    if beacons_chk == -1:
                        beacons_chk = int(newSN)
                    else:
                        if int(newSN)-beacons_chk != 1:
                            beacon_errors.update({seg[0]:float(seg[1])})
                        beacons_chk = int(newSN)
                if 'Authentication' in line:
                    seg = line.split()
                    if 'R' in seg[10]:
                        authRe.append(float(seg[1]))
                    elif self.ap in seg[4]:
                        auth1.append(float(seg[1]))
                    else:
                        auth2.append(float(seg[1]))
                if 'Association' in line:
                    seg = line.split()
                    if 'R' in seg[11]:
                        assoRe.append(float(seg[1]))
                    elif 'Request' in line:
                        asso1.append(float(seg[1]))
                    elif 'Response' in line:
                        asso2.append(float(seg[1]))
                if 'Disassociate' in line:
                    seg = line.split()
                    if 'R' in seg[10]:
                        disaRe.update({float(seg[1]):seg[2]})
                    else:
                        disa.update({float(seg[1]):seg[2]})
                if 'Deauthentication' in line:
                    seg = line.split()
                    if 'R' in seg[10]:
                        deauthRe.update({float(seg[1]):seg[2]})
                    else:
                        deauth.update({float(seg[1]):seg[2]})
                if 'Null function' in line:
                    seg = line.split()
                    if 'P' in seg[13]:
                        powersave.append(float(seg[1]))
        if self.verbose:
            print beacon_errors.keys()
        bins = range(int(beacons[0]),int(beacons[-1]+1))
        binBeacons = np.digitize(beacons,bins)
        binAuth = np.digitize(authRe,bins)
        unibeac, cntbeac = np.unique(binBeacons, return_counts=True)
        uniAuth, cntAuth = np.unique(binAuth, return_counts=True)
        dbeacons = dict(zip(unibeac, cntbeac))
        dict_auth = dict(zip(uniAuth, cntAuth))
        if self.verbose:
            print unibeac, cntbeac
            print uniAuth, cntAuth
            print dict_auth
        #d = {x:binBeacons.count(x) for x in binBeacons}
        if len(dict_auth) > 0:
            brate = plt.stem(dict_auth.keys(), dict_auth.values(),'lawngreen',label="authRetries")
        power = plt.plot(powersave, [1]*len(powersave),'bv',label="STA -> powersave")
        authseq1 = plt.plot(auth1, [1]*len(auth1),'go',label="Auth seq1")
        authseq2 = plt.plot(auth2, [1]*len(auth2),'o', color='lime',label="Auth seq2")
        assoseq1 = plt.plot(asso1, [1]*len(asso1),'D', color='darkmagenta',label="associate Request")
        assoseq2 = plt.plot(asso2, [1]*len(asso2),'*', color='fuchsia',label="associate Response")
        disasso = plt.plot(disa.keys(), [1]*len(disa.keys()),'+', color='gold',label="dissociate")
        deauthentic = plt.plot(deauth.keys(), [1]*len(deauth.keys()),'rx',label="deauth")
        plt.plot(dbeacons.keys(), dbeacons.values(),'y', linewidth=1.0,label="beacons")
        plt.legend()        
        plt.grid(b=True, which='minor',  linestyle='--', alpha=0.2)
        plt.minorticks_on()
        plt.grid(True)        
        plt.show()
        summary()
        
    def cleanup(self):
        for i in self.captureInfo:
            i.remTmpFile()
        
    

if __name__ == "__main__":    
    wifiVerifyparseCmd()



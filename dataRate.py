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
#import pyshark
# wlan.sa Source address: HonHaiPr_55:fe:c3 (08:3e:8e:55:fe:c3)
# BSS Id: 96:57:a5:09:97:ac (96:57:a5:09:97:ac)
mpl.rcParams['savefig.dpi'] = 600

# The following code includes a class that manages command line functionality
description =   "dataRate.py : This program performs filters on pcap captures and parses information to summarize " \
                "stated data rate, packets, and size. " 
epilog =    "Author: Eric Zhong; Email: zhong@hp.com; " \
            "Last Updated: November 3, 2017"

class Datainfocmdline(object):
    def __init__(self):
        
        self.parser = argparse.ArgumentParser(description=description,epilog=epilog,prefix_chars="-/")    

        self.parser.add_argument("-c","-C","/c","/C","--client",dest="client",required=True ,help="client mac address: device which is connecting to the accesspoint")
        self.parser.add_argument("-p","-P","/p","/P","--filename",dest="path",help="System Path to pcap file captured from client device")
        self.parser.add_argument("-v","-V","/v","/V","--verbose",dest="verbose",action="store_true",help="print out lines that are begin searched")


        self._args = self.parser.parse_args()
        new = Dataparse(self._args.client, self._args.path, self._args.verbose )
    
        
class Dataparse():
    def __init__(self, client, path, verbose):
        self.client = client
        self.verbose = verbose
        self.path = path
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
                if self.checkMACaddr(self.client):
                    self.filterforPrn(self.path)                    
                    self.filter()
                    self.processfile()                    
                else:
                    print 'invalid mac address'
      

    def checkMACaddr(self, mac):
        chk = re.search("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$",mac)
        if chk:
            return True
        else:
            return False
            
    def filterforPrn(self, file):        #84:ba:3b:05:d4:04 canon
        self.fn = file.split('.pcap')[0]+'_onlyprn.pcap'
        tsharkCall = ["tshark", "-r", file,"-Y", "wlan.addr eq "+self.client+'&& !_ws.malformed', "-w", self.fn]
        if os.path.isfile(self.fn):
            print 'PCAP file already exists!'
            pass
        else:
            self.startfilter(tsharkCall)
    
    def filter(self):
    #tshark -r speed.pcap -T fields -e _ws.col.No. -e _ws.col.Time -e _ws.col.Source -e _ws.col.Destination -e _ws.col.Length -e wlan_radio.duration -e radiotap.datarate -e wlan_radio.data_rate -e radiotap.dbm_antsignal -e wlan_radio.signal_dbm -e radiotap.dbm_antnoise -e wlan_radio.noise_dbm -e wlan.fc.type > test.txt
    #tshark -r speed.pcap -T fields -e _ws.col.No. -e _ws.col.Time -e _ws.col.Source -e _ws.col.Destination -e _ws.col.Length -e wlan_radio.duration -e radiotap.datarate -e radiotap.dbm_antsignal -e radiotap.dbm_antnoise -e wlan.fc.type -e wlan.fc.retry > test.txt
        tsharkOut  = open('datadump.txt', "w")
        formating = [ '-T', 'fields', '-e', '_ws.col.No.',\
            '-e', '_ws.col.Time', '-e', '_ws.col.Source', '-e', '_ws.col.Destination', '-e', '_ws.col.Length',\
            '-e', 'wlan_radio.duration', '-e', 'radiotap.datarate', '-e', 'radiotap.dbm_antsignal',\
			'-e','radiotap.dbm_antnoise', '-e', 'wlan.fc.type','-e', 'wlan.fc.retry']
        tsharkCall = ["tshark", "-r", self.fn] + formating  
        tsharkProc = subprocess.Popen(tsharkCall, stdout=tsharkOut, executable=self.tshark)
        tsharkProc.wait()
        tsharkOut.close()
            
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
        
        with open('datadump.txt') as f:
            with open('out.txt','a+') as f2:
                pkts = []
                size = []
                mcs = []
                duration = []
                framecolor = []
                rssi = []
                noise = []
                retries = []
                for line in f:                    
                    #print len(line.split('\t'))                
                    #f2.write(line.split('\t')[-1])
                    pkts.append(line.split('\t')[1])
                    size.append(line.split('\t')[4])
                    mcs.append(line.split('\t')[6])
                    duration.append(line.split('\t')[5])
                    rssi.append(line.split('\t')[7])
                    noise.append(line.split('\t')[8])
                    retries.append(line.split('\t')[-1])
                    clr = line.split('\t')[-2]
                    if clr == '0':
                        framecolor.append('r')
                    elif clr == '1':
                        framecolor.append('b')
                    elif clr == '2':
                        framecolor.append('g')
                pktsgrp = [int(float(i)) for i in pkts]
                unipkt, cntpkts = np.unique(pktsgrp, return_counts=True)
                unimcs, cntmcs = np.unique(mcs, return_counts=True)
                #print len(unimcs), len(cntmcs)
                #print unimcs
                #print cntmcs
                #print len(unipkt), '\n', pkts,'\n',len(color), len(size)
                sizegrp = []
                total = 0
                for i in xrange(len(pktsgrp)):
                    try:
                        if pktsgrp[i] == pktsgrp[i+1]:
                            total += int(size[i])
                        else:
                            sizegrp.append(total)
                            total = 0
                    except IndexError as e:
                        sizegrp.append(total)
                        pass              
                sizegrp = np.array(sizegrp) // (2**10)
                plt.figure(1,figsize=(22, 11))
                plt.subplot(411)
                plt.plot(unipkt, cntpkts,'k', linewidth=1.0,label="pkts")  
                plt.ylabel('Num of Pkts')      
                plt.legend()        
                plt.grid(b=True, which='minor',  linestyle='--', alpha=0.2)
                plt.minorticks_on()
                plt.grid(True)  
                #plt.scatter(unipkt, cntpkts, color)        
                plt.subplot(412)
                totalsize = float(np.sum(np.array(map(float,size))))/ float(2**20)
                plt.plot(unipkt, sizegrp,'k', linewidth=1.0,label="size")
                plt.plot([],[],' ',label="total size MB: "+str(totalsize))
                plt.ylabel('KB')                
                plt.legend()        
                plt.grid(b=True, which='minor',  linestyle='--', alpha=0.2)
                plt.minorticks_on()
                plt.grid(True)     
                
                plt.subplot(413)                 
                plt.xticks([])
                plt.ylabel('Mbits/s') 
                plt.yticks([1,11,12,18,24,36,48,54])
                plt.scatter(pkts, mcs,color=framecolor,label="phyrate", s=1)
                mcs = np.array(map(float,mcs))
                datafilt = np.array([True if x=='g' else False for x in framecolor])
                dataonly = mcs[datafilt]
                uniData, AmtDat = np.unique(dataonly, return_counts=True)
                mu = mcs.mean()
                median = np.median(mcs)
                sigma = mcs.std()
                props = dict(boxstyle='round', facecolor='wheat', alpha=0.5)
                textstr = 'All\n$\mu=%.2f$\n$\mathrm{median}=%.2f$\n$\sigma=%.2f$\n'%(mu, median, sigma)
                textstr += 'DataOnly\nbins='+str(uniData)+'\namt='+str(AmtDat)
                plt.text(0.01, 24, textstr, fontsize=11, verticalalignment='center', bbox=props)
                
                plt.subplot(414)
                major_ticks = np.arange(0, 12, 1)
                plt.xticks([])
                plt.ylabel('MBytes/s\npktSize/Duration')
                plt.yticks(major_ticks)                
                actualrate = np.array(map(float,size))//np.array(map(float,duration))*(2^20/1000000)
                actualratedatapkts = actualrate[datafilt]
                #print max(actualrate), min(actualrate), np.mean(actualrate)
                plt.scatter(pkts, actualrate,color=framecolor,label="actualRate", s=1)
                mu = actualrate.mean()
                mu2 = actualratedatapkts.mean()
                median = np.median(actualrate)
                median2 = np.median(actualratedatapkts)
                sigma = actualrate.std()
                sigma2 = actualratedatapkts.std()
                props = dict(boxstyle='round', facecolor='wheat', alpha=0.5)                
                textstr = 'All\n$\mu=%.2f$\n$\mathrm{median}=%.2f$\n$\sigma=%.2f$\n'%(mu, median, sigma)
                textstr += 'DataOnly\n$\mu=%.2f$\n$\mathrm{median}=%.2f$\n$\sigma=%.2f$'%(mu2, median2, sigma2)
                plt.text(0.01, 5, textstr, fontsize=11, verticalalignment='center', bbox=props)
                #manager = plt.get_current_fig_manager()
                #manager.window.showMaximized()                
                plt.savefig(''.join((self.path.split('/')[-1],'_plot1.pdf')))
                fig2 = plt.figure(2,figsize=(22, 11))
                signal_axes = fig2.add_subplot(211) #plt.subplot(211)
                signal_axes.yaxis_inverted()
                signal_axes.set_xticks([]) # plt.xticks([])
                #signal_axes.set_axis_off()
                signal_axes.set_yticks(np.arange(-20,-100,-10)) #plt.yticks(np.arange(-20,-100,-10))
                
                signal_axes.scatter(pkts, rssi,c='g',label="rssi", s=1)
                signal_axes.scatter(pkts, noise,c='r',label="noise", s=1)
                props = dict(boxstyle='round', facecolor='white', alpha=0.5)
                rssi = np.array(map(float,rssi))
                textstr = '$\max=%.2f$\n$\mu=%.2f$\n$\mathrm{median}=%.2f$\n$\sigma=%.2f$\n$\min=%.2f$'%\
                (max(rssi), rssi.mean(),np.median(rssi),rssi.std(), min(rssi))
                signal_axes.text(0.95, -60, textstr, fontsize=12, verticalalignment='bottom', bbox=props)
                signal_axes.set_ylabel('dBm')
                signal_axes.legend()
                signal_axes2 = fig2.add_subplot(212)# plt.subplot(212)
                signal_axes2.set_xticks([]) #plt.xticks([])
                signal_axes2.scatter(pkts, retries,color=framecolor, s=1, label="retries")  
                signal_axes2.set_ylabel('pkt retry\n1=yes 0=not retry')       
                fig2.set_size_inches(22,11)
                fig2.savefig(''.join((self.path.split('/')[-1],'__plot2.pdf')))
                #plt.show()
        
    def cleanup(self):
        for i in self.captureInfo:
            i.remTmpFile()
        
    

if __name__ == "__main__":    
    Datainfocmdline()

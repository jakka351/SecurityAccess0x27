#!/usr/bin/python3
#coding:utf-8
#################################################################################################################
# FG1ECUComms.py requestSecurityAccess Service 0x27 ecu security access 
# https://github.com/jakka351/FG-Falcon
#################################################################################################################
# Notes
#  1. This software can only be distributed with my written permission. It is for my own educational purposes and 
#     is potentially dangerous to ECU health and safety. 
#################################################################################################################
'''__    ___________    ____  /\     ___________             _________                                   __   
  / /    \_   _____/___/_   | \ \    \_   _____/ ____  __ __ \_   ___ \  ____   _____   _____   ______   \ \  
 / /      |    __)/ ___\|   |  \ \    |    __)__/ ___\|  |  \/    \  \/ /  _ \ /     \ /     \ /  ___/    \ \ 
 \ \      |     \/ /_/  >   |   \ \   |        \  \___|  |  /\     \___(  <_> )  Y Y  \  Y Y  \\___ \     / / 
  \_\     \___  /\___  /|___|    \ \ /_______  /\___  >____/  \______  /\____/|__|_|  /__|_|  /____  >   /_/  
              \//_____/           \/         \/     \/               \/             \/      \/     \/         
 Falcon Diagnostic Utility - [FG1ECUComms]'''
#############################################################################################################
# library imports
#############################################################################################################
import os, sys, time, queue, traceback
from threading import *
from threading import Thread
from array import array
import can 
#################################################################################################################
# GNU/Linux socketcan canbus interfaces //
# // vcan0 is virtual socket for testing on linux socketcan
# // virtualcan is https://github.com/windelbouwman/virtualcan cross platform
#################################################################################################################
businput     = 'socketcan'
channelinput = 'can0'
bitrateinput = '125000'
MidSpeedCan  = can.interface.Bus(channel=channelinput, bustype=businput, bitrate=bitrateinput) # MS CAN
# // insert secret key here
fixed                                                 = 0x123456
# // ecu rx can id insert here
DiagSix_Rx                                            = 0x123
ServiceRequest                                        = dict()
#################################################################################################################
# SocketCAN Diagnostic Message Parser - only parses diagnostic tx/rx messages
#################################################################################################################
def Parser(message):
    messageSent = 0
    responsePos = 0
    responseNeg = 0
    try:   
        while True:
            for i in range(1):
                if message.arbitration_id in DiagSig_Rx.keys() and message.data[1] in ServiceRequest.keys():
                    messageSent = 1
                    print("   [ >>-------->> Rx ECU:")
                    print("   [ DiagSig_Rx:", DiagSig_Rx[message.arbitration_id], " Service Request:  ", ServiceRequest[message.data[1]], "  ]  ")
                    print("   [", message, "]")
                    print("   [ ________________________________________________________________________________________________________________    ] // ")  
                    return messageSent

                elif message.arbitration_id not in DiagSig_Rx.keys():
                    pass 

                if message.arbitration_id in DiagSig_Tx.keys() and (message.data[1] - 0x40) in ServiceRequest.keys():
                    responsePos = 1
                    print("   [ <<--------<< Tx ECU:")
                    print("   [ DiagSig_Tx:", DiagSig_Tx[message.arbitration_id], "Positive Response:  ", ServiceRequest[message.data[1] - 0x40], "  ]  ")
                    print("   [", message, "]")
                    print("   [ ______________________________________________________________________________________________________________________] //  ")
                    return responsePos
                elif message.arbitration_id in DiagSig_Tx.keys() and message.data[1] == 0x7F and (message.data[2] - 0x40) in ServiceRequest.keys() and message.data[3] in NegativeResponseCode.keys():
                    responseNeg = 1 
                    print("   [   Negative Response Code:", NegativeResponseCode[message.data[3]], "                                                                                                           ] ")
                    print("   [ <<--------<< Tx ECU:")
                    print("   [", message, "]")
                    print("   [ DiagSig_Tx:", DiagSig_Tx[message.arbitration_id], "[ 0x7F Negative Response:", ServiceRequest[(message.data[2] - 0x40)], "Error Code:",  NegativeResponseCode[message.data[3]], "]")
                    print("   ------//FG1ECUComms.py         |            6FPA-util  ---//")
                    return responseNeg
                elif message.arbitration_id not in DiagSig_Tx.keys():
                    pass 

    except KeyError:
        pass
    except KeyboardInterrupt:
        sys.exit(0)  
    except can.CanError:
        print("can error")                   
    except Exception:
        traceback.print_exc(file=sys.stdout)                     # quit if there is a python problem
    except OSError:
        sys.exit()
#################################################################################################################
# SocketCAN parser results
#################################################################################################################
def PARSER_RESPONSE(_DiagSig_Rx): 
   Parser()
   if messageSent == 1: 
       print("request sent onto canbus for", DiagSig_Rx[_DiagSig_Rx])
   if responsePos == 1:
       print("recieved positive response to request from:", DiagSig_Tx[(_DiagSig_Rx + 0x08)], " for Service:", ServiceRequest )
   if responseNeg == 1:
       print("recieved negative response code from ecu:",  DiagSig_Tx[(_DiagSig_Rx + 0x08)] )
   return 
#################################################################################################################
# SID 0x27 SecurityAccess request
#################################################################################################################
requestSecurityAccess                                 = 0x27
ServiceRequest[requestSecurityAccess]                 = [requestSecurityAccess, "requestSecurityAccess", "0x27"]
reportSecurityAccess                                  = 0x67
ServiceRequest[reportSecurityAccess]                  = [reportSecurityAccess, "reportSecurityAccess", "0x27 Ecu Response"]
# the level of access in the request
securityLevel                                         = dict()
levelOne                                              = 0x01
securityLevel[levelOne]                               = [levelOne, "Security Access Level 1, 0x2701"]
levelTwo                                              = 0x03
securityLevel[levelTwo]                               = [levelTwo, "Security Access Level 2, 0x2703"]
levelThree                                            = 0x05
securityLevel[levelThree]                             = [levelThree, "Security Access Level 3, 0x2705"]
levelFour                                             = 0x11
securityLevel[levelFour]                              = [levelFour, "Security Access Level 4, 0x2711"]

#################################################################################################################
# Usage: requestSecurityAccess(DiagSig_Rx, securityLevel)
#
#################################################################################################################
def requestSecurityAccess(DiagSix_Rx, securityLevel):
    msg = can.Message(arbitration_id = DiagSig_Rx,
                      data           = [0x02, requestSecurityAccess, securityLevel, 0, 0, 0, 0, 0] , is_extended_id=False)
    try:
        response = MidSpeedCan.recv()
        MidSpeedCan.send(msg)
        Parser(response)
        if messsage.arbitration_id == (DiagSig_Rx + 8) and message.data[1] == 0x67:
            print(message)
            seed    = message.data[1], message.data[2], message.data[3]
            seed[0] = message.data[1]
            seed[1] = message.data[2]
            seed[2] = message.data[3]
            print("Got Seed: ", seed)
            return seed
        else:
            pass
    except can.CanError():
        print("Service 0x27 requestSecurityAccess failed.")
#############################################################################################################
# function that generates the key
#############################################################################################################
def KeyGen(seed, fixed):
    seed   = requestSecurityAccess(DiagSix_Rx, 0x01)
    try: 
        challengeCode = array('Q')
        challengeCode.append(fixed & 0xff)
        challengeCode.append((fixed >> 8) & 0xff)
        challengeCode.append((fixed >> 16) & 0xff)
        challengeCode.append((fixed >> 24) & 0xff)
        challengeCode.append((fixed >> 32) & 0xff)
        challengeCode.append(seed[2])
        challengeCode.append(seed[1])
        challengeCode.append(seed[0])
        temp1 = 0xC541A9
        for i in range(64):
            abit = temp1 & 0x01
            chbit = challengeCode[7] & 0x01
            bbit = abit ^ chbit
            temp2 = (temp1 >> 1) + bbit * 0x800000 & -1
            temp1 = (temp2 ^ 0x109028 * bbit) & -1
            challengeCode[7] = challengeCode[7] >> 1 & 0xff
            for a in range(7, 0, -1):
                challengeCode[a] = challengeCode[a] + (challengeCode[a - 1] & 1) * 128 & 0xff
                challengeCode[a - 1] = challengeCode[a - 1] >> 1
        key = [ temp1 >> 4 & 0xff, ((temp1 >> 12 & 0x0f) << 4) + (temp1 >> 20 & 0x0f), (temp1 >> 16 & 0x0f) + ((temp1 & 0x0f) << 4) ]
        print("Succesfully got key: {key}")
        return key
    except can.CanError():
        print("CAN Error")            
#############################################################################################################
# function to send key 
# Usage: SendKey(key) should be all that needs to be called.
#############################################################################################################
def SendKey(key):
    key = Keygen(seed)
    keyResponse   = can.Message(arbitration_id = DiagSig_Rx,
                          data           = [0x02, 0x27, key[0], key[1], key[2], 0, 0, 0], is_extended_id = False)
    try:
        response = MidSpeedCan.recv()
        MidSpeedCan.send(keyResponse)
        Parser(response)
        if messsage.arbitration_id == (DiagSig_Rx + 8)  and message.data[1] == 0x67:
            print(message)
            return
        else:
            pass
    except can.CanError():
        print("CAN Error")            

#################################################################################################################


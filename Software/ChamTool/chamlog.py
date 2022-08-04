#!/usr/bin/env python3
#
# Command line tool to analyze binary dump files from the Chameleon
# Authors: Simon K. (simon.kueppers@rub.de), Astra Pi (astra@flipperdevices.com)

from __future__ import print_function

import argparse
import sys
import json
import Chameleon
import io
import datetime
from Chameleon.ISO14443 import CardTypesMap

def verboseLog(text):
    formatString = "[{}] {}"
    timeString = datetime.datetime.utcnow()
    print(formatString.format(timeString, text), file=sys.stderr)
	
def formatText(log):
    formatString  = '{timestamp:0>5d} ms <{deltaTimestamp:>+6d} ms>:'
    formatString += '{eventName:<28} [{data}] ' \
                    '\033[94m {note} \x1b[0m \n'

    text = ''

    for logEntry in log:
        if logEntry['data']:
            # Add spaces every 2 characters
            logEntry['data'] = ' '.join(logEntry['data'][i:i+2] for i in range(0, len(logEntry['data']), 2))
        if logEntry['eventName'] == 'CODEC RX' or logEntry['eventName'] == 'CODEC RX SNI READER':
            text += '\033[91m'
            text += "RDR "
        elif logEntry['eventName'] == 'CODEC RX SNI CARD W/PARITY' or logEntry['eventName'] == 'CODEC TX':
            text += '\033[92m'
            text += "TAG "
        else:
            text += "INF "
        text += formatString.format(**logEntry)
        print("formatting log entry:" + str(logEntry))

    return text

def formatJSON(log):
    text = json.dumps(log, sort_keys=True, indent=4)
    
    return text

def formatProxmarkTrace(log):
    # Proxmark trace specifications:
    #
    #      /*
    #    Traceformat:
    #    32 bits timestamp (little endian)
    #    16 bits duration (little endian)
    #    15 bits data length (little endian) (0x7FFF)
    #    1 bit isResponse (0=reader to tag, 1=tag to reader)
    #    data length Bytes data
    #    x Bytes parity,  where x == ceil(data length/8)
    # */

    # typedef struct {
    #     uint32_t timestamp;
    #     uint16_t duration;
    #     uint16_t data_len : 15;
    #     bool isResponse : 1;
    #     uint8_t frame[];
    #     // data_len         bytes of data
    #     // ceil(data_len/8) bytes of parity
    # } PACKED tracelog_hdr_t;

    # #define TRACELOG_HDR_LEN        sizeof(tracelog_hdr_t)
    # #define TRACELOG_PARITY_LEN(x)  (((x)->data_len - 1) / 8 + 1)

    pass

def main():
    outputTypes = {
        'text': formatText,
        'json': formatJSON
    }

    argParser = argparse.ArgumentParser(description="Analyzes binary Chameleon logfiles")

    group = argParser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", dest="logfile", metavar="LOGFILE")
    group.add_argument("-p", "--port", dest="port", metavar="COMPORT")
    
    argParser.add_argument("-t", "--type", choices=outputTypes.keys(), default='text',
                            help="specifies output type")
    argParser.add_argument("-d", "--decode", dest="decode", choices=CardTypesMap.keys(), default=None, help="Decode the sniffed traffic and application data with a decoder")
    argParser.add_argument("-l", "--live", dest="live", action='store_true', help="Use live logging capabilities of Chameleon")
    argParser.add_argument("-c", "--clear", dest="clear", action='store_true', help="Clear Chameleon's log memory when using -p")
    argParser.add_argument("-m", "--mode", dest="mode", metavar="LOGMODE", help="Additionally set Chameleon's log mode after reading it's memory")
    argParser.add_argument("-v", "--verbose", dest="verbose", action='store_true', default=0)

    args = argParser.parse_args()
	
    if (args.verbose):
        verboseFunc = verboseLog
    else:
        verboseFunc = None

    print("\nNote: If parityBit check failed, '!' is appended to the decoded data and raw data with parity bit is displayed.\n")
    if (args.live):
        # Live logging mode
        if (args.port is not None):
            chameleon = Chameleon.Device(verboseFunc)

            if (chameleon.connect(args.port)):
                chameleon.cmdLogMode("LIVE")

                while True:
                    stream = io.BytesIO(chameleon.read())
                    log = Chameleon.Log.parseBinary(stream, args.decode)
                    loglist = []
                    if (len(log) > 0):
                        loglist.append(outputTypes[args.type](log))
                    loglist.sort()
                    for line in loglist:
                        print(line)
                    sys.stdout.flush()
      
    else:
        if (args.logfile is not None):
            handle = open(args.logfile, "rb")
        elif (args.port is not None):
            chameleon = Chameleon.Device(verboseFunc)

            if (chameleon.connect(args.port)):
                handle = io.BytesIO()
                chameleon.cmdDownloadLog(handle)
                handle.seek(0)
                
                if (args.clear):
                    chameleon.cmdClearLog()

                if (args.mode is not None):
                    chameleon.cmdLogMode(args.mode)
                        
                chameleon.disconnect()
            else:
                sys.exit(2)
                
        # Parse actual logfile
        log = Chameleon.Log.parseBinary(handle, args.decode)

        # Print to console using chosen output type
        print(outputTypes[args.type](log))


if __name__ == "__main__":
    main()

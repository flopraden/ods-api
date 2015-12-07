import subprocess
import re
import logging
from util import calc_keyid,calc_ds
import sys
import time
import os

import pprint
pp = pprint.PrettyPrinter(indent=4)

# create logger
logger = logging.getLogger('ODS-API')
logger.setLevel(logging.DEBUG)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# create formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger.addHandler(ch)

# RegExp to parse

regexport=re.compile('^([^ ]+?)\.?(?: |\t)*[0-9]+(?: |\t)*IN(?: |\t)*DNSKEY(?: |\t)*([0-9]+)(?: |\t)*([0-9]+)(?: |\t)*([0-9]+)(?: |\t)*([^ ]+)(?: |\t)*;\{id = ([0-9]+) \(([a-zA-Z]+)\), size = ([0-9]+)b\}.*$',re.M)
regexportds=re.compile('^([^ ]+?)\.?(?: |\t)*[0-9]+(?: |\t)*IN(?: |\t)*DS(?: |\t)*([0-9]+)(?: |\t)*([0-9]+)(?: |\t)*([0-9]+)(?: |\t)*([a-fA-F0-9]+).*$',re.M)
regkey=re.compile('^([^ ]+?)\.?(?: |\t)*(KSK|ZSK)(?: |\t)*([a-zA-Z]+)(?: |\t)*((?:[0-9-]+ [0-9:]+)|waiting for ds-seen)(?: |\t)*\(([a-zA-Z]+)\)(?: |\t)*([0-9]+)(?: |\t)*([0-9]+)(?: |\t)*([0-9a-fA-F]+)(?: |\t)*([^ \t]+)(?: |\t)*([0-9]+)$',re.M)
regkeymissing=re.compile('^([^ ]+?)\.?(?: |\t)*(KSK|ZSK)(?: |\t)*([a-zA-Z]+)(?: |\t)*((?:[0-9-]+ [0-9:]+)|waiting for ds-seen|\(not scheduled\))(?: |\t)*\(([a-zA-Z]+)\)(?: |\t)*([0-9]+)(?: |\t)*([0-9]+)(?: |\t)*([0-9a-fA-F]+)(?: |\t)*([^ \t]+) NOT IN repository(?: |\t)*$',re.M)

# Convert sha alg int to str

shaalg = { 1 : 'sha1', 2: 'sha256' }


def reload_ods_enforcer(path_pid):
    with open(path_pid,'r') as fpid:
        lignes=[ligne.rstrip('\n') for ligne in fpid]
        for pid in lignes:
            logger.debug("reload enforcer : KILL HUP %d", int(pid))
            os.kill(int(pid), 1)


def export_keystate(configfile,**kwargs):

    # Get config file
    if configfile is not None:
        ods_conf=" --config " + configfile
    else:
        ods_conf=""

    # Construct ods_ksmutil path with conf name
    ods=kwargs.get('ods_ksmutil_path') + ods_conf

    # Get key list
    (errno,output)=subprocess.getstatusoutput(ods + ' key list --verbose')
    if errno != 0:
        logger.critical("KSMUTIL KEY LIST ERROR %d: %s",errno,output)
        exit(1)
    ods_keylist=regkey.findall(output)
    ods_keymissinglist=regkeymissing.findall(output)

    # Construct dict of key
    dKey={}
    for (domain,keyType,state,nextTrans,nextState,keySize,alg,ckaid,repoHSM,tag) in ods_keylist:
        if nextTrans == 'waiting for ds-seen':
            nT=None
            waiting=True
        elif nextTrans == '(not scheduled)':
            nT=None
            waiting=False
        else:
            nT=time.strptime(nextTrans, '%Y-%m-%d %H:%M:%S')
            waiting=False
        try:
            dKey[domain][int(tag)]={'tag' : int(tag), 'type': keyType.lower(), 'state': state.lower(), 'nextTrans': nT, 'nextState': nextState.lower(),
                                 'size': int(keySize), 'ckaid': int(ckaid,16), 'repo': repoHSM, 'algorithm': int(alg), 'waiting': waiting}
        except KeyError:
            dKey[domain]={ int(tag): {'type': keyType.lower(), 'state': state.lower(), 'nextTrans': nT, 'nextState': nextState.lower(),
                                 'size': int(keySize), 'ckaid': int(ckaid,16), 'repo': repoHSM, 'algorithm': int(alg), 'waiting': waiting} }
    # Add missing keys : no keytag => keytag='missing'
    for (domain,keyType,state,nextTrans,nextState,keySize,alg,ckaid,repoHSM) in ods_keymissinglist:
        if nextTrans == 'waiting for ds-seen':
            nT=None
            waiting=True
        else:
            nT=time.strptime(nextTrans, '%Y-%m-%d %H:%M:%S')
            waiting=False
        ddKey=dKey.get(domain,{})
        keyinf={'type': keyType.lower(), 'state': state.lower(), 'nextTrans': nT, 'nextState': nextState.lower(),
                                 'size': int(keySize), 'ckaid': int(ckaid,16), 'repo': repoHSM, 'algorithm': int(alg), 'waiting': waiting}
        try:
            ddKey['missing'].append(keyinf)
        except KeyError:
            ddKey['missing']=[keyinf]


    # Get keys info
    (errno,output)=subprocess.getstatusoutput(ods + ' key export')
    if errno != 0 and errno != 255:
        # err 255 => partial error occured when some key are not anymore in HSM
        logger.critical("KSMUTIL KEY EXPORT ERROR %d: %s",errno,output)
    if errno == 255:
        # err 255 => partial error occured when some key are not anymore in HSM
        logger.error("Export is partial : missing key in HSM?")
    
    ods_keyexport=regexport.findall(output)
    
    for (domain,flags,protocol,algorithm,pubKey,keytag,keyType,size) in ods_keyexport:
        if domain in dKey:
            iKeyTag=int(keytag)
            if iKeyTag in dKey[domain]:
                iAlg=int(algorithm)
                iSize=int(size)
                lKeyType=keyType.lower()
                if iAlg != dKey[domain][iKeyTag]['algorithm']:
                    logger.error("Algorithm differ from key list ( %d != %d ) for tag %d of key in domain %s : skipping", iAlg, dKey[domain][iKeyTag]['algorithm'], iKeyTag, domain)
                if iSize != dKey[domain][iKeyTag]['size']:
                    logger.error("Size differ from key list ( %d != %d ) for tag %d of key in domain %s : skipping", iSize, dKey[domain][iKeyTag]['size'], iKeyTag, domain)
                if lKeyType != dKey[domain][iKeyTag]['type']:
                    logger.error("Type differ from key list ( %s != %s ) for tag %d of key in domain %s : skipping", lKeyType, dKey[domain][iKeyTag]['type'], iKeyTag, domain)
                dKey[domain][iKeyTag].update({'flags': int(flags), 'protocol': int(protocol), 'pubKey': pubKey, 'calc-id': calc_keyid(flags,protocol, algorithm ,pubKey),'calc-ds': calc_ds(domain, flags, protocol, algorithm, pubKey)})
            else:
                logger.error("Tag %d of key in domain %s not in key list : skipping", iKeyTag, domain)
        else:
            logger.error("Domain %s not in key list : skipping", domain)

    # Get keys info for DS
    (errno,output)=subprocess.getstatusoutput(ods + ' key export --ds')
    if errno != 0 and errno != 255:
        # err 255 => partial error occured when some key are not anymore in HSM
        logger.critical("KSMUTIL KEY EXPORT DS ERROR %d: %s",errno,output)
    if errno == 255:
        # err 255 => partial error occured when some key are not anymore in HSM
        logger.error("Export ds is partial : missing key in HSM?")
    ods_keyexportds=regexportds.findall(output)
    
    for (domain,keytag,algorithm,shaid,shasum) in ods_keyexportds:
        if domain in dKey:
            iKeyTag=int(keytag)
            if iKeyTag in dKey[domain]:
                iAlg=int(algorithm)
                if iAlg != dKey[domain][iKeyTag]['algorithm']:
                    logger.error("Algorithm differ from key list ( %d != %d ) for tag %d of key in domain %s : skipping (DS)", iAlg, dKey[domain][iKeyTag]['algorithm'], iKeyTag, domain)
                shas=dKey[domain][iKeyTag].get('ds',{})
                shas[int(shaid)]=shasum
                dKey[domain][iKeyTag]['ds']=shas
            else:
                logger.error("Tag %d of key in domain %s not in key list : skipping DS", iKeyTag, domain)
        else:
            logger.error("Domain %s not in key list : skipping DS", domain)

    return dKey


def seen_ds(domain,ckaid,configfile, **kwargs):
    # Get config file
    if configfile is not None:
        ods_conf=" --config " + configfile
    else:
        ods_conf=""

    # Construct ods_ksmutil path with conf name
    ods=kwargs.get('ods_ksmutil_path') + ods_conf

    # Get key list
    (errno,output)=subprocess.getstatusoutput(ods + ' key ds-seen --zone %s --cka_id %x' % (domain,ckaid))
    if errno != 0:
        logger.critical("KSMUTIL ERROR %d: %s",errno,output)
    return (errno,output)


def del_key(ods_path,configfile,domain,dry_run=False,**kwargs):
    logger.debug("Delete key from Domain %s in ODS %s : %s", domain,configfile,pp.pformat(kwargs))
    if dry_run:
        return
    # Get config file
    if configfile is not None:
        ods_conf=" --config " + configfile
    else:
        ods_conf=""

    # Construct ods_ksmutil path with conf name
    ods=ods_path + ods_conf

    # Construct args for KSMUTIL
    if 'ckaid' in kwargs:
        ods_param=' --zone {0!s} --cka_id {1:x}'.format(domain,kwargs['ckaid'])
    elif 'tag' in kwargs:
        ods_param=' --zone {0!s} --tag {1:d}'.format(domain,kwargs['tag'])
    else:
        logger.error("no ckaid or tag : could not delete key for domain %s",domain)
    if 'keep-key' in kwargs:
        ods_param=' --no-hsm' + ods_param
    
    ods_param=' key delete' + ods_param

    if 'force' in kwargs:
        ods_param=' -F' + ods_param

    ods_cmdline=ods +  ods_param
    logger.debug("Execute <%s>",ods_cmdline)

    # Delete key
    with subprocess.Popen(ods_cmdline.split(' '), stdout=subprocess.PIPE,stdin=subprocess.PIPE) as proc:
        out, outerr = proc.communicate("Y\n".encode())
        if proc.returncode != 0:
            if out is None:
                out=b''
            if outerr is None:
                outerr=b''
            logger.error("KSMUTIL KEY DEL (RETIRE) ERROR %d: (%s/%s)",proc.returncode,out.decode(),outerr.decode())


def rollover_key(ods_path,configfile,domain,dry_run=False,**kwargs):
    logger.debug("rollover key from Domain %s in ODS %s : %s", domain,configfile,pp.pformat(kwargs))
    if dry_run:
        return
    # Get config file
    if configfile is not None:
        ods_conf=" --config " + configfile
    else:
        ods_conf=""

    # Construct ods_ksmutil path with conf name
    ods=ods_path + ods_conf

    # Construct args for KSMUTIL
    if 'keytype' in kwargs:
        ods_param=' --zone {0!s} --keytype {1!s}'.format(domain,kwargs['keytype'])
    else:
        ods_param=' --zone {0!s} --all'.format(domain)

    ods_cmdline=ods + ' key rollover' + ods_param
    logger.debug("Execute <%s>",ods_cmdline)

    # rollover key
    (errno,output)=subprocess.getstatusoutput(ods_cmdline)
    if errno != 0:
        logger.error("KSMUTIL KEY ROLLOVER ERROR %d: %s",errno,output)


def add_key(ods_path,configfile,domain,keyinfo,dry_run=False):
    logger.debug("Add key for Domain %s in ODS %s : %s", domain,configfile,pp.pformat(keyinfo))
    if dry_run:
        return
    # Get config file
    if configfile is not None:
        ods_conf=" --config " + configfile
    else:
        ods_conf=""

    # Construct ods_ksmutil path with conf name
    ods=ods_path + ods_conf

    # Construct args for KSMUTIL
    try:
        ods_param=' --zone {domain!s} --cka_id {ckaid:x} --repository "{repo!s}" --bits {size:d} --algorithm {algorithm:d} --keystate {state!s} --keytype {type!s} --time {time!s}'.format(domain=domain,time=time.strftime("%Y%m%d%H%M%S", time.localtime()),**keyinfo)
    except KeyError as e:
        logger.error("Missing info in key : %s \n Skipping add key for domain %s",e,domain)
        return

    logger.debug("Execute <%s>",ods + ' key import' + ods_param)
    # Import key in repo in the keylist of domain
    (errno,output)=subprocess.getstatusoutput(ods + ' key import' + ods_param)
    if errno != 0:
        logger.critical("KSMUTIL KEY IMPORT ERROR %d: %s",errno,output)


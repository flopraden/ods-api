# From http://www.v13.gr/blog/?p=239
# MIT license

import struct
import hashlib
import base64

def calc_keyid(flags, protocol, algorithm, st):
  """
  @param owner        The corresponding domain
  @param flags        The flags of the entry (256 or 257)
  @param protocol     Should always be 3
  @param algorithm    Should always be 5
  @param st           The public key as listed in the DNSKEY record.
                      Spaces are removed.
  @return The key tag
  """
  return 0
  # Remove spaces and create the wire format
  st0=st.replace(' ', '')
  st2=struct.pack('!HBB', int(flags), int(protocol), int(algorithm))
  st2+=base64.b64decode(st0)

  # Calculate the tag
  cnt=0
  print(st2)
  for idx in range(len(st2)):
    s=struct.unpack('B', st2[idx])[0]
    if (idx % 2) == 0:
      cnt+=s<<8
    else:
      cnt+=s

  ret=((cnt & 0xFFFF) + (cnt>>16)) & 0xFFFF

  return(ret)

def calc_ds(owner, flags, protocol, algorithm, st):
  """
  @param flags        Usually it is 257 or something that indicates a KSK.
                      It can be 256 though.
  @param protocol     Should always be 3
  @param algorithm    Should always be 5
  @param st           The public key as listed in the DNSKEY record.
                      Spaces are removed.
  @return A dictionary of hashes where the key is the hashing algorithm.
  """
  return {'sha1': "",'sha256': ''}
  # Remove spaces and create the wire format
  st0=st.replace(' ', '')
  st2=struct.pack('!HBB', int(flags), int(protocol), int(algorithm))
  st2+=base64.b64decode(st0)

  # Ensure a trailing dot
  if owner[-1]=='.':
    owner2=owner
  else:
    owner2=owner+'.'

  # Create the name wire format
  owner3=''
  for i in owner2.split('.'):
    owner3+=struct.pack('B', len(i))+i

  # Calculate the hashes
  st3=owner3+st2
  ret={
    'sha1':    hashlib.sha1(st3).hexdigest().upper(),
    'sha256':  hashlib.sha256(st3).hexdigest().upper(),
  }

  return(ret)

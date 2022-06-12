# 0x27 requestSecurityAcesss
A tool forked from daftracing/vbflasher to unlock ecu's using a SocketCAN compatible interface.

## Install
```
$ pip3 install can pyserial crccheck
```

## Code reuse
It can be used as a module to provide ISOTP implementation and UDS functionalities including SecurityAccess 

## Example usage
#### Update ABS module on a Ford Focus RS mk3
```
$ ./vbflasher.py can0 /tmp/E3B1-14C039-AA.vbf /tmp/G1FC-14C036-AF.vbf /tmp/G1FC-14C381-AF.vbf
```
***
### requestSecurityAccess.py  
python functions to send a security access request via a socketcan interface - supply your own can_id and secret key. Untested.

### Chalenge Prompt
We are doing an project for a school competition in which we need to use a Raspberry Pi to make an IOT prototype. We received SD cards from the professor, and because we lost ours we asked another group to give us a copy of their card, I know it’s been modified because the original hash doesn’t match. Could you please investigate and tell me if everything is ok? Here is some parts of the file system:

FLAG FORMAT: KLCTF{flag}
### Solution
We are given a compressed raspberry pi file system.

Notice the suspicous file "back".
```
backdoor_pi/bin]$ ls
back          chvt           fgconsole   lesspipe     nc              rnano            umount
bash          con2fbmap      fgrep       ln           nc.openbsd      run-parts        uname
bunzip2       cp             findmnt     loadkeys     nc.traditional  sed              uncompress
```

Running strings on the binary shows us we found the correct file.
```
backdoor_pi/bin]$ strings back
Flask(
request(
abortc
{}:{}t@
34c05015de48ef10309963543b4a347b5d3d20bbe2ed462cf226b1cc8fff222es<
Congr4ts, you found the b@ckd00r. The fl4g is simply : {}:{}i
```

The binary is a compiled python 2.7 program.
```
backdoor_pi/bin]$ file back
back: python 2.7 byte-compiled
```

We use uncompyle2 to decompile the binary.
```
backdoor_pi/bin]$ uncompyle2 back 
# 2017.10.12 09:27:33 CDT
# Embedded file name: back.py
import sys
import os
import time
from flask import Flask
from flask import request
from flask import abort
import hashlib

def check_creds(user, pincode):
    if len(pincode) <= 8 and pincode.isdigit():
        val = '{}:{}'.format(user, pincode)
        key = hashlib.sha256(val).hexdigest()
        if key == '34c05015de48ef10309963543b4a347b5d3d20bbe2ed462cf226b1cc8fff222e':
            return 'Congr4ts, you found the b@ckd00r. The fl4g is simply : {}:{}'.format(user, pincode)
    return abort(404)


app = Flask(__name__)

@app.route('/')
def hello():
    return '<h1>HOME</h1>'


@app.route('/backdoor')
def backdoor():
    user = request.args.get('user')
    pincode = request.args.get('pincode')
    return check_creds(user, pincode)


if __name__ == '__main__':
    app.run(threaded=True, host='0.0.0.0', port=3333)
# okay decompyling back 
# decompiled 1 files: 1 okay, 0 failed, 0 verify failed
# 2017.10.12 09:27:33 CDT

```

Lets take the check creds function and make it executable on our system.
I converted val to utf-8 before hashing so it will run with python3. Since python3 has a big performance boost with iterators, this will be
beneficial in later steps.
```py
import sys
import os
import time
import hashlib

def check_creds(user, pincode):
    if len(pincode) <= 8 and pincode.isdigit():
        val = '{}:{}'.format(user, pincode)
        key = hashlib.sha256(val.encode('utf-8').hexdigest()
        if key == '34c05015de48ef10309963543b4a347b5d3d20bbe2ed462cf226b1cc8fff222e':
            return 'Congr4ts, you found the b@ckd00r. The fl4g is simply : {}:{}'.format(user, pincode)
    return 'false'

```
The flag is the user and pincode that match the hash. The easiest way to find the user is cat /var/passwd.
```
$ cat backdoor_pi/etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
pi:x:1000:1000:,,,:/home/pi:/bin/bash
sshd:x:101:65534::/var/run/sshd:/usr/sbin/nologin
ntp:x:102:104::/home/ntp:/bin/false
statd:x:103:65534::/var/lib/nfs:/bin/false
messagebus:x:104:106::/var/run/dbus:/bin/false
usbmux:x:105:46:usbmux daemon,,,:/home/usbmux:/bin/false
lightdm:x:106:109:Light Display Manager:/var/lib/lightdm:/bin/false
avahi:x:107:110:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
b4ckd00r_us3r:x:1001:1004::/home/b4ckd00r_us3r:/bin/bash
```

The most likley user is b4ckd00r so lets try that. We know from check_creds the pin is <= 8 char long so lets just 
brute force it.

```py
user = 'b4ckd00r_us3r'
c = 0
for pincode in range(99999999):
	if((pincode%1000000) == 0):
		c += 1
		print(str(c) + '% done')
	if(check_creds(user, str(pincode)) != 'false'):
		print( check_creds(user, str(pincode)) )
		quit()
print('nope...')
```

output:
```
backdoor_pi]$ python3 crack.py 
1% done
2% done
3% done
4% done
5% done
6% done
7% done
8% done
9% done
10% done
11% done
12% done
13% done
Congr4ts, you found the b@ckd00r. The fl4g is simply : b4ckd00r_us3r:12171337
```




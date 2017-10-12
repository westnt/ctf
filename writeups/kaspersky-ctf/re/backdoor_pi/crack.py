import sys
import os
import time
import hashlib

def check_creds(user, pincode):
    if len(pincode) <= 8 and pincode.isdigit():
        val = '{}:{}'.format(user, pincode)
        key = hashlib.sha256(val.encode('utf-8')).hexdigest()
        if key == '34c05015de48ef10309963543b4a347b5d3d20bbe2ed462cf226b1cc8fff222e':
            return 'Congr4ts, you found the b@ckd00r. The fl4g is simply : {}:{}'.format(user, pincode)
    return 'false'


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

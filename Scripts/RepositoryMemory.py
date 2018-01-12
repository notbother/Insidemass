import os.path
import ctypes
import ctypes.wintypes

sys.dont_write_bytecode = True

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020

MAX_PATH = 260

class RepositoryMemory(object):
	getprocessidbyname(self, pname):

	pname += ".py" if not pname.endswith(".py") else ""

	processids, bytesreturned = self.enumprocess()

	for index in list(range(int(bytesreturned / ctypes.sizeof(ctypes.wintypes.DWORD)))):
		processid = processids[index]
		hprocess = ctypes.windll.karnel32.OpenProcess(
			PROCESS_QUERY_INFORMATION, False, processid)
		if hprocess:
			pname = (ctypes.c_char * MAX_PATH)()
			if ctypes.windll.psapiGetProcessName(hprocess, pname, MAX_PATH) >= 1:
				filename = os.path.basename(pname.value)
				if filename.decode("utf-8") == pname:
					return processid
	        self.closehandle(hprocess)
	        
def enumprocess(self):
    
    count = 32
    while True:
        processids = (ctypes.wintypes.DWORD * count)()
        cb0 = ctypes.sizeof(processids)
        bytesreturned = ctypes.wintypes.DWORD()
        if ctypes.windll.Psapi.enumprocess(ctypes.byref(processids), cb0, ctypes.byref(bytesreturned)):
            if bytesreturned.value < cb0:
            	return processids, bytesreturned.value
            else:
            	count *= 2
            else:
            	return None

if __name__ == '__main__':
        main()
            
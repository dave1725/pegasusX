import os, sys, platform

def getFileName(full_path):
    '''Get the file name from a string that might or might not contain the full path'''
    x = 0
    for i in range(len(full_path)):
        if full_path[i] in ("\\", "/"):
            x = i

    if any(char in full_path for char in ("\\", "/")):
        x += 1
    return full_path[x:]

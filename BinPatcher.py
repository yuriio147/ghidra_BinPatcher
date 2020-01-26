# Write memory back to a copy of the binary file
#@author yuriio
#@category Memory
#@keybinding ALT-SHIFT-P
#@menupath File.Run.Bin Patcher
#@toolbar BinPatcher.png

import shutil
import os
import platform
import subprocess


CREATE_NEW_FILE_FOR_EACH_PATCH = True
OPEN_FILE_LOCATION_AFTER_PATCH = True


def info(text):
    print "INFO: {}".format(text)


def error(text):
    print "ERROR: {}".format(text)


def warning(text):
    print "WARNING: {}".format(text)


def show_file(path):
    if platform.system() == "Windows":
        os.startfile(path)
    elif platform.system() == "Darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


def get_source_binary_path():
    path = os.path.abspath(str(currentProgram.getExecutablePath()))
    if path.startswith('\\'):
        path = path[1:]  # Windows
    if os.path.isfile(path):
        return path
    error("Invalid source binary path - {}".format(path))
    return None


def get_destination_binary_path():
    src_path = get_source_binary_path()
    path = None
    if not CREATE_NEW_FILE_FOR_EACH_PATCH:
        path = os.path.abspath(str(askFile("Select output file name", "Save changes")))
    else:
        name, extension = os.path.splitext(src_path)
        path = "{}_patched{}".format(name, extension)
    if os.path.isfile(path):
        os.remove(path)
    shutil.copy(src_path, path)
    return path


def find_addresses_to_patch(memory, min_addr, max_addr):
    mem_blocks = memory.getBlocks()
    bytes_to_patch = []
    for block in mem_blocks:
        block_name = block.getName()
        block_start_addr = block.getStart()
        block_end_addr = block.getEnd()
        block_size = block_end_addr.getOffset() - block_start_addr.getOffset()
        info("Cheking {} block({}-{})...".format(block_name,
                                                 block_start_addr,
                                                 block_end_addr))
        if not block.isInitialized():
            warning("Block {} is uninitialized!".format(block_name))
            continue
        for displacement in range(0, block_size, 16):
            addr16 = block_start_addr.addNoWrap(displacement)
            for i in range(16):
                addr = addr16.addNoWrap(i)
                # A byte is always signed in Java
                current_value = memory.getByte(addr) & 0xFF
                source_info = memory.getAddressSourceInfo(addr)
                # A byte is always signed in Java
                original_value = source_info.getOriginalValue() & 0xFF
                if current_value != original_value:
                    patch_info = {
                        'offset': source_info.getFileOffset(),
                        'data': bytearray([current_value])
                    }
                    bytes_to_patch.append(patch_info)
                    pattern = "source value: {}; new value: {}; address: {}"
                    byte_info = pattern.format(hex(original_value),
                                               hex(current_value),
                                               addr)
                    info("Found a byte to patch ({})".format(byte_info))
    return bytes_to_patch


def patch_binary(patch_data, binary_path):
    info("Patching copied file {}".format(binary_path))
    with open(binary_path, "rb+") as f:
        for patch in patch_data:
            f.seek(patch['offset'])
            f.write(patch['data'])


def main():
    source_bin_path = get_source_binary_path()
    dest_bin_path = get_destination_binary_path()
    info("Source binary: {}".format(source_bin_path))
    info("Destination binary: {}".format(dest_bin_path))

    memory = currentProgram.getMemory()
    start = currentProgram.getMinAddress()
    end = currentProgram.getMaxAddress()

    patch_data = find_addresses_to_patch(memory, start, end)
    if len(patch_data) == 0:
        warning("Nothing to patch!")
        return
    patch_binary(patch_data, dest_bin_path)
    show_file(dest_bin_path)


main()

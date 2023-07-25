import re

def extract_syscalls(records):
    syscalls = []

    for record in records:
        match = re.search(r'(.+?)(?=\()', record)
        if match:
            syscalls.append(match.group(1))

    return syscalls

if __name__ == '__main__':
    with open('nginx.txt', 'r') as input_file:
        records = input_file.read().splitlines()

    syscalls = extract_syscalls(records)
    unique_syscall = set(syscalls)

    with open('nginxSyscall.txt', 'w') as output_file:
        for syscall in unique_syscall:
            output_file.write(syscall+'\n')

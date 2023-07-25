import re

def extract_syscalls(records):
    syscalls = []
    syscall_pattern = r'(\w+)\((.*?)\) = -1 (\w+) \((.*?)\)'

    for record in records:
        match = re.search(syscall_pattern, record)
        if match:
            syscall = {
                'syscall_name': match.group(1),
                'args': match.group(2),
                'error_code': match.group(3),
                'error_message': match.group(4)
            }
            syscalls.append(syscall)

    return syscalls

if __name__ == '__main__':
    with open('input.txt', 'r') as input_file:
        records = input_file.read().splitlines()

    syscalls = extract_syscalls(records)

    with open('output.txt', 'w') as output_file:
        for syscall in syscalls:
            output_file.write(f'Syscall: {syscall["syscall_name"]}\n')
            output_file.write(f'Arguments: {syscall["args"]}\n')
            output_file.write(f'Error Code: {syscall["error_code"]}\n')
            output_file.write(f'Error Message: {syscall["error_message"]}\n\n')


# TODO experimental
def read_file_bytes_pattern(file_path):
    with open(file_path, "rb") as read_file:
        file_bytes = read_file.read()
        return {i: hex(file_bytes[i]) for i in range(len(file_bytes))}


# TODO experimental
def compare_byte_pattern(check, reference):
    if (len(check) >= len(reference)):
        ref_copy = reference.copy()
        for key, value in reference.items():
            if key not in check or check[key] != reference[key]:
                ref_copy.pop(key)
        return ref_copy
    else:
        check_copy = check.copy()
        for key, value in check.items():
            if key not in reference or check[key] != reference[key]:
                check_copy.pop(key)
        return check_copy


# def check_byte_pattern_nested(check_pattern, existing_patterns):
#     next_patterns = set(existing_patterns)
#     patterns_updated = False
#     for pattern in existing_patterns:
#         start_found = False
#         end_found = False

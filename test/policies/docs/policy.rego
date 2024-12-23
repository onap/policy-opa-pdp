package docs

import rego.v1

default allow := false

allow if {
    has_access_to_file
    action_is_read_or_write
}

action_is_read_or_write if {
    input.action in ["read", "write"]
}

has_access_to_file contains file_info if {
    some file in data.docs.files
    file.file_id == input.file_id
    file.access_level == input.access_level
    file_info := {attr: file[attr] | attr in input.attributes}
}


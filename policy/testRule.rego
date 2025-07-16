package main

# Deny if key contains 'secret' and value is not encrypted

deny contains msg if {
    some k
    val := input[k]
    lower_key := lower(k)
    contains(lower_key, "secret")
    not startswith(val, "![")
    msg := sprintf("Key '%s' must start with '![...'", [k])
}

deny contains msg if {
    some k
    val := input[k]
    lower_key := lower(k)
    contains(lower_key, "secret")
    not endswith(val, "]")
    msg := sprintf("Key '%s' must end with ']'", [k])
}

# Deny if key contains 'password' and value is not encrypted
deny contains msg if {
    some k
    val := input[k]
    lower_key := lower(k)
    contains(lower_key, "password")
    not startswith(val, "![")
    msg := sprintf("Key '%s' must start with '![...'", [k])
}

deny contains msg if {
    some k
    val := input[k]
    lower_key := lower(k)
    contains(lower_key, "password")
    not endswith(val, "]")
    msg := sprintf("Key '%s' must end with ']'", [k])
}

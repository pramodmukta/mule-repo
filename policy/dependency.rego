package main

# Set of deprecated versions
deprecated_versions = {
    "1.10.3",
    "1.2.5",
    "1.7.4"
}

# Deny if any connector is using a deprecated version
deny contains msg if {
    some k
    version := input[k]
    version == deprecated_versions[_]
    msg := sprintf("Connector '%s' is using deprecated version '%s'", [k, version])
}

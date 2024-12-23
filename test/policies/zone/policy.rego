package zone

import rego.v1

default allow := false

allow if {
    has_zone_access
    action_is_log_view
}

action_is_log_view if {
    "view" in input.actions
}

has_zone_access contains access_data if {
    some zone_data in data.zone.zone.zone_access_logs
    zone_data.timestamp >= input.time_period.from
    zone_data.timestamp < input.time_period.to
    zone_data.zone_id == input.zone_id
    access_data := {datatype: zone_data[datatype] | datatype in input.datatypes}
}


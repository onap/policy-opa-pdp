package vehicle

import  rego.v1

default allow := false

allow if {
    user_has_vehicle_access
    action_is_granted
}

action_is_granted if {
    "use" in input.actions
}

user_has_vehicle_access contains vehicle_data if {
    some vehicle in data.vehicle.vehicles
    vehicle.vehicle_id == input.vehicle_id
    vehicle.owner == input.user
    vehicle_data := {info: vehicle[info] | info in input.attributes}
}



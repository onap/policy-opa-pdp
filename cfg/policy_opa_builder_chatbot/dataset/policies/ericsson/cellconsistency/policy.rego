package cell.consistency
import rego.v1
default allow = false
# Rule to check cell consistency
check_cell_consistency if {
    input.SubNetwork.MeContext.ManagedElement.vsDataGNBDUFunction.vsDataNRCellDU.ID != data.node.cell.consistency.allowedCellId
}
# Rule to allow if PCI is within range 1-3000
allow_if_pci_in_range  if {
    input.SubNetwork.MeContext.ManagedElement.vsDataGNBDUFunction.vsDataNRCellDU.nRPCI
 >= data.node.cellconsistency.minPCI
    input.SubNetwork.MeContext.ManagedElement.vsDataGNBDUFunction.vsDataNRCellDU.nRPCI
 <= data.node.cellconsistency.maxPCI
}
# Main rule to determine the final decision
allow  if{
    check_cell_consistency
    allow_if_pci_in_range
}
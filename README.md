# Open5GS E2E Core

## Overview

A customized Open5GS 2.7.2 implementation for private end-to-end testing and vendor NF compatibility validation.
<img width="1179" height="676" alt="image" src="https://github.com/user-attachments/assets/5949a455-f3c1-40e6-a407-e78123ea9944" />


## Description of what this customization does

- **Multi-Vendor Compatibility**: Enhanced modifications for interoperability testing with different vendor NFs
- **E2E PDU Session Testing**: Basic end-to-end PDU session establishment validation
- **QoS Flow Testing**: Non-GBR QoS rule verification and GBR QoS flow simulation
- **Network Selection Validation**: Core network signaling selection across different DNNs, slices, and tracking areas
- **MEC Workflow Simulation**: Basic Multi-access Edge Computing workflow testing

## Testing Scenarios

- PDU session establishment procedures
- Non-GBR and GBR QoS flow validation
- DNN-based routing and network slice selection
- Location-based signaling and tracking area management
- Basic MEC workflow integration (Edge UPF project involved for QoS management)

## Installation

Based on Open5GS 2.7.2. Follow the standard Open5GS compilation and installation process:

```bash
git clone https://github.com/timyl/open5gs_e2e_core.git
cd open5gs_e2e_core
```

Refer to [official Open5GS documentation](https://open5gs.org/open5gs/docs/) for detailed build instructions.

## Related Projects

- **open5gs_e2e_edge**: Edge UPF functionality for distributed MEC scenarios

## License

GNU Affero General Public License v3.0 (GNU AGPL v3.0)

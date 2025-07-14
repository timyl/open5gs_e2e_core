Overview
Open5GS E2E Core is a customized implementation based on Open5GS 2.7.2, specifically designed for private end-to-end testing scenarios. This repository provides enhanced compatibility testing capabilities for integrating with various vendor Network Functions (NFs) and validates core 5G functionalities including PDU session establishment, QoS flow management, and Multi-access Edge Computing (MEC) workflows.
Key Features

Private E2E Testing Framework: Tailored for internal testing and validation purposes
Multi-Vendor Compatibility: Enhanced code modifications to support interoperability testing with different vendor NFs
PDU Session Validation: Comprehensive testing of basic end-to-end PDU session establishment procedures
QoS Flow Testing: Support for both Non-GBR and simulated GBR QoS flow scenarios
Network Slice Testing: Validation of core network signaling selection across different DNNs, slices, and tracking areas
MEC Workflow Simulation: Basic Multi-access Edge Computing workflow testing capabilities

Architecture
This project implements a complete 5G Core Network with the following components:

AMF (Access and Mobility Management Function): Handles registration, connection, and mobility management
AUSF (Authentication Server Function): Manages authentication procedures
UDM (Unified Data Management): Provides unified data management capabilities
NSSF (Network Slice Selection Function): Enables network slice selection
SMF (Session Management Function): Manages PDU sessions
UPF (User Plane Function): Handles user plane traffic forwarding

Testing Scenarios
Core Functionality Testing

PDU Session Establishment: End-to-end validation of PDU session setup procedures
Non-GBR QoS Rules: Basic Non-Guaranteed Bit Rate QoS rule verification and validation
GBR QoS Flow Simulation: Testing scenarios for Guaranteed Bit Rate QoS flows

Network Selection and Routing

DNN-based Routing: Validation of Data Network Name selection and routing logic
Network Slice Selection: Testing slice selection mechanisms across different network slices
Tracking Area Management: Verification of location-based signaling selection and tracking area procedures

Edge Computing Integration

MEC Workflow Simulation: Basic Multi-access Edge Computing workflow testing and validation
Edge UPF Integration: Compatible with edge UPF deployments for distributed computing scenarios

Vendor Interoperability

Multi-Vendor NF Testing: Enhanced compatibility testing with various vendor Network Functions
Protocol Compliance: Validation of standard compliance across different vendor implementations

Version Information
This project is based on Open5GS version 2.7.2 with custom modifications for enhanced testing capabilities and vendor compatibility.
Getting Started
Prerequisites

Ubuntu 20.04 or later
Dependencies as specified in the original Open5GS project
Git
Basic understanding of 5G Core Network architecture

Installation
This project follows the standard Open5GS compilation and installation process. Please refer to the official Open5GS documentation and website for detailed installation instructions.
bash# Clone the repository
git clone https://github.com/timyl/open5gs_e2e_core.git
cd open5gs_e2e_core

# Follow the official Open5GS installation guide
# https://open5gs.org/open5gs/docs/guide/01-quickstart/
Note: For complete build and installation instructions, please refer to:

Official Open5GS Documentation
Open5GS GitHub Repository

Related Projects

open5gs_e2e_edge: Companion project providing edge UPF functionality for distributed MEC scenarios
Open5GS: The upstream open-source 5G Core Network implementation (base version 2.7.2)

License
This project is licensed under the GNU Affero General Public License v3.0 (GNU AGPL v3.0), maintaining compatibility with the upstream Open5GS project.
Contributing
This is primarily a private testing repository. For contributions to the base Open5GS project, please refer to the upstream repository.
Support
For technical support regarding the base Open5GS functionality, please refer to the official Open5GS community resources and documentation at open5gs.org.

This project is based on Open5GS 2.7.2 - an open-source implementation of 5G Core and EPC networks.

# External validation inputs

The repository includes only the generated feature-compatible window files used
by the fixed-threshold diagnostic transfer checks:

- `external/processed/cicddos2019_windows.csv`
- `external/processed/iot23_binary_windows.csv`
- `external/processed/iot23_ddos_only_windows.csv`
- `external/processed/toniot_binary_windows.csv`
- `external/processed/toniot_ddos_dos_windows.csv`

The source datasets remain governed by their publishers' terms and are not
redistributed here. Obtain the original data from:

- CIC-DDoS2019: https://www.unb.ca/cic/datasets/ddos-2019.html
- IoT-23: https://www.stratosphereips.org/datasets-iot23
- TON_IoT: https://research.unsw.edu.au/projects/toniot-datasets

These adapters map public columns into the frozen eight-feature interface. The
resulting evaluation is explicitly diagnostic feature-compatible transfer: it
does not claim that external flow features have identical semantics to live OVS
controller counters, and no target labels were used to select the transferred
threshold.

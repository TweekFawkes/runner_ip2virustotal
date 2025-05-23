# IP to VirusTotal Lookup Tool

A Python script that queries IP addresses for threat intelligence using the VirusTotal API.

## Overview

This tool allows you to quickly check IP addresses against VirusTotal's comprehensive threat intelligence database. It provides detailed information about IP reputation, malicious detections, community votes, and associated threat classifications.

## Features

- **IP Address Validation**: Supports both IPv4 and IPv6 addresses
- **Comprehensive Reporting**: Shows reputation scores, detection ratios, and malicious classifications
- **Community Insights**: Displays VirusTotal community votes and analysis statistics
- **Flexible Output**: Choose between formatted reports or raw JSON output
- **Error Handling**: Graceful handling of API errors and invalid inputs

## Installation

1. Clone this repository or download the `app.py` file
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

Or install the VirusTotal library directly:

```bash
pip install vt-py
```

## Getting a VirusTotal API Key

1. Visit [VirusTotal](https://www.virustotal.com) and create a free account
2. Log in and navigate to your profile settings
3. Find your API key in the API Key section
4. Copy the API key for use with this tool

**Note**: Free accounts have a limit of 500 API requests per day.

## Usage

### Basic Usage

```bash
python app.py <IP_ADDRESS>
```

### With API Key as Argument

```bash
python app.py <IP_ADDRESS> --api-key YOUR_API_KEY
```

### Using Environment Variable

Set your API key as an environment variable:

```bash
# Linux/macOS
export VT_API_KEY="your_api_key_here"

# Windows (PowerShell)
$env:VT_API_KEY="your_api_key_here"

# Windows (Command Prompt)
set VT_API_KEY=your_api_key_here
```

Then run:

```bash
python app.py <IP_ADDRESS>
```

### Raw JSON Output

To get the raw JSON response from VirusTotal:

```bash
python app.py <IP_ADDRESS> --raw
```

## Examples

### Check a suspicious IP address:

```bash
python app.py 192.168.1.1
```

### Check with API key specified:

```bash
python app.py 8.8.8.8 --api-key your_vt_api_key
```

### Get raw JSON output:

```bash
python app.py 1.1.1.1 --raw
```

## Output Information

The tool provides the following information about each IP address:

- **General Information**: IP address, type, country, ASN, and AS owner
- **Network Details**: Network range and regional internet registry
- **Reputation Score**: VirusTotal community reputation score
- **Analysis Results**: Statistics from security vendors (harmless, malicious, suspicious, etc.)
- **Detection Ratio**: Number of security engines that flagged the IP as malicious
- **Malicious Detections**: Specific threat classifications from security vendors
- **Community Votes**: Harmless vs malicious votes from the VirusTotal community
- **Last Analysis Date**: When the IP was last analyzed

## Command Line Options

- `ip_address`: The IP address to lookup (required)
- `--api-key`: Your VirusTotal API key (optional if using environment variable)
- `--raw`: Output raw JSON response instead of formatted report
- `--help`: Show help message and exit

## Error Handling

The tool handles various error conditions:

- **Invalid IP addresses**: Validates IPv4 and IPv6 format before querying
- **Missing API key**: Clear error message with instructions to obtain one
- **API errors**: Specific VirusTotal API error messages
- **Network issues**: General connection and request errors

## API Rate Limits

VirusTotal's free tier includes:
- 500 requests per day
- 4 requests per minute

The tool does not implement rate limiting, so be mindful of these limits when making multiple requests.

## Dependencies

- **vt-py**: Official VirusTotal Python client library
- **Python 3.6+**: Required for the script to run

## Security Considerations

- Keep your API key secure and never commit it to version control
- Use environment variables or secure configuration management for API keys
- Be aware that IP lookups may be logged by VirusTotal

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve this tool.

## License

This project is provided as-is for educational and security research purposes.

## Acknowledgments

- [VirusTotal](https://www.virustotal.com) for providing the threat intelligence API
- [vt-py](https://github.com/VirusTotal/vt-py) - The official VirusTotal Python client library


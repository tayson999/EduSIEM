"""
PHASE 1: LOG PARSING MODULE
============================
Learn how to extract structured data from raw logs.

Key Concepts:
- Regular expressions (regex) to match patterns.
- Extracting fields: timestamp, IP, action, status.
- Handling multiple log formats (Apache, SSH, Windows).
"""

import re
from datetime import datetime
from typing import List, Dict, Optional

class LogParser:
    """Base class for parsing different log formats."""
    
    def parse(self, line: str) -> Optional[Dict]:
        """
        Parse a single log line.
        
        Args:
            line: Raw log line string.
        
        Returns:
            Dictionary with structured fields, or None if parse fails.
        """
        raise NotImplementedError


class ApacheAccessLogParser(LogParser):
    """
    Parser for Apache HTTP server access logs.
    
    Typical format:
    192.168.1.10 - - [05/Dec/2025:14:32:10 +0000] "GET /index.html HTTP/1.1" 200 1234
    """
    
    # Regex pattern for Apache combined/common log format
    PATTERN = re.compile(
        r'(?P<ip>[\d.]+)\s+'           # IP address
        r'(?P<ident>[\w.-]+)\s+'         # Ident (usually -)
        r'(?P<user>[\w.-]+)\s+'          # Username (usually -)
        r'\[(?P<timestamp>[^\]]+)\]\s+'  # Timestamp
        r'"(?P<request>[^"]*)"\s+'       # HTTP request line
        r'(?P<status>\d+)\s+'            # HTTP status code
        r'(?P<size>\d+|\-)'              # Response size
    )
    
    def parse(self, line: str) -> Optional[Dict]:
        """Parse an Apache access log line."""
        match = self.PATTERN.match(line)
        if not match:
            return None
        
        groups = match.groupdict()
        
        # Extract HTTP method and path from request
        request_parts = groups['request'].split()
        method = request_parts[0] if len(request_parts) > 0 else "UNKNOWN"
        path = request_parts[1] if len(request_parts) > 1 else "/"
        
        return {
            'source_ip': groups['ip'],
            'user': groups['user'] if groups['user'] != '-' else None,
            'timestamp': self._parse_timestamp(groups['timestamp']),
            'method': method,
            'path': path,
            'status': int(groups['status']),
            'bytes_sent': int(groups['size']) if groups['size'] != '-' else 0,
            'log_type': 'apache_access'
        }
    
    @staticmethod
    def _parse_timestamp(timestamp_str: str) -> datetime:
        """Parse Apache timestamp format: 05/Dec/2025:14:32:10 +0000"""
        try:
            return datetime.strptime(timestamp_str.split()[0], '%d/%b/%Y:%H:%M:%S')
        except ValueError:
            return datetime.now()


class SSHAuthLogParser(LogParser):
    """
    Parser for SSH authentication logs (typically /var/log/auth.log on Linux).
    
    Typical formats:
    Dec  5 14:32:10 server sshd[1234]: Failed password for user from 192.168.1.10 port 54321 ssh2
    Dec  5 14:32:15 server sshd[1235]: Accepted publickey for admin from 192.168.1.5 port 54322 ssh2
    """
    
    PATTERN_FAILED = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+'
        r'(?P<hostname>\S+)\s+'
        r'sshd\[(?P<pid>\d+)\]:\s+'
        r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<source_ip>[\d.]+) port (?P<port>\d+)'
    )
    
    PATTERN_ACCEPTED = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+'
        r'(?P<hostname>\S+)\s+'
        r'sshd\[(?P<pid>\d+)\]:\s+'
        r'Accepted (?P<auth_type>\S+) for (?P<user>\S+) from (?P<source_ip>[\d.]+) port (?P<port>\d+)'
    )
    
    def parse(self, line: str) -> Optional[Dict]:
        """Parse an SSH authentication log line."""
        
        # Try matching failed login
        match = self.PATTERN_FAILED.match(line)
        if match:
            groups = match.groupdict()
            return {
                'timestamp': self._parse_timestamp(groups['timestamp']),
                'hostname': groups['hostname'],
                'user': groups['user'],
                'source_ip': groups['source_ip'],
                'port': int(groups['port']),
                'action': 'failed_login',
                'auth_type': None,
                'log_type': 'ssh_auth'
            }
        
        # Try matching accepted login
        match = self.PATTERN_ACCEPTED.match(line)
        if match:
            groups = match.groupdict()
            return {
                'timestamp': self._parse_timestamp(groups['timestamp']),
                'hostname': groups['hostname'],
                'user': groups['user'],
                'source_ip': groups['source_ip'],
                'port': int(groups['port']),
                'action': 'accepted_login',
                'auth_type': groups['auth_type'],
                'log_type': 'ssh_auth'
            }
        
        return None
    
    @staticmethod
    def _parse_timestamp(timestamp_str: str) -> datetime:
        """Parse SSH log timestamp (assumes current year)."""
        try:
            return datetime.strptime(timestamp_str, '%b %d %H:%M:%S')
        except ValueError:
            return datetime.now()


class WindowsEventLogParser(LogParser):
    """
    Parser for Windows Event Log entries (simplified CSV format).
    
    Typical format:
    2025-12-05 14:32:10,4625,Failure Reason Code: User logon with misspelled or bad password,192.168.1.50,Administrator
    """
    
    PATTERN = re.compile(
        r'(?P<timestamp>[\d\-]+\s+[\d:]+),'
        r'(?P<event_id>\d+),'
        r'"(?P<description>[^"]+)",'
        r'(?P<source_ip>[\d.]+),'
        r'(?P<account>\S+)'
    )
    
    def parse(self, line: str) -> Optional[Dict]:
        """Parse a Windows Event Log line."""
        match = self.PATTERN.match(line)
        if not match:
            return None
        
        groups = match.groupdict()
        event_id = int(groups['event_id'])
        
        # Map common Windows event IDs to actions
        action_map = {
            4625: 'failed_login',
            4624: 'successful_login',
            4688: 'process_creation',
            4697: 'service_installed',
        }
        
        return {
            'timestamp': datetime.strptime(groups['timestamp'], '%Y-%m-%d %H:%M:%S'),
            'event_id': event_id,
            'description': groups['description'],
            'source_ip': groups['source_ip'],
            'account': groups['account'],
            'action': action_map.get(event_id, 'unknown'),
            'log_type': 'windows_event'
        }


class LogParserFactory:
    """Factory to select the right parser based on log type."""
    
    PARSERS = {
        'apache': ApacheAccessLogParser,
        'ssh': SSHAuthLogParser,
        'windows': WindowsEventLogParser,
    }
    
    @classmethod
    def get_parser(cls, log_type: str) -> LogParser:
        """Get a parser instance for the given log type."""
        parser_class = cls.PARSERS.get(log_type.lower())
        if not parser_class:
            raise ValueError(f"Unknown log type: {log_type}")
        return parser_class()
    
    @classmethod
    def parse_file(cls, filepath: str, log_type: str) -> List[Dict]:
        """
        Parse all lines in a log file.
        
        Args:
            filepath: Path to log file.
            log_type: Type of log (apache, ssh, windows).
        
        Returns:
            List of parsed log entries (dictionaries).
        """
        parser = cls.get_parser(log_type)
        entries = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parsed = parser.parse(line)
                    if parsed:
                        entries.append(parsed)
                    # Optionally log unparsed lines for debugging
                    # else:
                    #     print(f"Warning: Could not parse line {line_num}: {line}")
        except FileNotFoundError:
            print(f"Error: Log file not found: {filepath}")
        
        return entries


if __name__ == "__main__":
    # Example usage
    print("=== Apache Log Parser Example ===")
    apache_line = '192.168.1.10 - - [05/Dec/2025:14:32:10 +0000] "GET /index.html HTTP/1.1" 200 1234'
    parser = ApacheAccessLogParser()
    result = parser.parse(apache_line)
    print(f"Parsed: {result}\n")
    
    print("=== SSH Log Parser Example ===")
    ssh_line = 'Dec  5 14:32:10 server sshd[1234]: Failed password for user from 192.168.1.10 port 54321 ssh2'
    parser = SSHAuthLogParser()
    result = parser.parse(ssh_line)
    print(f"Parsed: {result}\n")
    
    print("=== Windows Event Log Parser Example ===")
    windows_line = '2025-12-05 14:32:10,4625,Failure Reason Code: User logon with misspelled or bad password,192.168.1.50,Administrator'
    parser = WindowsEventLogParser()
    result = parser.parse(windows_line)
    print(f"Parsed: {result}")

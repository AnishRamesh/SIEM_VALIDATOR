export function getXqlQuery(rule: { ruleId?: string; ruleName?: string; existingTid?: string; suggestedTid?: string } | null | undefined): string {
  if (!rule) return "";

  const ruleId = rule.ruleId || "";
  const ruleName = rule.ruleName || "";
  const tid = rule.existingTid || rule.suggestedTid || "T1018";

  // Static maps for core templates
  const staticXql: Record<string, string> = {
    'RULE-001': `dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_name = "lsass.exe" 
| filter action_process_image_command_line contains "mini-dump" or actor_process_image_name in ("rundll32.exe", "procdump.exe")
| fields _time, actor_process_image_path, actor_process_image_command_line, target_process_name`,

    'RULE-002': `dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "powershell.exe" and (action_process_image_command_line contains "-enc" or action_process_image_command_line contains "-encodedcommand" or action_process_image_command_line contains "-noni" or action_process_image_command_line contains "bypass")
| fields _time, host_name, actor_process_image_name, action_process_image_command_line`,

    'RULE-003': `dataset = xdr_data
| filter event_type = REGISTRY
| filter action_registry_key_name contains "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" or action_registry_key_name contains "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce" or action_registry_key_name contains "SYSTEM\\\\CurrentControlSet\\\\Services"
| fields _time, host_name, action_registry_key_name, action_registry_value_name, actor_process_image_name`,

    'RULE-004': `dataset = xdr_data
| filter event_type = NETWORK
| filter (local_port = 3389 or remote_port = 3389) and (action_process_image_name = "ssh.exe" or action_process_image_name = "plink.exe" or action_process_image_name = "putty.exe")
| fields _time, host_name, local_ip, remote_ip, local_port`,

    'RULE-005': `dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_name = "lsass.exe" and (action_process_image_command_line contains ".dmp" or actor_process_image_name = "rundll32.exe" or action_process_image_command_line contains "comsvcs")
| fields _time, host_name, actor_process_image_name, action_process_image_command_line`,

    'RULE-006': `dataset = xdr_data
| filter event_type = PROCESS
| filter actor_process_image_name = "WmiPrvSE.exe" and (action_process_image_name in ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"))
| fields _time, host_name, actor_process_image_name, action_process_image_command_line`,

    'RULE-007': `dataset = xdr_data
| filter event_type = AUTHENTICATION
| filter auth_result = SUCCESS and auth_type = DOMAIN
| stats unique_user_count = count_distinct(user_name) by host_name
| filter unique_user_count >= 5
| fields host_name, unique_user_count`,

    'RULE-008': `dataset = xdr_data
| filter event_type = NETWORK
| stats port_scanned = count_distinct(remote_port) by host_name, remote_ip
| filter port_scanned >= 100
| fields host_name, remote_ip, port_scanned`,

    'RULE-009': `dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("torrent.exe", "utorrent.exe", "qbittorrent.exe") or action_process_image_command_line contains "metasploit" or action_process_image_command_line contains "nmap"
| fields _time, host_name, actor_process_image_name, action_process_image_command_line`,

    'RULE-010': `dataset = xdr_data
| filter event_type = AUTHENTICATION
| filter auth_result = FAIL and auth_method = PASSWORD
| stats auth_failures = count(auth_result) by host_name, user_name, remote_ip
| filter auth_failures >= 30
| fields host_name, user_name, remote_ip, auth_failures`,

    'RULE-011': `dataset = xdr_data
| filter event_type = AUTHENTICATION
| filter auth_type = DATABASE and auth_result = SUCCESS
| stats db_connections = count(auth_result) by host_name, user_name, client_ip
| filter db_connections >= 50
| fields host_name, user_name, client_ip, db_connections`,

    'RULE-012': `dataset = xdr_data
| filter event_type = NETWORK
| filter destination_domain_name contains "proxy" or destination_domain_name contains "tunnel" or destination_domain_name contains "ngrok" or destination_domain_name contains "localtunnel"
| fields _time, host_name, local_ip, destination_domain_name`,

    'RULE-013': `dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "schtasks.exe" and (action_process_image_command_line contains "/create" or action_process_image_command_line contains "/run") and (actor_process_image_name = "sc.exe" or actor_process_image_name = "cmd.exe")
| fields _time, host_name, actor_process_image_name, action_process_image_command_line`,

    'RULE-014': `dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("wevtutil.exe", "powershell.exe") and (action_process_image_command_line contains "cl " or action_process_image_command_line contains "clear-log" or action_process_image_command_line contains "Clear-EventLog")
| fields _time, host_name, actor_process_image_name, action_process_image_command_line`,

    'RULE-015': `dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_path not contains "C:\\\\Windows\\\\System32" and action_process_image_path not contains "C:\\\\Program Files" and action_process_image_path contains "Temp"
| fields _time, host_name, actor_process_image_name, action_process_image_path`,

    'RULE-016': `dataset = xdr_data
| filter event_type = NETWORK
| filter destination_port = 88 and action_process_image_name = "powershell.exe" and action_process_image_command_line contains "Get-DomainSPNTicket"
| fields _time, host_name, actor_process_image_name, action_process_image_command_line`,

    'RULE-017': `dataset = xdr_data
| filter event_type = NETWORK
| filter destination_port = 5985 or destination_port = 5986
| fields _time, host_name, local_ip, remote_ip, destination_port`,

    'RULE-018': `dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "vssadmin.exe" and (action_process_image_command_line contains "delete" or action_process_image_command_line contains "shadows")
| fields _time, host_name, actor_process_image_name, action_process_image_command_line`,

    'RULE-019': `dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "rundll32.exe" and action_process_image_path not contains "C:\\\\Windows\\\\System32"
| fields _time, host_name, actor_process_image_name, action_process_image_path`,

    'RULE-020': `dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "net.exe" and (action_process_image_command_line contains "user /add" or action_process_image_command_line contains "localgroup administrators")
| fields _time, host_name, actor_process_image_name, action_process_image_command_line`,

    'RULE-021': `dataset = xdr_data
| filter event_type = DNS
| filter query_type = "TXT"
| stats txt_queries = count(query_name) by host_name, query_name
| filter txt_queries >= 200
| fields host_name, query_name, txt_queries`,

    'RULE-022': `dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_command_line contains "/suspended" or action_process_signature_status = "UNSIGNED"
| fields _time, host_name, actor_process_image_name, action_process_image_path`,

    'RULE-023': `dataset = xdr_data
| filter event_type = FILE
| filter file_extension = "aspx" or file_extension = "asp" or file_extension = "jsp" or file_extension = "php"
| filter file_parent_directory contains "inetpub\\\\wwwroot"
| fields _time, host_name, file_path, actor_process_image_name`,

    'RULE-024': `dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("7z.exe", "zip.exe", "tar.exe", "rar.exe") and (action_process_image_command_line contains "db" or action_process_image_command_line contains "backup" or action_process_image_command_line contains "sql")
| fields _time, host_name, actor_process_image_name, action_process_image_command_line`
  };

  if (staticXql[ruleId]) {
    return staticXql[ruleId];
  }

  // Procedural query generation based on the technique and rule title
  const lowerName = ruleName.toLowerCase();
  let filterStr = "";

  if (lowerName.includes("powershell")) {
    filterStr = `| filter action_process_image_name = "powershell.exe" and action_process_image_command_line contains "${tid}"`;
  } else if (lowerName.includes("registry") || lowerName.includes("key")) {
    filterStr = `| filter event_type = REGISTRY and action_registry_key_name contains "${tid}"`;
  } else if (lowerName.includes("file") || lowerName.includes("directory") || lowerName.includes("dll") || lowerName.includes("web shell")) {
    filterStr = `| filter event_type = FILE and file_path contains "${tid}"`;
  } else if (lowerName.includes("rdp") || lowerName.includes("network") || lowerName.includes("ip") || lowerName.includes("dns") || lowerName.includes("port") || lowerName.includes("tunnel")) {
    filterStr = `| filter event_type = NETWORK and destination_port in (80, 443, 3389, 22) \\n| filter action_process_image_command_line contains "${tid}"`;
  } else if (lowerName.includes("credentials") || lowerName.includes("lsass") || lowerName.includes("dump") || lowerName.includes("ticket") || lowerName.includes("auth")) {
    filterStr = `| filter event_type = AUTHENTICATION or event_type = PROCESS\\n| filter action_process_image_command_line contains "${tid}" or action_process_name = "lsass.exe"`;
  } else {
    filterStr = `| filter action_process_image_command_line contains "${tid}" or actor_process_image_name contains "${tid}"`;
  }

  return `dataset = xdr_data
| filter event_type in (PROCESS, NETWORK, FILE, REGISTRY)
${filterStr}
| fields _time, host_name, actor_process_image_name, action_process_image_command_line
| limit 100`;
}

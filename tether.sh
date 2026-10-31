#!/bin/bash
# =============================================================================
# tether - share this qube's internet with devices plugged into USB
#          Ethernet adapters and (optionally) USB Wi-Fi dongles acting as
#          access points. Everything joins one Linux bridge.
#          Version 1.0
#
#   tether status      adapters, clients, uplink, last log lines (works as a normal user)
#   tether install     packages + this script + /etc/tether.conf + the service, then start it
#   tether uninstall   remove everything install added
#   tether reload      check /etc/tether.conf, then restart the service to apply it
#   tether settings    edit /etc/tether.conf
#   tether reset       save /etc/tether.conf as .bak, write the defaults, then reload
#   tether log         view the log read-only in the editor (works as a normal user)
#
# How it fits together: one systemd service (tether-watch.service) runs
# "tether watch". That watcher builds the bridge and the firewall (nft tables
# "ip tether" and "bridge tether"), runs dnsmasq (DHCP/DNS) and hostapd (Wi-Fi)
# as its own child processes and checks every CHECK_EVERY seconds for adapters
# being plugged in or out. Stopping the service takes all of it down again.
# =============================================================================
# =============================================================================
# MAP OF THIS SCRIPT, version 1.0 (comments only; nothing here runs)
# =============================================================================
#
# WORKFLOW
#   tether install    -> installs packages, copies itself to /usr/bin/tether, writes
#                        /etc/tether.conf (if missing), installs + starts tether-watch.service
#   tether-watch.service runs "tether watch" (cmd_watch) as root at every boot. That one
#   process does all the work: bridge, firewall, dnsmasq child, one hostapd child per dongle.
#   The other commands only look (status, log) or edit the conf and restart the service
#   (settings, reload, reset). uninstall removes everything.
#
# FLOW OF THE WATCHER (cmd_watch)
#
#   start
#     |
#     v
#   watch_wait_for_conf: parse_conf /etc/tether.conf --errors in the top part--> log them,
#     |  (errors in a [device] block only skip that dongle)         write config-errors file,
#     |                                                             sleep 60, parse again
#     v
#   apply_parsed (PARSED -> CFG), log the notes, trap TERM/INT -> watch_exit
#     |
#     v
#   WIFI=1 ? wifi_cleanup_conf (drop stale non-sticky blocks)
#          : wifi_clear_conf   (remove all [device] blocks)
#     |
#     v
#   +-> watch_ensure_tether: tether_check ok? --no--> tether_up (bridge + sysctls +
#   |     |                    nft_apply + attach_adapters); new bridge: restart dnsmasq
#   |     | failed: watch_sleep RETRY_AFTER_FAIL, loop again
#   |     v
#   |   check_dnsmasq          (start/restart the dnsmasq child)
#   |   switch_cdmode_adapters (USB adapters in CD-ROM mode -> network mode)
#   |   wired_scan             (adapters plugged/unplugged, cable up/down)
#   |   check_uplink           (NetVM switched -> re-apply firewall)
#   |   wifi_scan (WIFI=1)     new dongle -> wifi_plugged -> wifi_start:
#   |     |                      wifi_pick_security, wifi_pick_band, pick_channel,
#   |     |                      write_hostapd_conf, wifi_launch (hostapd child)
#   |     |                    running -> wifi_check_running (died? plan a retry)
#   |     |                    failed  -> wifi_retry; gone -> wifi_unplugged
#   |   write_status           (status_lines -> /run/tether/status, for "tether status")
#   |     |
#   +-- watch_sleep CHECK_EVERY (TERM: watch_exit stops children, tether_down, exit)
#
# COMMANDS (main -> cmd_*)
#   status   any user     cmd_status   read_status, then status_overview, status_cables,
#                                      status_wifi, status_leases, status_counters (root), log
#   log      any user     cmd_log      editor -R +, or a read-only temp copy
#   install  root (sudo)  cmd_install  install_check_qube_type, install_packages,
#                                      install_files, install_service
#   settings root (sudo)  cmd_settings $EDITOR /etc/tether.conf
#   reload   root (sudo)  cmd_reload   parse_conf; errors -> nothing changes; else restart service
#   reset    root (sudo)  cmd_reset    .bak copy, write_default_conf, cmd_reload
#   uninstall root (sudo) cmd_uninstall
#   watch    root (only by the service)  cmd_watch
#
# FILES
#   /usr/bin/tether                    the installed program (this script)
#   /etc/tether.conf (root 0600)       settings + one [device]/[ap] block per Wi-Fi dongle
#                                      (holds Wi-Fi passwords); /etc/tether.conf.bak from reset
#   /etc/systemd/system/tether-watch.service   the service (unit_text)
#   /var/log/tether.log (0644)         log (LOG_FILE), readable by every user
#   /var/lib/tether/added-packages     packages install added (offered for removal by uninstall)
#   /run/tether/ (tmpfs)               runtime: status, config-errors, dnsmasq.conf,
#                                      dnsmasq.leases, nft.rules, hostapd-IFACE.conf/.out,
#                                      hostapd/ (ctrl sockets), dongles, ip_forward.orig
#   /lib/firmware/regulatory.db-upstream   regulatory.db used on Qubes kernels
#
# MAIN GLOBALS
#   SETTINGS_SPEC      "NAME|default|type" of every top setting
#   DEVICE_FIELDS      the [device]/[ap] keys with their defaults (fills the DEV_* arrays)
#   CFG[KEY]           active settings (loaded once by the watcher)
#   PARSED[KEY], PARSED_LINE[KEY]   parse result of the top part (values, line numbers)
#   CONF_LINES         the lines of the parsed file (for messages)
#   CONF_HIDDEN[N]     1 for a line in [ap] that is not KEY=value (line_text shows ***)
#   DEV_COUNT, DEV_START   number of [device] blocks, line of each; DEV_<KEY>[i] their values;
#   DEV_LINE["i.KEY"]  line of each device key; DEV_APS[i] number of [ap]; DEV_ERRS[i] errors
#   ERRS, TOP_ERRS, TOP_ERRS_PUBLIC, NOTES   all errors, top-part errors, the same for the
#                      config-errors file, notes
#   TOP_INVALID[KEY]   top settings whose own value is invalid (validate_top, top_keys_valid)
#   VALUE, VALUE_ERR, REASON   parse_value / check_value results
#   CONF_OUT           lines conf_write writes
#   W_STATE[iface]     running | failed | skipped | noap | nohostapd; W_PID, W_MAC, W_CHAN,
#                      W_BAND, W_SSID, W_SEC, W_RETRY, W_FAILS, W_ORIG, W_STARTED, W_NOSAE,
#                      W_NOREG: per-dongle runtime state (W_ARRAYS lists them for clean-up)
#   W_CUR_CHAN, W_CUR_SEC, W_CUR_BAND   results of pick_channel, wifi_pick_security,
#                      wifi_pick_band
#   WIRED_IFACES       result of wired_ifaces
#   SEEN, CABLE        wired adapters seen and their link state; CD_DONE switched CD-mode ones
#   DNSMASQ_PID, DNSMASQ_FAILS, DNSMASQ_WAIT_UNTIL, UPLINK_LAST, BRIDGE_NEW, SLEEP_PID
#   WIFI_DEL_LINES, WIFI_DEL_BLOCKS   lines/blocks that WIFI=0 removes (wifi_region)
#   EDITOR_CMD         editor chosen by pick_editor; INSTALL_ADDED packages install added
#
# SECTIONS AND FUNCTIONS (line numbers in this file)
#
#   Constants: where everything lives  (line 376)
#
#   Small helpers  (line 448)
#     449 say                         print a line to stdout
#     450 die                         print "tether: msg" to stderr and exit 1
#     451 ask                         ask a y/n question; true only for an answer starting with y/Y
#     452 have                        is this command installed?
#     454 trim                        strip leading/trailing whitespace
#     462 flag                        1 if the value is 1, else 0 (a setting as the 0/1 nft_opt and
#                                     hostapd expect)
#     465 alive                       is the pid a running (not zombie) process?
#     473 rand_str                    random string of N chars from a given set (uses SRANDOM)
#     480 rand_mac                    random locally administered unicast MAC
#     485 is_ip                       is it a dotted IPv4 address with each part <= 255?
#     490 ip2int                      IPv4 address -> 32-bit integer
#     495 is_cidr                     is it ADDRESS/PREFIX with prefix 0-32?
#     499 in_net                      is address $1 inside network $2?
#     504 is_mac                      is it aa:bb:cc:dd:ee:ff (any case)?
#     508 atomic_write                atomic_write MODE FILE CMD...: CMD's output to FILE.tmp, chmod
#                                     MODE, mv over FILE
#
#   Logging  (line 516)
#     519 log                         timestamped line to stdout (journal) and, with LOGGING=1,
#                                     LOG_FILE (reset past LOG_MAX_MB)
#     535 log_lines                   log every line read from stdin with a prefix (dnsmasq/hostapd
#                                     output)
#     538 try                         run a command; on failure log it with its error text and
#                                     return 1
#
#   Config file parser and validator - part 1: the parser  (line 547)
#     579 spec_type                   type of a top setting from SETTINGS_SPEC (fails for unknown
#                                     keys)
#     587 secret_word                 does a word look like a password key (PASS, PSK, SECRET,
#                                     TOKEN, any case)?
#     603 line_text                   line N of the parsed file without its trailing comment,
#                                     passwords shown as ***
#     623 add_note                    add a note (reload shows it, the watcher logs it; it stops
#                                     nothing)
#     626 add_error                   record an error "line N: text, reason" (globally or for device
#                                     i)
#     639 parse_value                 split the text after KEY= into VALUE (quotes removed);
#                                     VALUE_ERR if junk follows
#     657 parse_reset                 forget the last parse: clear all results, load the
#                                     SETTINGS_SPEC defaults
#     668 parse_conf                  read the whole conf line by line (parse_section_line /
#                                     parse_key_line), then validate
#     698 parse_section_line          a "[device]" or "[ap]" line: open a new device block or its
#                                     [ap] part
#     719 parse_key_line              a KEY=value line: check the key belongs where it is, store
#                                     value and line number
#     744 device_index                index of the [device] block for a factory MAC (-1 if none)
#     753 apply_parsed                copy the parsed top settings PARSED into the active CFG
#     756 reparse                     parse_conf "$CONF" quietly (callers only need the result)
#
#   Config file parser and validator - part 2: the validator (called by parse_conf)  (line 760)
#     762 check_value                 check one value against its type (bool, ip, lannet, ...); sets
#                                     REASON
#     812 top_keys_valid              are all the named top settings free of errors? (uses
#                                     TOP_INVALID)
#     815 validate_top                check every top setting plus the cross-checks (LAN_IP in
#                                     LAN_NET, DHCP range...)
#     857 validate_device             check one [device] block: calls the five validate_device_*
#                                     parts below
#     869 validate_device_mac         HARDWARE_MAC present, a valid MAC, not used by an earlier
#                                     block
#     886 validate_device_bools       STICKY, RANDOMIZE_MAC, HIDDEN are 0 or 1
#     896 validate_device_country     COUNTRY_CODE uppercased, 2 letters or 00; BAND=5 needs a real
#                                     one
#     912 validate_device_band        BAND against the hardware (if plugged in), CHANNEL against the
#                                     band
#     944 validate_device_ap          the [ap] part: present, SSID, SECURITY, password length
#
#   Writing /etc/tether.conf (always 0600 root: it holds the Wi-Fi passwords)  (line 967)
#     969 default_conf                text of a fresh /etc/tether.conf (used by install and reset)
#    1040 write_default_conf          write default_conf to $CONF as root 0600
#    1043 nonblank_len                length of an array (by name) without its trailing blank lines
#    1051 conf_write                  replace the conf atomically with the lines in CONF_OUT
#    1062 conf_remove_device          cut [device] block number i out of the conf
#    1075 new_ssid                    random unused SSID like AP_4821
#    1093 device_block                text of a new [device]+[ap] block for a dongle (random
#                                     SSID/password)
#    1123 conf_append_device          append a new device block (re-adds the Wi-Fi section header if
#                                     missing)
#
#   Hardware lookups (sysfs, iw, lsusb, ethtool)  (line 1137)
#    1140 driver_of                   kernel driver name of an interface
#    1141 is_skipped                  is its driver in SKIP_DRIVERS (phones sharing their own
#                                     internet)?
#    1142 phy_of                      wireless phy name (phy0...) of an interface
#    1143 bridge_of                   name of the bridge an interface is in ("" if none)
#    1148 wired_ifaces                fill WIRED_IFACES with the wired interfaces matching a pattern
#                                     (no Wi-Fi)
#    1158 usb_dir                     sysfs USB device directory behind an interface (fails if not
#                                     USB)
#    1170 usb_desc                    human description "Name (vid:pid, driver)"
#    1186 is_usb_wifi                 is it a wireless interface on USB?
#    1189 wifi_iface_for_mac          plugged-in Wi-Fi interface whose factory MAC is $1
#    1200 perm_mac                    factory MAC (ethtool -P, else ip permaddr, else the current
#                                     one)
#    1212 phy_supports_ap             does the phy list AP mode?
#    1220 band_supported              does the phy have an enabled channel in band 2.4 or 5?
#    1229 phy_has_sae                 can the phy run a WPA3 (SAE + CMAC) access point?
#
#   Bridge + firewall  (line 1238)
#    1251 remove_tagged_rules         delete our tagged rules from Qubes' custom-input chain
#    1261 nft_opt                     print an optional nft rule line only when its flag is 1
#    1264 nft_rules                   the full nft ruleset text for both tables, built from CFG
#    1335 nft_apply                   load the ruleset and add the tagged Qubes input rules (DHCP,
#                                     DNS, ping)
#    1351 qubes_accept                add one tagged accept rule for traffic from the bridge to
#                                     Qubes' custom-input
#    1356 tether_check                print what is missing (bridge, address, tables, rules,
#                                     ip_forward); 0 if nothing
#    1371 tether_up                   create/configure the bridge, sysctls, ip_forward, firewall,
#                                     attach adapters
#    1398 tether_down                 remove rules, tables, the bridge; adapters down; restore
#                                     ip_forward
#
#   Wired adapters  (line 1413)
#    1417 attach_adapters             put every matching, not-skipped wired adapter into the bridge
#    1432 switch_cdmode_adapters      send the usb_modeswitch message to adapters still in CD mode
#    1461 wired_scan                  log plug/unplug and cable up/down of wired adapters; attach
#                                     new ones
#
#   Uplink: this qube's address/gateway changes when the NetVM is switched  (line 1490)
#    1494 uplink_now                  "ADDRESS via GATEWAY" of UPLINK
#    1502 check_uplink                log uplink changes and re-apply the firewall when it changed
#
#   dnsmasq: child of the watcher, config in /run/tether  (line 1512)
#    1516 write_dnsmasq_conf          write /run/tether/dnsmasq.conf from CFG
#    1554 dnsmasq_wanted              is DHCP or DNS on (so dnsmasq is needed at all)?
#    1556 start_dnsmasq               start dnsmasq in the foreground as a child, output to the log
#    1565 stop_dnsmasq                stop our dnsmasq child
#    1570 check_dnsmasq               restart dnsmasq if it died (pause after 3 failures in a row)
#
#   Wi-Fi dongles: one hostapd child each, the AP joins the bridge (bridge=)  (line 1587)
#    1607 known_dongle                is this MAC in /run/tether/dongles (got a fresh block this
#                                     boot)?
#    1608 known_add                   add a MAC to /run/tether/dongles
#    1609 known_del                   remove a MAC from /run/tether/dongles
#    1612 wifi_skip                   log why a dongle is left alone and set its state to skipped
#    1614 wifi_fail                   set a dongle's state to failed, retry after RETRY_AFTER_FAIL
#    1616 wifi_no_wpa3                log once that a dongle can't do WPA3 and set W_NOSAE (use
#                                     wpa2)
#     - Wi-Fi: keeping the [device] blocks of the conf in step  (line 1621)
#    1626 wifi_cleanup_conf           at start: drop non-sticky blocks of dongles that are not
#                                     plugged in
#    1650 wifi_region                 find the conf lines WIFI=0 removes (all [device] blocks, also
#                                     broken ones)
#    1695 wifi_region_end_block       close the block wifi_region has open and record it (uses
#                                     wifi_region's locals)
#    1704 conf_drop_wifi_errs         with WIFI=0: forget errors on lines that are about to be
#                                     removed
#    1715 drop_msgs_on_deleted_lines  print the messages that are not on a line in WIFI_DEL_LINES
#    1725 wifi_clear_conf             at start with WIFI=0: stop leftover hostapd, remove every
#                                     [device] block
#     - Wi-Fi: starting and stopping access points  (line 1744)
#    1751 pick_channel                channel for a dongle: fixed, or the first free default of its
#                                     band (rotates on failures)
#    1775 country_applied             set the country with iw and check the kernel really took it
#                                     (global or per phy)
#    1790 wifi_start                  start one AP: security, band, channel, MAC, hostapd conf, then
#                                     wifi_launch
#    1812 wifi_pick_security          W_CUR_SEC: the configured security, or wpa2 when the dongle
#                                     can't do WPA3
#    1831 wifi_pick_band              W_CUR_BAND: the configured band, or 2.4 when the country did
#                                     not apply
#    1848 write_hostapd_conf          write /run/tether/hostapd-IFACE.conf (root 0600, holds the
#                                     password)
#    1881 hostapd_security            hostapd lines for wpa2 / wpa3 / wpa2+wpa3 / open
#    1895 wifi_launch                 run hostapd in the background (output to the log) and record
#                                     the dongle as running
#    1907 wifi_stop                   stop a dongle's hostapd, delete its files, restore its MAC
#    1917 wifi_stop_all               stop every dongle
#     - Wi-Fi: plug-in, unplug and the per-check scan  (line 1919)
#    1923 wifi_unplugged              dongle gone: stop it, drop its non-sticky block, forget its
#                                     state
#    1939 wifi_plugged                new dongle: check AP mode/hostapd, find or create its block,
#                                     start it
#    1985 wifi_scan                   each check: new dongles -> wifi_plugged, running ->
#                                     wifi_check_running, failed -> wifi_retry
#    2002 wifi_check_running          hostapd died? find out why (no WPA3, ...) and plan the retry
#    2027 wifi_retry                  wait over? start a failed dongle again from its current (re-
#                                     read) block
#
#   Status file: what "tether status" shows to a normal user (no secrets)  (line 2041)
#    2045 status_lines                the status file's text: KEY=value lines, then one WIFI_DONGLE
#                                     line per dongle
#    2065 write_status                write /run/tether/status (no secrets) atomically, for "tether
#                                     status" as a user
#    2069 read_status                 read the status file's KEY=value lines into an associative
#                                     array (by name)
#
#   The watcher (run by tether-watch.service; the only long-running part)  (line 2076)
#    2081 watch_exit                  TERM/INT handler: stop children, take the tether down, exit 0
#    2095 watch_sleep                 sleep in the background and wait for it, so the TERM trap runs
#                                     at once
#    2099 cmd_watch                   "tether watch": wait for a valid conf, then the main loop (see
#                                     the flow above)
#    2123 watch_wait_for_conf         parse the conf until its top part is valid (logs errors,
#                                     sleeps 60 s)
#    2140 watch_ensure_tether         tether_check, and tether_up if anything is missing; restarts
#                                     dnsmasq on a new bridge
#
#   tether status  (line 2156)
#    2160 cmd_status                  "tether status": on a config error only the errors, else the
#                                     status_* parts, then the last log lines
#    2192 status_overview             "== tether ==": service, watcher, uplink, bridge, dnsmasq
#
#    2213 status_cables               "== cable adapters ==": each matching adapter, its link and
#                                     bridge
#    2229 status_wifi                 "== Wi-Fi dongles ==" from the status file (root: also the
#                                     passwords)
#    2244 status_leases               "== clients ==": the DHCP leases
#    2255 status_counters             "== firewall counters ==": rules of our tables that matched a
#                                     packet (root)
#
#   install / uninstall / reload / settings - part 1: log, settings, reload, reset  (line 2261)
#    2267 pick_editor                 set EDITOR_CMD to $EDITOR, else vim, else vi (dies if none)
#    2276 cmd_log                     "tether log": open the log read-only in the editor, at the end
#    2303 cmd_settings                "tether settings": open the conf in $EDITOR (vim, vi)
#    2312 cmd_reload                  "tether reload": validate the conf, restart the service only
#                                     if it is valid
#    2337 cmd_reset                   "tether reset": ask, save conf as .bak, write defaults, reload
#
#   install / uninstall / reload / settings - part 2: install, uninstall  (line 2353)
#    2358 pkg_installed               is a Debian package installed?
#    2366 regdb_qubes                 Qubes kernel and the upstream regulatory.db exists?
#    2368 regdb_use_upstream          install: point the regulatory.db alternative at the upstream
#                                     file
#    2377 regdb_restore_auto          uninstall: set the regulatory.db alternative back to automatic
#    2384 unit_text                   text of tether-watch.service
#    2406 wait_for_bridge             wait up to 20 s for the watcher to bring the bridge up
#    2421 cmd_install                 "tether install": calls the four install_* parts below
#    2430 install_check_qube_type     AppVM/TemplateVM: ask first; other non-standalone types:
#                                     refuse
#    2452 install_packages            apt-get the missing APT_PKGS (recorded in INSTALL_ADDED), mask
#                                     hostapd.service, regdb
#    2478 install_files               package record, dnsmasq user, copy self to BIN, write the conf
#                                     if missing
#    2501 install_service             log file, systemd unit, start the service, wait for the bridge
#    2512 cmd_uninstall               "tether uninstall": stop and remove everything, offer to
#                                     remove added packages
#
#   Help and main  (line 2544)
#    2547 usage                       the --help text (mirrored in tether-help.txt)
#    2620 is_installed                are the program, the conf and the unit file there?
#    2623 need_root                   re-run the command through sudo (keeps EDITOR)
#    2632 main                        check the command, Qubes, installed, root; dispatch to
#                                     cmd_$cmd
#
# END OF MAP
# =============================================================================
set -uo pipefail
# iw, nft, dnsmasq, hostapd, usb_modeswitch live in sbin, which a normal user's PATH may lack
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# =============================================================================
# Constants: where everything lives
# =============================================================================
VERSION=1.0                            # shown in the first line of --help (no --version flag)
BIN=/usr/bin/tether                    # /usr/local: AppVMs never inherit it; sbin: not in user PATH
CONF=/etc/tether.conf
CONF_BAK=$CONF.bak                     # "tether reset" keeps the previous settings here (root 600)
UNIT=tether-watch.service
UNIT_FILE=/etc/systemd/system/$UNIT
RUN_DIR=/run/tether                    # runtime files; tmpfs, so gone after reboot
# non-secret state written by the watcher for "tether status" as a user
STATUS_FILE=$RUN_DIR/status
# errors in the top part of the conf while the watcher waits for a fix (world-readable)
CONF_ERR_FILE=$RUN_DIR/config-errors
LEASES=$RUN_DIR/dnsmasq.leases
STATE_DIR=/var/lib/tether              # remembers which packages install added (for uninstall)
PKG_RECORD=$STATE_DIR/added-packages
# every rule we add to the Qubes chain carries this, so we remove exactly ours
TAG='comment "tether"'
APT_PKGS=(dnsmasq-base nftables iproute2 usb-modeswitch hostapd iw ethtool)
SELF="$(readlink -f "${BASH_SOURCE[0]}")"

# ---------------------------------------------------------------------------
# Settings: name | default | type (the type picks the check in check_value).
# A key missing from the file keeps its default.
# ---------------------------------------------------------------------------
SETTINGS_SPEC=(
  "LOGGING|1|bool"
  "LOG_MAX_MB|100|posint"
  "LOG_FILE|/var/log/tether.log|path"
  "ADAPTER_PATTERN|enx|ifname"
  "UPLINK|eth0|ifname"
  "BRIDGE|br-tether|ifname"
  "LAN_IP|192.168.100.1|ip"
  "LAN_NET|192.168.100.0/24|lannet"
  "DHCP|1|bool"
  "DHCP_START|192.168.100.50|ip"
  "DHCP_END|192.168.100.150|ip"
  "LEASE_TIME|12h|lease"
  "STATIC_LEASES||static"
  "MAC_ALLOWLIST||maclist"
  "DNS|1|bool"
  "UPSTREAM_DNS1|10.139.1.1|ip"
  "UPSTREAM_DNS2|10.139.1.2|ipopt"
  "DNS_BLOCKLIST||fileopt"
  "ALLOW_DOT|0|bool"
  "ISOLATE_USB_PORTS|1|bool"
  "ISOLATE_WIFI_CLIENTS|1|bool"
  "ALLOW_PING|0|bool"
  "BLOCK_PRIVATE|1|bool"
  "PRIVATE_NETS|{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 }|netset"
  "CHECK_EVERY|5|posint"
  "RETRY_AFTER_FAIL|20|posint"
  "SKIP_DRIVERS|rndis_host ipheth|words"
  "CDMODE_SWITCH|0bda:8151=555342430860d9a9c0000000800006e0000000000000000000000000000000|cdmode"
  "WIFI|1|bool"
)
DEVICE_KEYS=" HARDWARE_MAC STICKY RANDOMIZE_MAC BAND COUNTRY_CODE CHANNEL "  # [device] level
AP_KEYS=" SSID PASS SECURITY HIDDEN "                                       # [ap] level
# Every [device]/[ap] key with the value it has when the block does not set it
# (parse_conf keeps them in the arrays DEV_<KEY>, one entry per [device] block)
DEVICE_FIELDS=(HARDWARE_MAC= STICKY=0 RANDOMIZE_MAC=0 BAND=2.4 COUNTRY_CODE= CHANNEL=auto
  SSID= PASS= SECURITY=wpa2 HIDDEN=0)
# CHANNEL=auto picks from these
CH_24=(1 6 11)
CH_5=(36 40 44 48)
CH_5_ALL=" 36 40 44 48 52 56 60 64 100 104 108 112 116 120 124 128 132 136 140 144 149 153 157 161 \
165 169 173 177 "

declare -A CFG=()  # active settings (the watcher loads them once; reload restarts it)

# =============================================================================
# Small helpers
# =============================================================================
say() { printf '%s\n' "$*"; }
die() { printf 'tether: %s\n' "$*" >&2; exit 1; }
ask() { local a=""; read -r -p "$1 [y/n] " a || true; [[ $a == [yY]* ]]; }
have() { command -v "$1" >/dev/null 2>&1; }
# Print $1 without its leading and trailing whitespace
trim() {
  local s=$1
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

# 1 if $1 is 1, else 0 (turns a setting into the 0/1 that nft_opt and hostapd expect)
flag() { if [[ $1 == 1 ]]; then echo 1; else echo 0; fi; }

# Is this pid still a running process? (a finished child can linger as a zombie until reaped)
alive() {
  local st=""
  [[ -n ${1:-} ]] && kill -0 "$1" 2>/dev/null || return 1
  read -r _ _ st _ < "/proc/$1/stat" 2>/dev/null || return 1
  [[ $st != Z ]]
}

# Random text from the given characters (SRANDOM = bash's 32-bit random number from the kernel)
rand_str() {
  local chars=$1 n=$2 out="" i
  for ((i = 0; i < n; i++)); do out+=${chars:SRANDOM % ${#chars}:1}; done
  printf '%s' "$out"
}

# Random locally administered unicast MAC (bit 1 of the first byte set, bit 0 clear)
rand_mac() {
  printf '%02x:%02x:%02x:%02x:%02x:%02x' $(((SRANDOM & 0xfc) | 0x02)) $((SRANDOM & 255)) \
    $((SRANDOM & 255)) $((SRANDOM & 255)) $((SRANDOM & 255)) $((SRANDOM & 255))
}

is_ip() {
  [[ $1 =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  local i
  for i in 1 2 3 4; do ((10#${BASH_REMATCH[i]} <= 255)) || return 1; done
}
ip2int() {
  local IFS=. a b c d
  read -r a b c d <<< "$1"
  echo $(((10#$a << 24) + (10#$b << 16) + (10#$c << 8) + 10#$d))
}
is_cidr() {
  [[ $1 == */* ]] && is_ip "${1%/*}" && [[ ${1#*/} =~ ^[0-9]{1,2}$ ]] && ((10#${1#*/} <= 32))
}
# in_net 192.168.100.7 192.168.100.0/24
in_net() {
  local mask
  mask=$(((0xffffffff << (32 - 10#${2#*/})) & 0xffffffff))
  (( ($(ip2int "$1") & mask) == ($(ip2int "${2%/*}") & mask) ))
}
is_mac() { [[ ${1,,} =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]]; }

# Write the output of a command to FILE.tmp, give it MODE, then move it over FILE, so a
# reader never sees a half-written file: atomic_write MODE FILE COMMAND [ARGS...]
atomic_write() {
  local mode=$1 file=$2
  shift 2
  "$@" > "$file.tmp" && chmod "$mode" "$file.tmp" && mv -f "$file.tmp" "$file"
}

# =============================================================================
# Logging: timestamped lines to stdout (the journal, for the watcher) and,
# with LOGGING=1, to LOG_FILE. Past LOG_MAX_MB the file starts fresh with a note.
# =============================================================================
# Log one line (the arguments joined by a space) with a timestamp
log() {
  local line f max size
  line="$(date '+%Y-%m-%d %H:%M:%S') $*"
  printf '%s\n' "$line"
  [[ ${CFG[LOGGING]:-1} == 1 ]] || return 0
  f=${CFG[LOG_FILE]:-/var/log/tether.log}
  max=${CFG[LOG_MAX_MB]:-100}
  size=$(stat -c %s "$f" 2>/dev/null || echo 0)
  if ((size > max * 1024 * 1024)); then
    printf '######## LOG RESET %s: previous log passed %s MB and was cleared ########\n' \
      "$(date '+%Y-%m-%d %H:%M:%S')" "$max" > "$f" 2>/dev/null
  fi
  printf '%s\n' "$line" >> "$f" 2>/dev/null
  return 0
}
# Feed a child's output (dnsmasq, hostapd) into the log, line by line
log_lines() { local l; while IFS= read -r l; do log "$1$l"; done; }

# Run a command; on failure log it with its error text (used while building the bridge/firewall)
try() {
  local out
  out=$("$@" 2>&1) && return 0
  log "ERROR: '$*' failed: ${out//$'\n'/ | }"
  return 1
}

# =============================================================================
# Config file parser and validator - part 1: the parser
#
# The top part is KEY=value lines (parsed, not sourced).
# Values may be "double" or 'single' quoted; quote anything with spaces.
# Text after the value starting with # is a comment. Then come INI-style blocks:
#   [device]   one per Wi-Fi dongle (HARDWARE_MAC, STICKY, RANDOMIZE_MAC, BAND, COUNTRY_CODE,
#              CHANNEL)
#              (COUNTRY_CODE may be missing in older blocks: it counts as empty)
#     [ap]     its access point (SSID, PASS, SECURITY, HIDDEN). Several [ap] are
#              accepted for the future (multi-SSID); only the first is used now.
#
# parse_conf FILE fills:
#   PARSED[KEY]            top settings (defaults first), PARSED_LINE[KEY] = its line number
#   DEV_COUNT, DEV_START[i]  number of devices, line of each [device]; DEV_<KEY>[i] values,
#                          DEV_LINE["i.KEY"] = line of that key, DEV_APS[i] = number of [ap]
#   ERRS                   every problem as "line N: <line>, <reason>" (<line> never shows a
#                          password: line_text replaces it with ***)
#   TOP_ERRS               the problems outside [device] blocks
#   TOP_ERRS_PUBLIC        the same with PASS values hidden (for the world-readable CONF_ERR_FILE)
#                          (now the same text: line_text already hides them everywhere)
#   DEV_ERRS[i]            problems of device i (newline separated)
#   NOTES                  things worth saying that are not errors
# Returns 0 when there are no errors.
# =============================================================================
declare -A PARSED=() PARSED_LINE=() DEV_LINE=()
declare -a CONF_LINES=() ERRS=() TOP_ERRS=() TOP_ERRS_PUBLIC=() NOTES=()
declare -a DEV_START=() DEV_APS=() DEV_ERRS=()
declare -a DEV_HARDWARE_MAC=() DEV_STICKY=() DEV_RANDOMIZE_MAC=() DEV_BAND=() DEV_COUNTRY_CODE=()
declare -a DEV_CHANNEL=() DEV_SSID=() DEV_PASS=() DEV_SECURITY=() DEV_HIDDEN=()
DEV_COUNT=0
PARSE_DEV=-1        # while parsing: index of the current [device] block (-1 = none yet)
PARSE_SECTION=top   # while parsing: top | device | ap

spec_type() {
  local e
  for e in "${SETTINGS_SPEC[@]}"; do [[ ${e%%|*} == "$1" ]] && { echo "${e##*|}"; return 0; }; done
  return 1
}

# Does word $1 look like a password key? (PASS, PASSWORD, SAE_PASSWORD, WPA_PASSPHRASE,
# WPA_PSK, ..., any case)
secret_word() {
  local w=${1^^}
  [[ $w == *PASS* || $w == *PSK* || $w == *SECRET* || $w == *TOKEN* ]]
}

declare -a CONF_HIDDEN=()   # parse_conf: [N]=1 for a line in [ap] that is not KEY=value

# Line N of the file without its trailing comment (for messages)
# Every message that quotes a conf line gets the text from here (errors and notes, so the
# reload output, the world-readable log, the config-errors file and "tether status"), so this
# is where passwords are hidden; the value is never shown, whatever is wrong with the line:
#   - the line starts with a password-looking word (also without "=", as in "PASS secret"):
#     shown as WORD=***
#   - a later password-looking word followed by = or : ("SSID=x PASS=y"): the text up to
#     that word, then =***
#   - a line in [ap] that is not KEY=value (it may be a mangled PASS line): shown as ***
line_text() {
  local t=${CONF_LINES[$1]:-} w
  [[ $t =~ ^(.*[^[:space:]])[[:space:]]+#.*$ ]] && t=${BASH_REMATCH[1]}
  if [[ -n ${CONF_HIDDEN[$1]:-} ]]; then t="***"
  elif [[ $t =~ ^([^A-Za-z0-9_]*)([A-Za-z0-9_]+) ]] && secret_word "${BASH_REMATCH[2]}"; then
    t="${BASH_REMATCH[1]}${BASH_REMATCH[2]}=***"
  else
    # every word followed by = or :, left to right; cut at the first password-looking one
    w=$t
    while [[ $w =~ ([A-Za-z0-9_]+)[[:space:]]*[=:](.*)$ ]]; do
      if secret_word "${BASH_REMATCH[1]}"; then
        t="${t:0:${#t} - ${#BASH_REMATCH[0]}}${BASH_REMATCH[1]}=***"; break
      fi
      w=${BASH_REMATCH[2]}
    done
  fi
  printf '%s' "$t"
}

# A note (shown by reload and logged, does not stop anything): the arguments joined by a space
add_note() { NOTES+=("$*"); }

# add_error LINE DEVICE_INDEX(-1 = none) REASON
add_error() {
  local msg t
  t=$(line_text "$1")
  msg="line $1: $t, $3"
  ERRS+=("$msg")
  if (($2 >= 0)); then DEV_ERRS[$2]+="$msg"$'\n'; return 0; fi
  TOP_ERRS+=("$msg")
  # a stray PASS line outside [ap] must not show its password to every user
  # (line_text has already replaced the value with ***, so this copy has the same text)
  TOP_ERRS_PUBLIC+=("line $1: $t, $3")
}

# Split the text after "KEY=" into the value (VALUE) and check that only a comment follows it
parse_value() {
  local s=$1 q
  VALUE=""; VALUE_ERR=""
  if [[ $s == \"* || $s == \'* ]]; then
    q=${s:0:1}; s=${s:1}
    [[ $s == *"$q"* ]] || { VALUE_ERR="missing closing quote"; return 1; }
    VALUE=${s%%"$q"*}; s=${s#*"$q"}
  else
    VALUE=${s%%[[:space:]]*}; s=${s:${#VALUE}}
  fi
  s=$(trim "$s")
  if [[ -n $s && $s != \#* ]]; then
    VALUE_ERR="unexpected text after the value (put values with spaces in quotes)"
    return 1
  fi
}

# Forget the last parse and start from the defaults
parse_reset() {
  local e key
  PARSED=(); PARSED_LINE=(); DEV_LINE=(); CONF_LINES=(); CONF_HIDDEN=()
  ERRS=(); TOP_ERRS=(); TOP_ERRS_PUBLIC=(); NOTES=()
  DEV_COUNT=0; DEV_START=(); DEV_APS=(); DEV_ERRS=()
  for e in "${DEVICE_FIELDS[@]}"; do declare -ga "DEV_${e%%=*}=()"; done
  for e in "${SETTINGS_SPEC[@]}"; do key=${e%%|*}; e=${e#*|}; PARSED[$key]=${e%%|*}; done
  PARSE_DEV=-1; PARSE_SECTION=top
}

# Read conf file $1 into PARSED / DEV_* (see the section comment), then validate it
parse_conf() {
  local file=$1 n=0 raw line
  parse_reset
  if [[ ! -r $file ]]; then
    ERRS+=("cannot read $file")
    TOP_ERRS+=("cannot read $file")
    TOP_ERRS_PUBLIC+=("cannot read $file")
    return 1
  fi
  while IFS= read -r raw || [[ -n $raw ]]; do
    n=$((n + 1)); line=$(trim "$raw"); CONF_LINES[n]=$line
    [[ -z $line || $line == \#* ]] && continue
    if [[ $line =~ ^\[([A-Za-z]+)\][[:space:]]*(#.*)?$ ]]; then
      parse_section_line "$n" "${BASH_REMATCH[1]}"
    elif [[ $line =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      parse_key_line "$n" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    else
      [[ $PARSE_SECTION == ap ]] && CONF_HIDDEN[n]=1   # may hold a password: line_text hides it
      add_error "$n" "$PARSE_DEV" "not a KEY=value line"
    fi
  done < "$file"
  validate_top
  local d
  for ((d = 0; d < DEV_COUNT; d++)); do validate_device "$d"; done
  ((${#ERRS[@]} == 0)) && return 0
  mapfile -t ERRS < <(printf '%s\n' "${ERRS[@]}" | sort -n -k2)     # in file order
  return 1
}

# A "[name]" line (line number $1): opens a [device] block or its [ap] section
parse_section_line() {
  local n=$1 d e
  case $2 in
    device)
      d=$DEV_COUNT; DEV_COUNT=$((DEV_COUNT + 1)); DEV_START[d]=$n; DEV_APS[d]=0; DEV_ERRS[d]=""
      for e in "${DEVICE_FIELDS[@]}"; do printf -v "DEV_${e%%=*}[$d]" '%s' "${e#*=}"; done
      PARSE_DEV=$d; PARSE_SECTION=device ;;
    ap)
      d=$PARSE_DEV
      if ((d < 0)); then add_error "$n" -1 "[ap] must come after a [device] line"; return 0; fi
      DEV_APS[d]=$((DEV_APS[d] + 1)); PARSE_SECTION=ap
      if ((DEV_APS[d] == 2)); then
        add_note "line $n: [ap], more than one [ap] per dongle is not supported yet;" \
          "only the first is used"
      fi ;;
    *) [[ $PARSE_SECTION == ap ]] && CONF_HIDDEN[n]=1   # as for a non KEY=value line in [ap]
       add_error "$n" "$PARSE_DEV" "unknown section (only [device] and [ap] exist)" ;;
  esac
}

# A KEY=value line: parse_key_line LINE KEY TEXT_AFTER_THE_=
parse_key_line() {
  local n=$1 key=$2 d=$PARSE_DEV
  parse_value "$3" || { add_error "$n" "$d" "$VALUE_ERR"; return 0; }
  case $PARSE_SECTION in
    top)
      if spec_type "$key" >/dev/null; then PARSED[$key]=$VALUE; PARSED_LINE[$key]=$n
      elif [[ $key == PASS ]]; then add_error "$n" -1 "unknown setting (PASS belongs under [ap])"
      else add_error "$n" -1 "unknown setting"; fi ;;
    device)
      if [[ $DEVICE_KEYS == *" $key "* ]]; then
        printf -v "DEV_${key}[$d]" '%s' "$VALUE"; DEV_LINE["$d.$key"]=$n
      elif [[ $AP_KEYS == *" $key "* ]]; then add_error "$n" "$d" "$key belongs under [ap]"
      else add_error "$n" "$d" "unknown [device] setting"; fi ;;
    ap)
      if [[ $AP_KEYS == *" $key "* ]]; then
        # later [ap] blocks: syntax-checked only (future multi-SSID)
        ((DEV_APS[d] == 1)) || return 0
        printf -v "DEV_${key}[$d]" '%s' "$VALUE"; DEV_LINE["$d.$key"]=$n
      elif [[ $DEVICE_KEYS == *" $key "* ]]; then
        add_error "$n" "$d" "$key belongs to [device], above [ap]"
      else add_error "$n" "$d" "unknown [ap] setting"; fi ;;
  esac
}

# Index of the [device] block for hardware MAC $1 in the last parse_conf (prints -1 if none)
device_index() {
  local i
  for ((i = 0; i < DEV_COUNT; i++)); do
    [[ ${DEV_HARDWARE_MAC[i],,} == "${1,,}" ]] && { echo "$i"; return 0; }
  done
  echo -1; return 1
}

# Load the top settings of the last parse into CFG (what the running watcher uses)
apply_parsed() { local k; for k in "${!PARSED[@]}"; do CFG[$k]=${PARSED[$k]}; done; }

# Parse the conf again, quietly (the watcher and the commands only need the result)
reparse() { parse_conf "$CONF" >/dev/null 2>&1; }

# =============================================================================
# Config file parser and validator - part 2: the validator (called by parse_conf)
# =============================================================================
# check_value TYPE VALUE: returns 1 and sets REASON if VALUE is not valid for TYPE
check_value() {
  local t=$1 v=$2 w
  REASON=""
  case $t in
    bool) [[ $v == 0 || $v == 1 ]] || REASON="must be 0 or 1" ;;
    posint) [[ $v =~ ^[1-9][0-9]{0,5}$ ]] || REASON="must be a whole number above 0" ;;
    path)
      [[ $v == /* && $v != *[[:space:]]* ]] \
        || REASON="must be an absolute path (starting with /, no spaces)" ;;
    ifname)
      [[ $v =~ ^[A-Za-z0-9._-]{1,15}$ ]] \
        || REASON="must be an interface name (1-15 letters, digits, . _ -)" ;;
    ip) is_ip "$v" || REASON="not an IPv4 address" ;;
    ipopt) [[ -z $v ]] || is_ip "$v" || REASON="not an IPv4 address (or leave it empty)" ;;
    lannet)
      if ! is_cidr "$v"; then REASON="must be a network like 192.168.100.0/24"
      elif ((10#${v#*/} < 8 || 10#${v#*/} > 30)); then REASON="prefix must be between /8 and /30"
      fi ;;
    lease)
      [[ $v =~ ^([0-9]+[smhdw]?|infinite)$ ]] \
        || REASON="must be a number with s, m, h, d or w (like 12h), or infinite" ;;
    static)
      for w in $v; do
        if ! { [[ $w == *=* ]] && is_mac "${w%%=*}" && is_ip "${w#*=}"; }; then
          REASON="\"$w\" is not MAC=IP (like aa:bb:cc:dd:ee:ff=192.168.100.10)"; break
        fi
      done ;;
    maclist)
      for w in $v; do is_mac "$w" || { REASON="\"$w\" is not a MAC address"; break; }; done ;;
    fileopt) [[ -z $v || -r $v ]] || REASON="file not found" ;;
    netset)
      if [[ ! $v =~ ^\{(.*)\}$ ]]; then REASON="must look like { 10.0.0.0/8, 172.16.0.0/12 }"
      else
        for w in ${BASH_REMATCH[1]//,/ }; do
          is_cidr "$w" || is_ip "$w" || { REASON="\"$w\" is not a network or address"; break; }
        done
      fi ;;
    words) [[ $v =~ ^[A-Za-z0-9_\ -]*$ ]] || REASON="only names separated by spaces" ;;
    cdmode)
      for w in $v; do
        [[ $w =~ ^[0-9a-f]{4}:[0-9a-f]{4}=[0-9a-fA-F]+$ ]] \
          || { REASON="\"$w\" is not vendor:product=hexmessage"; break; }
      done ;;
  esac
  [[ -z $REASON ]]
}

declare -A TOP_INVALID=()   # validate_top: KEY=1 for each top setting whose own value is invalid

# Are all the named top settings valid on their own? (cross-checks only compare valid values)
top_keys_valid() { local k; for k; do [[ -z ${TOP_INVALID[$k]:-} ]] || return 1; done; }

# Check every top setting against its type, then the settings that depend on each other
validate_top() {
  local key t net w mac
  TOP_INVALID=()
  for key in "${!PARSED_LINE[@]}"; do
    t=$(spec_type "$key")
    check_value "$t" "${PARSED[$key]}" \
      || { add_error "${PARSED_LINE[$key]}" -1 "$REASON"; TOP_INVALID[$key]=1; }
  done
  # Cross-checks, each only when the values it compares are valid on their own
  net=${PARSED[LAN_NET]}
  if top_keys_valid LAN_IP LAN_NET; then
    in_net "${PARSED[LAN_IP]}" "$net" \
      || add_error "${PARSED_LINE[LAN_IP]:-${PARSED_LINE[LAN_NET]:-0}}" -1 \
        "LAN_IP is not inside LAN_NET ($net)"
  fi
  if [[ ${PARSED[DHCP]} == 1 ]] && top_keys_valid LAN_NET DHCP_START DHCP_END; then
    in_net "${PARSED[DHCP_START]}" "$net" \
      || add_error "${PARSED_LINE[DHCP_START]:-0}" -1 "not inside LAN_NET ($net)"
    in_net "${PARSED[DHCP_END]}" "$net" \
      || add_error "${PARSED_LINE[DHCP_END]:-0}" -1 "not inside LAN_NET ($net)"
    (($(ip2int "${PARSED[DHCP_START]}") <= $(ip2int "${PARSED[DHCP_END]}"))) \
      || add_error "${PARSED_LINE[DHCP_END]:-0}" -1 "DHCP_END is before DHCP_START"
  fi
  if top_keys_valid LAN_NET STATIC_LEASES MAC_ALLOWLIST; then
    for w in ${PARSED[STATIC_LEASES]}; do
      in_net "${w#*=}" "$net" \
        || add_error "${PARSED_LINE[STATIC_LEASES]}" -1 "${w#*=} is not inside LAN_NET ($net)"
      mac=${w%%=*}
      if [[ -n ${PARSED[MAC_ALLOWLIST]} && " ${PARSED[MAC_ALLOWLIST],,} " != *" ${mac,,} "* ]]; then
        add_error "${PARSED_LINE[STATIC_LEASES]}" -1 \
          "$mac is not in MAC_ALLOWLIST, it would get no address"
      fi
    done
  fi
  [[ ${PARSED[BRIDGE]} != "${PARSED[UPLINK]}" ]] \
    || add_error "${PARSED_LINE[BRIDGE]:-0}" -1 "BRIDGE must differ from UPLINK"
  [[ ${PARSED[UPLINK]} != "${PARSED[ADAPTER_PATTERN]}"* ]] \
    || add_error "${PARSED_LINE[ADAPTER_PATTERN]:-0}" -1 "would match the uplink ${PARSED[UPLINK]}"
  return 0
}

# Check [device] block $1: each part below adds its errors to DEV_ERRS[$1]
validate_device() {
  local d=$1 s=${DEV_START[$1]}
  validate_device_mac "$d"
  ((DEV_APS[d] > 0)) || add_error "$s" "$d" "this [device] has no [ap] section"
  validate_device_bools "$d"
  validate_device_country "$d"
  validate_device_band "$d"
  ((DEV_APS[d] > 0)) || return 0
  validate_device_ap "$d"
}

# HARDWARE_MAC: present, a MAC, and not used by an earlier block
validate_device_mac() {
  local d=$1 s=${DEV_START[$1]} e
  [[ -n ${DEV_HARDWARE_MAC[d]} ]] \
    || { add_error "$s" "$d" "this [device] has no HARDWARE_MAC"; return 0; }
  if ! is_mac "${DEV_HARDWARE_MAC[d]}"; then
    add_error "${DEV_LINE["$d.HARDWARE_MAC"]}" "$d" "not a MAC address"; return 0
  fi
  for ((e = 0; e < d; e++)); do
    if [[ ${DEV_HARDWARE_MAC[e],,} == "${DEV_HARDWARE_MAC[d],,}" ]]; then
      add_error "${DEV_LINE["$d.HARDWARE_MAC"]}" "$d" \
        "this dongle already has a [device] block (line ${DEV_START[e]})"
      break
    fi
  done
}

# STICKY, RANDOMIZE_MAC and HIDDEN must be 0 or 1 (checked only when the block sets them)
validate_device_bools() {
  local d=$1 k ln v
  for k in STICKY RANDOMIZE_MAC HIDDEN; do
    ln=${DEV_LINE["$d.$k"]:-}; [[ -n $ln ]] || continue
    v="DEV_${k}[$d]"
    check_value bool "${!v}" || add_error "$ln" "$d" "$REASON"
  done
}

# COUNTRY_CODE of block $1: stored uppercase, two letters or 00, and 5 GHz needs a real one
validate_device_country() {
  local d=$1 s=${DEV_START[$1]} ln
  # Country (regulatory domain): lowercase is accepted and stored uppercase; 00 = world domain
  DEV_COUNTRY_CODE[d]=${DEV_COUNTRY_CODE[d]^^}
  ln=${DEV_LINE["$d.COUNTRY_CODE"]:-$s}
  if [[ -n ${DEV_COUNTRY_CODE[d]} && ! ${DEV_COUNTRY_CODE[d]} =~ ^([A-Z]{2}|00)$ ]]; then
    add_error "$ln" "$d" "must be a 2-letter country code (e.g. FR, DE, US) or 00"
  elif [[ ${DEV_BAND[d]} == 5 && -z ${DEV_COUNTRY_CODE[d]} ]]; then
    add_error "${DEV_LINE["$d.BAND"]:-$s}" "$d" "needs COUNTRY_CODE set (e.g. COUNTRY_CODE=FR)"
  elif [[ ${DEV_BAND[d]} == 5 && ${DEV_COUNTRY_CODE[d]} == 00 ]]; then
    add_error "$ln" "$d" \
      "00 (world) does not allow access points on 5 GHz, set your real country (e.g. FR)"
  fi
}

# BAND (against the hardware, if plugged in) and CHANNEL (against the band)
validate_device_band() {
  local d=$1 s=${DEV_START[$1]} ln v iface="" phy
  ln=${DEV_LINE["$d.BAND"]:-$s}
  case ${DEV_BAND[d]} in
    2.4|5)
      # The band can only be checked against the hardware while the dongle is plugged in
      if have iw && is_mac "${DEV_HARDWARE_MAC[d]}" \
        && iface=$(wifi_iface_for_mac "${DEV_HARDWARE_MAC[d]}"); then
        phy=$(phy_of "$iface")
        if ! band_supported "$phy" "${DEV_BAND[d]}"; then
          if [[ ${DEV_BAND[d]} == 5 ]]; then
            add_error "$ln" "$d" "this dongle does not support 5 GHz"
          else add_error "$ln" "$d" "this dongle ($iface) has no usable ${DEV_BAND[d]} GHz band"; fi
        fi
      elif [[ -n ${DEV_LINE["$d.BAND"]:-} ]]; then
        add_note "line $ln: $(line_text "$ln"), dongle not plugged in;" \
          "the band is checked when it is plugged in"
      fi
      v=${DEV_CHANNEL[d]}; ln=${DEV_LINE["$d.CHANNEL"]:-$s}
      if [[ $v != auto ]]; then
        if [[ ${DEV_BAND[d]} == 2.4 ]]; then
          [[ $v =~ ^([1-9]|1[0-4])$ ]] || add_error "$ln" "$d" "2.4 GHz channels are 1-14 (or auto)"
        else
          [[ $CH_5_ALL == *" $v "* ]] \
            || add_error "$ln" "$d" "not a 5 GHz channel (36, 40, 44, 48, ... or auto)"
        fi
      fi ;;
    *) add_error "$ln" "$d" "BAND must be 2.4 or 5" ;;
  esac
}

# The [ap] part: SSID, SECURITY and the password it needs
validate_device_ap() {
  local d=$1 s=${DEV_START[$1]} ln v
  v=${DEV_SSID[d]}; ln=${DEV_LINE["$d.SSID"]:-$s}
  if [[ -z $v ]]; then add_error "$ln" "$d" "SSID is missing or empty"
  elif (($(printf '%s' "$v" | wc -c) > 32)); then
    add_error "$ln" "$d" "SSID is longer than 32 bytes"
  fi
  ln=${DEV_LINE["$d.SECURITY"]:-$s}
  case ${DEV_SECURITY[d]} in
    wpa2|wpa3|wpa2+wpa3)
      v=${DEV_PASS[d]}; ln=${DEV_LINE["$d.PASS"]:-$s}
      if ((${#v} < 8 || ${#v} > 63)); then
        add_error "$ln" "$d" "password must be 8 to 63 characters for ${DEV_SECURITY[d]}"
      elif [[ ! $v =~ ^[[:print:]]+$ ]]; then
        add_error "$ln" "$d" "password may only contain printable characters"
      fi ;;
    open) ;;
    *) add_error "$ln" "$d" "SECURITY must be wpa2, wpa3, wpa2+wpa3 or open" ;;
  esac
}

# =============================================================================
# Writing /etc/tether.conf (always 0600 root: it holds the Wi-Fi passwords)
# =============================================================================
# The conf a fresh install writes (tether reset writes it too)
default_conf() {
  cat <<'CONF'
# tether settings. Change them with "tether settings" or edit this file, then run "tether reload".
# KEY=value lines; put values that contain spaces in quotes. Text after # is a comment.

# ---------- Logging ----------
LOGGING=1                       # 1 = write LOG_FILE (readable by every user), 0 = no log file
LOG_MAX_MB=100                  # when the log passes this size it is cleared, with a note at the top
LOG_FILE=/var/log/tether.log

# ---------- Network ----------
ADAPTER_PATTERN="enx"           # USB Ethernet adapters: every interface whose name starts with this joins the bridge
UPLINK="eth0"                   # this qube's way out (to its NetVM)
BRIDGE="br-tether"              # all cables and Wi-Fi access points join this one network
LAN_IP=192.168.100.1            # this qube on that network: gateway and DNS server for the devices
LAN_NET=192.168.100.0/24

# ---------- DHCP (addresses for the devices) ----------
DHCP=1                          # 0 = hand out no addresses (devices need a fixed IP in LAN_NET)
DHCP_START=192.168.100.50
DHCP_END=192.168.100.150
LEASE_TIME=12h                  # like 30m, 12h, 7d, or infinite
STATIC_LEASES=""                # fixed addresses: "aa:bb:cc:dd:ee:ff=192.168.100.10 ..."
MAC_ALLOWLIST=""                # empty = everyone; else only these MACs get leases AND are forwarded

# ---------- DNS ----------
DNS=1                           # 0 = dnsmasq serves no DNS (port=0); devices then use their own DNS servers
UPSTREAM_DNS1=10.139.1.1        # Qubes resolvers (through the NetVM / VPN)
UPSTREAM_DNS2=10.139.1.2
DNS_BLOCKLIST=""                # path to a hosts-style file ("0.0.0.0 ads.example.com"), loaded as addn-hosts

# DNS-over-TLS (port 853). 0 = blocked (default), 1 = allowed.
#   Blocked: devices fall back to plain DNS, which is redirected to our dnsmasq, so every
#            lookup goes through the Qubes resolvers (and your NetVM/VPN). Nothing leaks around it.
#   Allowed: devices can use their own encrypted DNS (e.g. Android "Private DNS"), which is more
#            private on the wire but goes straight to their chosen server, bypassing dnsmasq.
#   Note: DNS-over-HTTPS (port 443) looks like normal web traffic and can't be blocked either way.
ALLOW_DOT=0

# ---------- Firewall ----------
ISOLATE_USB_PORTS=1             # 1 = devices on different ports can't reach each other (cable to cable, cable to Wi-Fi, one AP to another)
# Devices plugged into the same external switch or hub can still reach each other; that traffic never reaches tether.
ISOLATE_WIFI_CLIENTS=1          # 1 = devices on the same Wi-Fi network can't reach each other
ALLOW_PING=0                    # 1 = devices may ping this qube and the outside
BLOCK_PRIVATE=1                 # 1 = devices can't reach PRIVATE_NETS (your other qubes, home LAN, tailnet)
PRIVATE_NETS="{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 }"

# ---------- Watcher ----------
CHECK_EVERY=5                   # seconds between checks for plugged/unplugged adapters
RETRY_AFTER_FAIL=20             # seconds to wait before retrying something that failed

# Drivers that are never added to the bridge: these are phones sharing THEIR internet
# (rndis_host = Android/Windows-style tethering, ipheth = iPhone). A phone like that would
# run its own DHCP server and hand out wrong addresses. Newer Androids may use cdc_ncm, which
# real adapters use too, so they can't be listed here; the bridge DHCP guard catches them.
SKIP_DRIVERS="rndis_host ipheth"

# Adapters that first appear as a virtual CD-ROM with Windows drivers ("CD mode") and only
# become a network card after a switch command. The watcher sends that command when it sees
# one. On Qubes the adapter then reconnects as a new USB device, so attach it to this qube
# again in the devices widget. Format: "vendor:product=switch-message", space-separated.
CDMODE_SWITCH="0bda:8151=555342430860d9a9c0000000800006e0000000000000000000000000000000"

# ---------- Wi-Fi ----------
WIFI=1                          # 1 = USB Wi-Fi dongles become access points on the bridge, 0 = ignore them

# ---------- Wi-Fi devices (added automatically) ----------
CONF
}

# Write a fresh default conf (root only: 600; it will hold the Wi-Fi passwords)
write_default_conf() { (umask 077; default_conf > "$CONF") && chmod 600 "$CONF"; }

# How many entries the array named $1 has without its trailing blank lines
nonblank_len() {
  local -n _nbl_lines=$1
  local n=${#_nbl_lines[@]}
  while ((n > 0)) && [[ -z $(trim "${_nbl_lines[n - 1]}") ]]; do n=$((n - 1)); done
  echo "$n"
}

# Replace the conf with the lines in CONF_OUT (trailing blank lines dropped), atomically
conf_write() {
  local tmp n
  n=$(nonblank_len CONF_OUT)
  tmp=$(mktemp "$CONF.XXXXXX") || return 1
  chmod 600 "$tmp"
  if printf '%s\n' "${CONF_OUT[@]:0:n}" > "$tmp" && mv -f "$tmp" "$CONF"; then return 0; fi
  rm -f "$tmp"; return 1
}

# Remove [device] block number $1 of the last parse (from its line up to the next [device] or the
# end)
conf_remove_device() {
  local d=$1 start end
  local -a lines=()
  mapfile -t lines < "$CONF"
  start=$((DEV_START[d] - 1))
  if ((d + 1 < DEV_COUNT)); then end=$((DEV_START[d + 1] - 1)); else end=${#lines[@]}; fi
  CONF_OUT=("${lines[@]:0:start}" "${lines[@]:end}")
  conf_write
}

# A new random SSID like AP_4821 that is not used yet: not in any [device] block of
# the last parse, not on any SSID= line of the conf (also catches blocks that failed
# to parse) and not broadcast by a running dongle
new_ssid() {
  local ssid used
  used=$'\n'$(printf '%s\n' "${DEV_SSID[@]}" "${W_SSID[@]}")$'\n'
  if [[ -r $CONF ]]; then
    used+=$(sed -nE \
      's/^[[:space:]]*SSID[[:space:]]*=[[:space:]]*["\x27]?([^"\x27#[:space:]]*).*/\1/p' \
      "$CONF")$'\n'
  fi
  while :; do
    ssid="AP_$(rand_str 0123456789 4)"
    [[ $used == *$'\n'"$ssid"$'\n'* ]] || break
  done
  printf '%s' "$ssid"
}

# Text of a fresh [device] block: device_block MAC "description" BAND [NO5]
# NO5=1 (dongle without 5 GHz): BAND and COUNTRY_CODE are written commented out under a
# note saying so; a commented-out BAND counts as the default 2.4 when the conf is parsed.
device_block() {
  local ssid pass cc_note='# if you set BAND=5 you must set a country code (e.g. FR, DE, US)'
  ssid=$(new_ssid)
  pass=$(rand_str abcdefghijklmnopqrstuvwxyz0123456789 8)
  printf '[device]\nHARDWARE_MAC=%s\n' "$1"
  printf '# %s, plugged %s\n' "$2" "$(date '+%Y-%m-%d %H:%M')"
  printf '# You can change anything below. Save the file and run "tether reload" to apply.\n'
  printf '# A new SSID and password are generated every time you plug in this dongle.\n'
  printf "# Set STICKY=1 to keep this dongle's settings the same every time you plug it in.\n"
  printf '# AppVMs forget changes on reboot. To keep them in AppVMs, plug the dongle into\n'
  printf '# their template, set STICKY=1 there, run "tether reload", then shut the template down.\n'
  printf 'STICKY=0\n'
  printf '%-24s%s\n' "RANDOMIZE_MAC=0" \
    "# 1 = broadcast a random MAC, new on every plug-in and different from HARDWARE_MAC"
  if [[ ${4:-0} == 1 ]]; then
    # "# " + %-22s keeps the comments in the same column as on the other lines
    printf '# this dongle does not support 5 GHz\n'
    printf '# %-22s# 2.4 | 5\n' "BAND=2.4"
    printf '# %-22s%s\n' "COUNTRY_CODE=" "$cc_note"
  else
    printf '%-24s# 2.4 | 5\n' "BAND=$3"
    printf '%-24s%s\n' "COUNTRY_CODE=" "$cc_note"
  fi
  printf 'CHANNEL=auto\n\n'
  printf '  [ap]\n  SSID="%s"\n  PASS="%s"\n' "$ssid" "$pass"
  printf '  %-22s# wpa2 | wpa3 | wpa2+wpa3 | open\n' "SECURITY=wpa2+wpa3"
  printf '  HIDDEN=0\n'
}

# Append a fresh block to the conf (re-adds the Wi-Fi section header if it was deleted)
conf_append_device() {
  local n
  local -a lines=() block=()
  mapfile -t lines < "$CONF"
  mapfile -t block < <(device_block "$@")
  n=$(nonblank_len lines)
  CONF_OUT=("${lines[@]:0:n}")
  if ! grep -qF -- '---------- Wi-Fi devices' "$CONF"; then
    CONF_OUT+=("" "# ---------- Wi-Fi devices (added automatically) ----------")
  fi
  CONF_OUT+=("" "${block[@]}")
  conf_write
}

# =============================================================================
# Hardware lookups (sysfs, iw, lsusb, ethtool)
# =============================================================================
driver_of() { basename "$(readlink -f "/sys/class/net/$1/device/driver" 2>/dev/null)"; }
is_skipped() { local d; d=$(driver_of "$1"); [[ " ${CFG[SKIP_DRIVERS]} " == *" $d "* ]]; }
phy_of() { cat "/sys/class/net/$1/phy80211/name" 2>/dev/null; }
bridge_of() { basename "$(readlink -f "/sys/class/net/$1/master" 2>/dev/null)"; }   # "" if in none

# Fill WIRED_IFACES with the wired interfaces matching pattern $1 (Wi-Fi ones, which have
# phy80211, are left out)
WIRED_IFACES=()
wired_ifaces() {
  local p
  WIRED_IFACES=()
  for p in /sys/class/net/"$1"*; do
    [[ -e $p && ! -e $p/phy80211 ]] && WIRED_IFACES+=("${p##*/}")
  done
  return 0
}

# The USB device directory behind an interface (the one with idVendor/idProduct), if it is USB
usb_dir() {
  local d
  d=$(readlink -f "/sys/class/net/$1/device" 2>/dev/null) || return 1
  [[ $d == */usb* ]] || return 1
  while [[ -n $d && $d != / ]]; do
    [[ -f $d/idVendor ]] && { echo "$d"; return 0; }
    d=${d%/*}
  done
  return 1
}

# "Ralink RT5370 Wireless Adapter (148f:5370, rt2800usb)": the lsusb name, else the sysfs strings
usb_desc() {
  local d vid pid name="" drv
  drv=$(driver_of "$1")
  d=$(usb_dir "$1") || { echo "not USB (${drv:-virtual})"; return 0; }
  vid=$(cat "$d/idVendor"); pid=$(cat "$d/idProduct")
  if have lsusb; then
    name=$(lsusb -d "$vid:$pid" 2>/dev/null \
      | sed -n '1s/^.*ID [0-9a-fA-F]\{4\}:[0-9a-fA-F]\{4\} *//p')
  fi
  [[ -n $(trim "$name") ]] \
    || name="$(cat "$d/manufacturer" 2>/dev/null) $(cat "$d/product" 2>/dev/null)"
  name=$(trim "$name"); [[ -n $name ]] || name="USB device"
  echo "$name ($vid:$pid, $drv)"
}

# Wireless (has a phy) and plugged in over USB
is_usb_wifi() { [[ -e /sys/class/net/$1/phy80211 ]] && usb_dir "$1" >/dev/null; }

# The plugged-in Wi-Fi interface whose factory MAC is $1 (fails if none)
wifi_iface_for_mac() {
  local p
  for p in /sys/class/net/*; do
    is_usb_wifi "${p##*/}" || continue
    [[ $(perm_mac "${p##*/}") == "${1,,}" ]] && { echo "${p##*/}"; return 0; }
  done
  return 1
}

# Factory MAC: ethtool -P, else "permaddr" from ip (shown once the MAC was changed), else the
# current one
perm_mac() {
  local m=""
  have ethtool && m=$(ethtool -P "$1" 2>/dev/null | awk '{print tolower($NF)}')
  if [[ -z $m || $m == 00:00:00:00:00:00 ]]; then
    m=$(ip -d link show dev "$1" 2>/dev/null \
      | awk '{for (i = 1; i < NF; i++) if ($i == "permaddr") print tolower($(i + 1))}')
  fi
  [[ -n $m ]] || m=$(tr 'A-F' 'a-f' < "/sys/class/net/$1/address" 2>/dev/null)
  echo "$m"
}

# Does this phy support access point mode? ("* AP" under "Supported interface modes:")
phy_supports_ap() {
  iw phy "$1" info 2>/dev/null | awk '/Supported interface modes:/ {m = 1; next}
    m && /^[ \t]+\* / {if ($2 == "AP") f = 1; next}  m {m = 0}  END {exit !f}'
}
# Has the phy at least one enabled frequency in band $2 (2.4 or 5)?
# 5 GHz = the 51xx-58xx MHz entries (59xx and up is 6 GHz). Only "disabled" ones don't
# count: "no IR" just means the current regulatory domain forbids sending there, the
# hardware still has the channel.
band_supported() {
  local re='\* 24[0-9][0-9](\.[0-9]+)? MHz'
  [[ $2 == 5 ]] && re='\* 5[1-8][0-9]{2}(\.[0-9]+)? MHz'
  iw phy "$1" info 2>/dev/null | grep -E "$re" | grep -vq 'disabled'
}
# Can the phy run a WPA3 (SAE) access point? Needs SAE (mac80211 drivers do it in hostapd and
# show "Device supports SAE", full-MAC ones need SAE_OFFLOAD_AP, newer iw may list AKM suite
# 00-0f-ac:8) plus the CMAC cipher for the management frame protection WPA3 requires.
# The AKM match is limited to an AKM section: in "Supported Ciphers" 00-0f-ac:8 is GCMP-128.
phy_has_sae() {
  iw phy "$1" info 2>/dev/null | awk '
    /Device supports SAE/ || /\[ SAE_OFFLOAD_AP \]/ {sae = 1}
    /^[ \t]*[A-Za-z].*:[ \t]*$/ {akm = ($0 ~ /AKM/)}       # a section header line ends with ":"
    akm && /00-0f-ac:8([^0-9]|$)/ {sae = 1}
    /CMAC \(00-0f-ac:6\)/ {cmac = 1}
    END {exit !(sae && cmac)}'
}

# =============================================================================
# Bridge + firewall
#
# Qubes' own "table ip qubes" has an input chain with policy drop, and an
# accept in our own table can't override a drop in another table (each table
# is checked on its own). So the few things devices may send TO this qube
# (DHCP, DNS, optionally ping) also get tagged accept rules in the Qubes
# "custom-input" chain, which exists for exactly this; we only ever delete
# rules carrying our tag there. Everything else lives in our own two tables,
# which are replaced as a whole and never touch any other table (such as
# Qubes' own tables, which stay as they are).
# =============================================================================
# Delete our tagged rules (only those) from the Qubes custom-input chain
remove_tagged_rules() {
  local h
  # awk picks the handle (last word) of each line with our tag; the chain may not exist yet
  for h in $(nft -a list chain ip qubes custom-input 2>/dev/null \
    | awk -v t="$TAG" 'index($0, t) {print $NF}'); do
    nft delete rule ip qubes custom-input handle "$h" 2>/dev/null
  done
}

# One optional rule line: nft_opt 1|0 "rule text" (prints it only for 1)
nft_opt() { (($1)) && printf '    %s\n' "$2"; return 0; }

# The complete ruleset of our two tables, for "nft -f" (the 0/1 values pick the optional rules)
nft_rules() {
  local br=${CFG[BRIDGE]} lan=${CFG[LAN_IP]} allow dns ping has_allow iso_ports block_dot block_priv
  allow=$(echo "${CFG[MAC_ALLOWLIST],,}" | xargs | sed 's/ /, /g')
  dns=$(flag "${CFG[DNS]}")
  ping=$(flag "${CFG[ALLOW_PING]}")
  if [[ -n $allow ]]; then has_allow=1; else has_allow=0; fi
  iso_ports=$(flag "${CFG[ISOLATE_USB_PORTS]}")
  block_dot=$((1 - $(flag "${CFG[ALLOW_DOT]}")))
  block_priv=$(flag "${CFG[BLOCK_PRIVATE]}")
  # "table x" + "delete table x" first: replaces the table in one go even if it did not exist
  cat <<NFT
table bridge tether
delete table bridge tether
table bridge tether {
  # Switch level: frames between the bridge ports, before any routing.
  # DHCP guard: DHCP server replies (from port 67) arriving on a port are dropped before
  # they reach the other ports or this qube, so only our dnsmasq can hand out addresses
  # (catches a phone or router on a cable that runs its own DHCP server).
  chain forward {
    type filter hook forward priority 0; policy accept;
    meta ibrname "$br" udp sport 67 counter drop
$(nft_opt "$iso_ports" "meta ibrname \"$br\" counter drop comment \"ISOLATE_USB_PORTS\"")
  }
  chain input {
    type filter hook input priority 0; policy accept;
    meta ibrname "$br" udp sport 67 counter drop
$(nft_opt "$has_allow" "meta ibrname \"$br\" ether saddr != { $allow } counter drop comment \"MAC_ALLOWLIST\"")
  }
}
table ip tether
delete table ip tether
table ip tether {
  chain antispoof {
    type filter hook prerouting priority raw; policy accept;
    iifname "$br" ip saddr != { 0.0.0.0, ${CFG[LAN_NET]} } counter drop comment "only our subnet (0.0.0.0 = DHCP request)"
    iifname "$br" ip frag-off & 0x1fff != 0 counter drop comment "no IP fragments (a classic exploit route)"
  }
  chain dns_redirect {
    type nat hook prerouting priority dstnat; policy accept;
$(nft_opt "$dns" "iifname \"$br\" udp dport 53 ip daddr != $lan counter redirect to :53 comment \"any DNS server -> our dnsmasq\"")
$(nft_opt "$dns" "iifname \"$br\" tcp dport 53 ip daddr != $lan counter redirect to :53")
  }
  chain input {
    type filter hook input priority filter; policy accept;
    iifname "$br" ct state invalid counter drop
    iifname "$br" udp dport 67 accept
$(nft_opt "$dns" "iifname \"$br\" meta l4proto { tcp, udp } th dport 53 accept")
$(nft_opt "$ping" "iifname \"$br\" icmp type echo-request accept")
    iifname "$br" counter drop comment "nothing else from the devices to this qube"
  }
  chain forward {
    type filter hook forward priority filter; policy accept;
    iifname "$br" ct state invalid counter drop
$(nft_opt "$block_dot" "iifname \"$br\" tcp dport 853 counter drop comment \"DNS-over-TLS, see ALLOW_DOT\"")
$(nft_opt "$dns" "iifname \"$br\" meta l4proto { tcp, udp } th dport 53 counter drop comment \"backstop behind the DNS redirect\"")
$(nft_opt "$((1 - ping))" "iifname \"$br\" icmp type echo-request counter drop comment \"ALLOW_PING=0\"")
$(nft_opt "$block_priv" "iifname \"$br\" ip daddr ${CFG[PRIVATE_NETS]} counter drop comment \"BLOCK_PRIVATE\"")
    iifname "$br" oifname "${CFG[UPLINK]}" counter accept comment "internet only"
    iifname "$br" counter drop comment "anywhere else"
    oifname "$br" ct state established,related counter accept
    oifname "$br" counter drop comment "nothing new from outside"
  }
  chain nat_out {
    type nat hook postrouting priority srcnat; policy accept;
    iifname "$br" oifname "${CFG[UPLINK]}" counter masquerade comment "oifname: follows a NetVM switch by itself"
  }
}
NFT
}

# Load our tables, then add our tagged accept rules to the Qubes input chain
nft_apply() {
  local f=$RUN_DIR/nft.rules
  nft_rules | grep -v '^$' > "$f"
  try nft -f "$f" || return 1
  remove_tagged_rules
  qubes_accept udp dport 67 || return 1
  if [[ ${CFG[DNS]} == 1 ]]; then
    qubes_accept udp dport 53 || return 1
    qubes_accept tcp dport 53 || return 1
  fi
  if [[ ${CFG[ALLOW_PING]} == 1 ]]; then
    qubes_accept icmp type echo-request || return 1
  fi
  return 0
}
# One tagged accept rule for traffic from the bridge in the Qubes input chain: qubes_accept MATCH...
qubes_accept() {
  try nft add rule ip qubes custom-input iifname "${CFG[BRIDGE]}" "$@" accept "$TAG"
}

# Prints what is missing (nothing, and success, if everything is in place)
tether_check() {
  local br=${CFG[BRIDGE]}
  ip link show "$br" >/dev/null 2>&1 || { echo "bridge $br missing"; return 1; }
  ip -4 -o addr show dev "$br" 2>/dev/null | grep -qF " ${CFG[LAN_IP]}/" \
    || { echo "bridge address missing"; return 1; }
  nft list table ip tether >/dev/null 2>&1 || { echo "nft table ip tether missing"; return 1; }
  nft list table bridge tether >/dev/null 2>&1 \
    || { echo "nft table bridge tether missing"; return 1; }
  nft list chain ip qubes custom-input 2>/dev/null | grep -qF "$TAG" \
    || { echo "rules in the Qubes input chain missing"; return 1; }
  [[ $(cat /proc/sys/net/ipv4/ip_forward) == 1 ]] || { echo "ip_forward is off"; return 1; }
  return 0
}

# Build the bridge and firewall (safe to repeat). BRIDGE_NEW=1 if the bridge had to be created.
tether_up() {
  local br=${CFG[BRIDGE]} prefix=${CFG[LAN_NET]#*/} s
  BRIDGE_NEW=0
  if ! ip link show "$br" >/dev/null 2>&1; then
    try ip link add "$br" type bridge || return 1
    BRIDGE_NEW=1
  fi
  # ports pass traffic at once
  try ip link set "$br" type bridge stp_state 0 forward_delay 0 || return 1
  # IPv4 only: nothing to filter on IPv6
  echo 1 > "/proc/sys/net/ipv6/conf/$br/disable_ipv6"
  try ip addr replace "${CFG[LAN_IP]}/$prefix" dev "$br" || return 1
  try ip link set "$br" up || return 1
  # Kernel hardening for the bridge: no impossible source addresses, no redirects, no source routing
  for s in "rp_filter 1" "accept_redirects 0" "send_redirects 0" "accept_source_route 0"; do
    echo "${s#* }" > "/proc/sys/net/ipv4/conf/$br/${s% *}"
  done
  # Remember whether forwarding was off before us, so taking the tether down restores that
  [[ -f $RUN_DIR/ip_forward.orig ]] \
    || cat /proc/sys/net/ipv4/ip_forward > "$RUN_DIR/ip_forward.orig"
  echo 1 > /proc/sys/net/ipv4/ip_forward
  nft_apply || return 1
  attach_adapters
  return 0
}

# Remove our rules, tables and bridge, take the adapters down and restore ip_forward
tether_down() {
  local i
  remove_tagged_rules
  nft delete table ip tether 2>/dev/null
  nft delete table bridge tether 2>/dev/null
  ip link del "${CFG[BRIDGE]}" 2>/dev/null          # adapters drop out of it automatically
  wired_ifaces "${CFG[ADAPTER_PATTERN]}"
  for i in "${WIRED_IFACES[@]}"; do ip link set "$i" down 2>/dev/null; done
  if [[ -f $RUN_DIR/ip_forward.orig ]]; then
    cat "$RUN_DIR/ip_forward.orig" > /proc/sys/net/ipv4/ip_forward
    rm -f "$RUN_DIR/ip_forward.orig"
  fi
  return 0
}

# =============================================================================
# Wired adapters
# =============================================================================
# Put every matching, not-skipped wired adapter into the bridge (safe to repeat)
attach_adapters() {
  local i
  wired_ifaces "${CFG[ADAPTER_PATTERN]}"
  for i in "${WIRED_IFACES[@]}"; do
    is_skipped "$i" && continue
    if [[ $(bridge_of "$i") != "${CFG[BRIDGE]}" ]]; then
      echo 1 > "/proc/sys/net/ipv6/conf/$i/disable_ipv6" 2>/dev/null
      try ip link set "$i" master "${CFG[BRIDGE]}" && log "adapter $i joined ${CFG[BRIDGE]}"
    fi
    ip link set "$i" up 2>/dev/null
  done
}

# Adapters still in "CD mode": send their switch message once per plug-in
declare -A CD_DONE=()
switch_cdmode_adapters() {
  local d e vid pid key msg
  [[ -n ${CFG[CDMODE_SWITCH]} ]] || return 0
  for d in /sys/bus/usb/devices/*; do
    [[ -f $d/idVendor && -f $d/devnum ]] || continue
    vid=$(cat "$d/idVendor"); pid=$(cat "$d/idProduct")
    for e in ${CFG[CDMODE_SWITCH]}; do
      [[ ${e%%=*} == "$vid:$pid" ]] || continue
      key="$(cat "$d/busnum"):$(cat "$d/devnum")"
      [[ -n ${CD_DONE[$key]:-} ]] && continue
      CD_DONE[$key]=1; msg=${e#*=}
      if ! have usb_modeswitch; then
        log "adapter $vid:$pid is in CD mode, but usb_modeswitch is missing (run tether install)"
        continue
      fi
      log "adapter $vid:$pid is in CD mode, switching it to network mode"
      if usb_modeswitch -v "0x$vid" -p "0x$pid" -b "$(cat "$d/busnum")" -g "$(cat "$d/devnum")" \
        -M "$msg" >/dev/null 2>&1; then
        log "switch command sent to $vid:$pid; it reconnects as a network adapter" \
          "(on Qubes attach it to this qube again)"
      else
        log "switching $vid:$pid failed"
      fi
    done
  done
}

# Plug/unplug and cable (link) changes of wired adapters, logged as in the old watch.sh
declare -A SEEN=() CABLE=()
wired_scan() {
  local i now c
  declare -A cur=()
  wired_ifaces "${CFG[ADAPTER_PATTERN]}"
  for i in "${WIRED_IFACES[@]}"; do
    cur[$i]=1
    if [[ -z ${SEEN[$i]:-} ]]; then
      SEEN[$i]=1
      if is_skipped "$i"; then
        log "skipped $i: driver $(driver_of "$i") is a phone sharing its internet, not added"
        SEEN[$i]=skip; continue
      fi
      log "adapter $i plugged in ($(usb_desc "$i"))"
      attach_adapters
    fi
    [[ ${SEEN[$i]} == skip ]] && continue
    now=$(cat "/sys/class/net/$i/carrier" 2>/dev/null || echo 0)
    c=${CABLE[$i]:-0}
    if [[ $now == 1 && $c != 1 ]]; then log "link up on $i (cable connected)"
    elif [[ $now != 1 && $c == 1 ]]; then log "link down on $i (cable unplugged)"; fi
    CABLE[$i]=$now
  done
  for i in "${!SEEN[@]}"; do
    [[ -n ${cur[$i]:-} ]] && continue
    [[ ${SEEN[$i]} == skip ]] || log "adapter $i removed"
    unset "SEEN[$i]" "CABLE[$i]"
  done
}

# =============================================================================
# Uplink: this qube's address/gateway changes when the NetVM is switched
# =============================================================================
# "ADDRESS via GATEWAY" of UPLINK right now ("none" for a missing part)
uplink_now() {
  local a g
  a=$(ip -4 -o addr show dev "${CFG[UPLINK]}" 2>/dev/null | awk '{print $4; exit}')
  g=$(ip -4 route show default dev "${CFG[UPLINK]}" 2>/dev/null | awk '{print $3; exit}')
  echo "${a:-none} via ${g:-none}"
}
UPLINK_LAST=""
# Log the uplink address once, and re-apply the firewall when it changes
check_uplink() {
  local now; now=$(uplink_now)
  if [[ -z $UPLINK_LAST ]]; then log "uplink ${CFG[UPLINK]}: $now"
  elif [[ $now != "$UPLINK_LAST" ]]; then
    log "uplink changed: $UPLINK_LAST -> $now; re-applying firewall rules"
    nft_apply || log "re-applying firewall rules failed"
  fi
  UPLINK_LAST=$now
}

# =============================================================================
# dnsmasq: child of the watcher, config in /run/tether
# =============================================================================
# dnsmasq.conf for the settings in CFG (DNS and DHCP parts as switched on)
write_dnsmasq_conf() {
  local f=$RUN_DIR/dnsmasq.conf w
  {
    echo "interface=${CFG[BRIDGE]}"
    echo "bind-interfaces"
    echo "except-interface=lo"
    echo "dhcp-leasefile=$LEASES"
    if [[ ${CFG[DNS]} == 1 ]]; then
      echo "no-resolv"
      echo "no-hosts"                  # don't hand out this qube's /etc/hosts names
      echo "server=${CFG[UPSTREAM_DNS1]}"
      [[ -n ${CFG[UPSTREAM_DNS2]} ]] && echo "server=${CFG[UPSTREAM_DNS2]}"
      echo "domain-needed"
      echo "bogus-priv"
      echo "stop-dns-rebind"
      echo "cache-size=1000"
      [[ -n ${CFG[DNS_BLOCKLIST]} ]] && echo "addn-hosts=${CFG[DNS_BLOCKLIST]}"
    else
      echo "port=0"
    fi
    if [[ ${CFG[DHCP]} == 1 ]]; then
      echo "dhcp-range=${CFG[DHCP_START]},${CFG[DHCP_END]},${CFG[LEASE_TIME]}"
      echo "dhcp-option=option:router,${CFG[LAN_IP]}"
      if [[ ${CFG[DNS]} == 1 ]]; then echo "dhcp-option=option:dns-server,${CFG[LAN_IP]}"
      else echo "dhcp-option=option:dns-server"; fi
      echo "dhcp-authoritative"
      echo "dhcp-rapid-commit"
      for w in ${CFG[STATIC_LEASES]}; do echo "dhcp-host=${w%%=*},${w#*=}"; done
      if [[ -n ${CFG[MAC_ALLOWLIST]} ]]; then
        for w in ${CFG[MAC_ALLOWLIST]}; do echo "dhcp-host=$w"; done
        echo "dhcp-ignore=tag:!known"
      fi
    fi
  } > "$f"
}

DNSMASQ_PID=""; DNSMASQ_FAILS=0; DNSMASQ_WAIT_UNTIL=0
# Does the conf need dnsmasq at all? (DHCP or DNS on)
dnsmasq_wanted() { [[ ${CFG[DHCP]} == 1 || ${CFG[DNS]} == 1 ]]; }
# Start dnsmasq in the background for the bridge (if DHCP or DNS is on)
start_dnsmasq() {
  dnsmasq_wanted || return 0
  have dnsmasq || { log "dnsmasq is missing (run tether install)"; return 1; }
  write_dnsmasq_conf
  dnsmasq --keep-in-foreground --conf-file="$RUN_DIR/dnsmasq.conf" --pid-file= \
    --user=dnsmasq --group=nogroup --log-facility=- > >(log_lines "dnsmasq: ") 2>&1 &
  DNSMASQ_PID=$!
  log "dnsmasq started (pid $DNSMASQ_PID)"
}
stop_dnsmasq() {
  if alive "$DNSMASQ_PID"; then kill "$DNSMASQ_PID" 2>/dev/null; wait "$DNSMASQ_PID" 2>/dev/null; fi
  DNSMASQ_PID=""
}
# Restart dnsmasq if it died; after 3 deaths in a row wait RETRY_AFTER_FAIL first
check_dnsmasq() {
  local rc
  dnsmasq_wanted || return 0
  [[ -n $DNSMASQ_PID ]] && alive "$DNSMASQ_PID" && return 0
  if [[ -n $DNSMASQ_PID ]]; then
    wait "$DNSMASQ_PID" 2>/dev/null; rc=$?
    log "dnsmasq (pid $DNSMASQ_PID) died (exit status $rc), restarting it"
    DNSMASQ_PID=""; DNSMASQ_FAILS=$((DNSMASQ_FAILS + 1))
    if ((DNSMASQ_FAILS >= 3)); then
      log "dnsmasq failed $DNSMASQ_FAILS times in a row, next try in ${CFG[RETRY_AFTER_FAIL]}s"
      DNSMASQ_WAIT_UNTIL=$((SECONDS + CFG[RETRY_AFTER_FAIL])); DNSMASQ_FAILS=0
    fi
  fi
  ((SECONDS >= DNSMASQ_WAIT_UNTIL)) || return 0
  start_dnsmasq
}

# =============================================================================
# Wi-Fi dongles: one hostapd child each, the AP joins the bridge (bridge=)
#
# W_STATE[iface]: running | failed (retry after RETRY_AFTER_FAIL) | skipped
#                 (config error, waits for reload/replug) | noap | nohostapd
# $RUN_DIR/dongles lists the factory MACs of plugged dongles that got a fresh
# (non-sticky) block, so their block is removed when they are unplugged.
# =============================================================================
declare -A W_STATE=() W_PID=() W_MAC=() W_CHAN=() W_BAND=() W_SSID=() W_RETRY=() W_FAILS=()
declare -A W_ORIG=()
declare -A W_SEC=() W_STARTED=() W_NOSAE=()   # security in use, start time, 1 = no WPA3 (use wpa2)
# 1 = "country not applied" was logged (once per plug-in)
declare -A W_NOREG=()
# The per-dongle arrays above that are forgotten when the dongle is unplugged (W_PID: by wifi_stop)
W_ARRAYS=(W_STATE W_MAC W_CHAN W_BAND W_SSID W_RETRY W_FAILS W_ORIG W_SEC W_STARTED W_NOSAE W_NOREG)
W_CUR_CHAN=""      # set by pick_channel
W_CUR_SEC=""       # set by wifi_pick_security
W_CUR_BAND=""      # set by wifi_pick_band
HOSTAPD_MISSING_LOGGED=0

known_dongle() { grep -qixF -- "$1" "$RUN_DIR/dongles" 2>/dev/null; }
known_add() { known_dongle "$1" || echo "${1,,}" >> "$RUN_DIR/dongles"; }
known_del() { [[ -f $RUN_DIR/dongles ]] && sed -i "/^${1,,}\$/d" "$RUN_DIR/dongles"; return 0; }

# Dongle $1 is left alone until reload or replug: log why ($2...) and mark it skipped
wifi_skip() { local i=$1; shift; log "Wi-Fi $i: $*"; W_STATE[$i]=skipped; }
# Dongle $1 failed: retry it after RETRY_AFTER_FAIL seconds
wifi_fail() { W_STATE[$1]=failed; W_RETRY[$1]=$((SECONDS + CFG[RETRY_AFTER_FAIL])); }
# Dongle $1 can't do WPA3: use wpa2 from now on (said once per plug-in)
wifi_no_wpa3() {
  [[ -n ${W_NOSAE[$1]:-} ]] || log "Wi-Fi $1: this dongle can't do WPA3, using wpa2"
  W_NOSAE[$1]=1
}

# -----------------------------------------------------------------------------
# Wi-Fi: keeping the [device] blocks of the conf in step
# -----------------------------------------------------------------------------
# At watcher start: drop non-sticky blocks of dongles that are not plugged in
# (left over from a crash or reboot; they would get a new SSID on plug-in anyway)
wifi_cleanup_conf() {
  local d plugged="" p changed=1
  for p in /sys/class/net/*; do is_usb_wifi "${p##*/}" && plugged+=" $(perm_mac "${p##*/}")"; done
  while ((changed)); do
    changed=0
    reparse
    for ((d = 0; d < DEV_COUNT; d++)); do
      [[ ${DEV_STICKY[d]} == 1 || -z ${DEV_HARDWARE_MAC[d]} ]] && continue
      [[ " $plugged " == *" ${DEV_HARDWARE_MAC[d],,} "* ]] && continue
      log "removing the [device] block of ${DEV_HARDWARE_MAC[d]} (not plugged in, STICKY=0)"
      conf_remove_device "$d"; changed=1; break
    done
  done
}

# The lines wifi_clear_conf removes, found by the section header lines alone (a block
# whose values do not parse is found too): from the Wi-Fi header (or the first [device]
# line if the header was deleted) to the end of the file, every [section] line and all
# lines after it, plus stray lines before the first of them that are not blank, a
# comment or a known top setting. The header itself stays.
# Fills WIFI_DEL_LINES[N]=1 for each such line and WIFI_DEL_BLOCKS ("LINE|what") for each
# removed block or run of stray lines, "what" being its MAC or "unreadable block at line N".
declare -A WIFI_DEL_LINES=()
declare -a WIFI_DEL_BLOCKS=()
wifi_region() {
  local n start=0 line cur=0 mac="" dev=0 total insec=0
  local -a lines=()
  WIFI_DEL_LINES=(); WIFI_DEL_BLOCKS=()
  [[ -r $1 ]] || return 1
  mapfile -t lines < "$1"
  total=${#lines[@]}
  for ((n = 1; n <= total; n++)); do
    line=$(trim "${lines[n - 1]}")
    if [[ $line == "# ---------- Wi-Fi devices"* ]]; then start=$((n + 1)); break; fi
    if [[ $line =~ ^\[device\][[:space:]]*(#.*)?$ ]]; then start=$n; break; fi
  done
  ((start > 0)) || return 0
  for ((n = start; n <= total; n++)); do
    line=$(trim "${lines[n - 1]}")
    if [[ $line == \[* ]]; then
      insec=1
      if [[ $line =~ ^\[device\][[:space:]]*(#.*)?$ ]]; then wifi_region_end_block; cur=$n; dev=1
      elif ((cur == 0)); then cur=$n
      fi
      WIFI_DEL_LINES[$n]=1; continue
    fi
    if ((insec)); then
      WIFI_DEL_LINES[$n]=1
      if ((dev)) && [[ -z $mac && $line =~ ^HARDWARE_MAC=(.*)$ ]] \
        && parse_value "${BASH_REMATCH[1]}"; then
        mac=$VALUE
      fi
      continue
    fi
    # before the first [section]: keep blank lines, comments and known top settings
    if [[ -z $line || $line == \#* ]] \
      || { [[ $line =~ ^([A-Za-z_][A-Za-z0-9_]*)= ]] \
        && spec_type "${BASH_REMATCH[1]}" >/dev/null; }; then
      wifi_region_end_block; continue
    fi
    ((cur > 0)) || cur=$n
    WIFI_DEL_LINES[$n]=1
  done
  wifi_region_end_block
  return 0
}
# wifi_region_end_block: close the block that is open (cur = its first line)
# Called only from wifi_region: it reads and resets wifi_region's locals cur, mac and dev
# (bash functions see the local variables of the function that called them).
wifi_region_end_block() {
  ((cur > 0)) || return 0
  if ((dev)) && is_mac "$mac"; then WIFI_DEL_BLOCKS+=("$cur|[device] block of $mac")
  else WIFI_DEL_BLOCKS+=("$cur|unreadable block at line $cur"); fi
  cur=0; mac=""; dev=0
}

# With WIFI=0 (as parsed), drop from the last parse_conf of $1 the errors and notes on
# lines that wifi_clear_conf is about to remove: they must not stop reload or the watcher
conf_drop_wifi_errs() {
  [[ ${PARSED[WIFI]} == 0 ]] || return 0
  wifi_region "$1" || return 0
  ((${#WIFI_DEL_LINES[@]})) || return 0
  mapfile -t ERRS < <(drop_msgs_on_deleted_lines "${ERRS[@]}")
  mapfile -t TOP_ERRS < <(drop_msgs_on_deleted_lines "${TOP_ERRS[@]}")
  mapfile -t TOP_ERRS_PUBLIC < <(drop_msgs_on_deleted_lines "${TOP_ERRS_PUBLIC[@]}")
  mapfile -t NOTES < <(drop_msgs_on_deleted_lines "${NOTES[@]}")
  return 0
}
# Print the messages ("line N: ...") that are not on a line in WIFI_DEL_LINES
drop_msgs_on_deleted_lines() {
  local e
  for e; do
    [[ $e =~ ^line\ ([0-9]+): && -n ${WIFI_DEL_LINES[${BASH_REMATCH[1]}]:-} ]] || printf '%s\n' "$e"
  done
  return 0
}

# At watcher start with WIFI=0: remove every [device] block, sticky ones and broken
# ones too (the section header line stays), and stop any hostapd of ours left behind
wifi_clear_conf() {
  local n e
  local -a lines=()
  pkill -f "^hostapd $RUN_DIR/" 2>/dev/null
  rm -f "$RUN_DIR"/hostapd-*.conf "$RUN_DIR"/hostapd-*.out "$RUN_DIR/dongles"
  if ! wifi_region "$CONF"; then
    log "WIFI=0: could not read $CONF to remove the [device] blocks"; return 1
  fi
  ((${#WIFI_DEL_LINES[@]})) || return 0
  mapfile -t lines < "$CONF"
  CONF_OUT=()
  for ((n = 1; n <= ${#lines[@]}; n++)); do
    [[ -n ${WIFI_DEL_LINES[$n]:-} ]] || CONF_OUT+=("${lines[n - 1]}")
  done
  conf_write || { log "WIFI=0: could not remove the [device] blocks from $CONF"; return 1; }
  for e in "${WIFI_DEL_BLOCKS[@]}"; do log "WIFI=0: removed the ${e#*|}"; done
  return 0
}

# -----------------------------------------------------------------------------
# Wi-Fi: starting and stopping access points
# -----------------------------------------------------------------------------
# Pick a channel for interface $1: fixed, or for auto the first of the band's
# defaults that none of our other running dongles uses (rotated after failures).
# $3 = the band actually used, if it differs from BAND (2.4 GHz fallback): then the
# block's CHANNEL belongs to the other band and auto is used.
pick_channel() {
  local i=$1 d=$2 band=${3:-${DEV_BAND[$2]}} c used="" o n k
  local -a list
  W_CUR_CHAN=${DEV_CHANNEL[d]}
  [[ $band == "${DEV_BAND[d]}" ]] || W_CUR_CHAN=auto
  [[ $W_CUR_CHAN == auto ]] || return 0
  for o in "${!W_STATE[@]}"; do
    [[ $o != "$i" && ${W_STATE[$o]} == running ]] && used+=" ${W_CHAN[$o]}"
  done
  if [[ $band == 5 ]]; then list=("${CH_5[@]}"); else list=("${CH_24[@]}"); fi
  n=${#list[@]}
  for ((k = 0; k < n; k++)); do
    c=${list[(k + ${W_FAILS[$i]:-0}) % n]}
    [[ " $used " == *" $c "* ]] && continue
    W_CUR_CHAN=$c; return 0
  done
  W_CUR_CHAN=${list[${W_FAILS[$i]:-0} % n]}     # all taken: share one
}

# Set country $2 for phy $1 and check that the kernel took it: "iw reg get" must show
# "country XX" in the global section or in the phy's own one ("phy#N", self-managed
# drivers). The kernel accepts "iw reg set" even when it can't use it (e.g. it rejects
# the signature of regulatory.db), it then just stays at 00, so only reading it back
# tells. The change is applied asynchronously, so it is polled for up to 3 s.
country_applied() {
  local phy=$1 cc=$2 k
  iw reg set "$cc" 2>/dev/null
  for ((k = 0; k < 6; k++)); do
    iw reg get 2>/dev/null | awk -v cc="$cc" -v me="phy#${phy#phy}" '
      /^global/ {sec = "global"; next}
      /^phy#/ {sec = $1; next}
      (sec == "global" || sec == me) && $1 == "country" && $2 == cc ":" {ok = 1}
      END {exit !ok}' && return 0
    sleep 0.5
  done
  return 1
}

# Start hostapd for interface $1 using [device] block $2
wifi_start() {
  local i=$1 d=$2 phy
  phy=$(phy_of "$i")
  if ! band_supported "$phy" "${DEV_BAND[d]}"; then
    wifi_skip "$i" "config error: ${DEV_BAND[d]} GHz is not supported by this dongle" \
      "(line ${DEV_LINE["$d.BAND"]:-${DEV_START[d]}}); set BAND and run tether reload"
    return 1
  fi
  wifi_pick_security "$i" "$d" "$phy" || return 1
  wifi_pick_band "$i" "$d" "$phy"
  pick_channel "$i" "$d" "$W_CUR_BAND"
  W_ORIG[$i]=$(cat "/sys/class/net/$i/address")
  ip link set "$i" down 2>/dev/null
  if [[ ${DEV_RANDOMIZE_MAC[d]} == 1 ]]; then
    try ip link set "$i" address "$(rand_mac)" \
      || log "Wi-Fi $i: could not set a random MAC, using the real one"
  fi
  write_hostapd_conf "$i" "$d"
  wifi_launch "$i" "$d"
}

# Set W_CUR_SEC to the security dongle $1 runs block $2 with (fails if it can't run at all)
wifi_pick_security() {
  local i=$1 d=$2 phy=$3 sec
  # WPA3 needs SAE in the dongle. wpa2+wpa3 falls back to wpa2 (only for this run, the conf
  # stays as it is); an explicit wpa3 is never downgraded silently.
  sec=${DEV_SECURITY[d]}
  if [[ $sec == wpa3 || $sec == wpa2+wpa3 ]] \
    && { [[ -n ${W_NOSAE[$i]:-} ]] || ! phy_has_sae "$phy"; }; then
    if [[ $sec == wpa3 ]]; then
      wifi_skip "$i" "config error: this dongle can't do WPA3 (no SAE support)," \
        "so SECURITY=wpa3 can't work (line ${DEV_LINE["$d.SECURITY"]:-${DEV_START[d]}});" \
        "set SECURITY=wpa2+wpa3 or wpa2 and run tether reload"
      return 1
    fi
    wifi_no_wpa3 "$i"; sec=wpa2
  fi
  W_CUR_SEC=$sec
}

# Set W_CUR_BAND to the band dongle $1 runs block $2 on
wifi_pick_band() {
  local i=$1 d=$2 phy=$3 band
  # 5 GHz access points need the country really set (in 00 every 5 GHz channel is no-IR and
  # hostapd would fail and be retried forever). If the kernel did not take it, run this
  # plug-in on 2.4 GHz instead (if the dongle has it); the conf stays as it is.
  band=${DEV_BAND[d]}
  if [[ $band == 5 && -n ${DEV_COUNTRY_CODE[d]} ]] && band_supported "$phy" 2.4 \
    && ! country_applied "$phy" "${DEV_COUNTRY_CODE[d]}"; then
    [[ -n ${W_NOREG[$i]:-} ]] || log "Wi-Fi $i: country ${DEV_COUNTRY_CODE[d]} not applied" \
      "(kernel rejected regulatory.db), 5 GHz unavailable, using 2.4 GHz"
    W_NOREG[$i]=1; band=2.4
  fi
  W_CUR_BAND=$band
}

# Write $RUN_DIR/hostapd-$1.conf for block $2 (root only: it holds the password) and empty
# hostapd's output file; uses W_CUR_SEC, W_CUR_BAND and W_CUR_CHAN
write_hostapd_conf() {
  local i=$1 d=$2 f=$RUN_DIR/hostapd-$1.conf out=$RUN_DIR/hostapd-$1.out mode
  if [[ $W_CUR_BAND == 5 ]]; then mode=a; else mode=g; fi
  (
    umask 077
    {
      echo "interface=$i"
      echo "bridge=${CFG[BRIDGE]}"
      echo "driver=nl80211"
      echo "ssid2=\"${DEV_SSID[d]}\""                # quoted form: any printable SSID
      echo "utf8_ssid=1"
      echo "hw_mode=$mode"
      echo "channel=$W_CUR_CHAN"
      if [[ -n ${DEV_COUNTRY_CODE[d]} ]]; then
        echo "country_code=${DEV_COUNTRY_CODE[d]}"   # hostapd sets the regulatory domain to it
        echo "ieee80211d=1"                          # announce the country in beacons
        # 802.11h (radar detection/DFS) only for the DFS channels 52-144; 36-48 don't need it
        [[ $mode == a ]] && ((W_CUR_CHAN >= 52 && W_CUR_CHAN <= 144)) && echo "ieee80211h=1"
      fi
      [[ $mode == g ]] && echo "ieee80211n=1"
      [[ $mode == a ]] && printf 'ieee80211n=1\nieee80211ac=1\n'
      echo "wmm_enabled=1"
      echo "ignore_broadcast_ssid=$(flag "${DEV_HIDDEN[d]}")"
      echo "ap_isolate=$(flag "${CFG[ISOLATE_WIFI_CLIENTS]}")"
      echo "auth_algs=1"
      echo "ctrl_interface=$RUN_DIR/hostapd"
      hostapd_security "$W_CUR_SEC" "${DEV_PASS[d]}"
    } > "$f"
    : > "$out"
  )
}

# hostapd lines for SECURITY $1 with password $2 (nothing for open)
hostapd_security() {
  case $1 in
    wpa2) printf 'wpa=2\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\nwpa_passphrase=%s\n' "$2" ;;
    wpa3)
      printf 'wpa=2\nwpa_key_mgmt=SAE\nrsn_pairwise=CCMP\nieee80211w=2\nsae_password=%s\n' "$2" ;;
    # transition mode: WPA2 clients use PSK, WPA3 clients SAE; PMF optional (1) but
    # required for the SAE clients (sae_require_mfp)
    wpa2+wpa3)
      printf 'wpa=2\nwpa_key_mgmt=WPA-PSK SAE\nrsn_pairwise=CCMP\nieee80211w=1\nsae_require_mfp=1\n'
      printf 'wpa_passphrase=%s\nsae_password=%s\n' "$2" "$2" ;;
  esac
}

# Run hostapd for dongle $1 (block $2) in the background and record it as running
wifi_launch() {
  local i=$1 d=$2 pid out=$RUN_DIR/hostapd-$1.out
  # hostapd's output also goes to $out, to find out why it stopped (see wifi_scan)
  hostapd "$RUN_DIR/hostapd-$i.conf" > >(tee -a "$out" | log_lines "hostapd $i: ") 2>&1 &
  pid=$!
  W_PID[$i]=$pid; W_STATE[$i]=running; W_CHAN[$i]=$W_CUR_CHAN; W_BAND[$i]=$W_CUR_BAND
  W_SSID[$i]=${DEV_SSID[d]}; W_SEC[$i]=$W_CUR_SEC; W_STARTED[$i]=$SECONDS
  log "Wi-Fi $i: access point \"${DEV_SSID[d]}\" starting on $W_CUR_BAND GHz channel $W_CUR_CHAN," \
    "country ${DEV_COUNTRY_CODE[d]:-not set (world)} (hostapd pid $pid, $W_CUR_SEC)"
}

# Stop the hostapd of interface $1 and give the interface its original MAC back
wifi_stop() {
  local i=$1 pid=${W_PID[$1]:-}
  if alive "$pid"; then kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; fi
  rm -f "$RUN_DIR/hostapd-$i.conf" "$RUN_DIR/hostapd-$i.out"
  if [[ -e /sys/class/net/$i && -n ${W_ORIG[$i]:-} ]]; then
    ip link set "$i" down 2>/dev/null
    ip link set "$i" address "${W_ORIG[$i]}" 2>/dev/null
  fi
  unset "W_PID[$i]"
}
wifi_stop_all() { local i; for i in "${!W_STATE[@]}"; do wifi_stop "$i"; done; }

# -----------------------------------------------------------------------------
# Wi-Fi: plug-in, unplug and the per-check scan
# -----------------------------------------------------------------------------
# Interface $1 vanished: stop its hostapd, drop its block unless sticky
wifi_unplugged() {
  local i=$1 mac=${W_MAC[$1]:-} d a
  log "Wi-Fi dongle $i removed"
  wifi_stop "$i"
  if [[ -n $mac ]] && known_dongle "$mac"; then
    reparse
    d=$(device_index "$mac")
    if ((d >= 0)) && [[ ${DEV_STICKY[d]} != 1 ]]; then
      conf_remove_device "$d" && log "removed its [device] block from $CONF (STICKY=0)"
    fi
    known_del "$mac"
  fi
  for a in "${W_ARRAYS[@]}"; do unset "${a}[$i]"; done
}

# A new dongle (interface $1): find or create its block, then start it
wifi_plugged() {
  local i=$1 mac phy d band no5
  mac=$(perm_mac "$i"); W_MAC[$i]=$mac
  phy=$(phy_of "$i")
  log "Wi-Fi dongle $i plugged in: $(usb_desc "$i"), factory MAC $mac"
  if ! phy_supports_ap "$phy"; then
    log "Wi-Fi $i: this dongle can't be an access point (no AP mode in iw), ignoring it"
    W_STATE[$i]=noap; return 0
  fi
  if ! have hostapd; then
    ((HOSTAPD_MISSING_LOGGED)) \
      || log "hostapd is missing, Wi-Fi access points are off (run tether install);" \
        "cables keep working"
    HOSTAPD_MISSING_LOGGED=1; W_STATE[$i]=nohostapd; return 0
  fi
  reparse
  d=$(device_index "$mac")
  if ((d >= 0)) && [[ ${DEV_STICKY[d]} != 1 ]] && ! known_dongle "$mac"; then
    conf_remove_device "$d"                  # old non-sticky block: start fresh
    reparse; d=-1
  fi
  if ((d < 0)); then
    band=2.4; band_supported "$phy" 2.4 || band=5               # 5 GHz-only dongles get BAND=5
    # no 5 GHz: BAND/COUNTRY_CODE commented out
    no5=0; band_supported "$phy" 5 || { no5=1; band=2.4; }
    conf_append_device "$mac" "$(usb_desc "$i")" "$band" "$no5"
    reparse
    d=$(device_index "$mac")
    if ((d < 0)); then
      log "Wi-Fi $i: could not add a [device] block to $CONF"
      wifi_fail "$i"; return 1
    fi
    log "Wi-Fi $i: added a [device] block to $CONF (SSID \"${DEV_SSID[d]}\")"
  else
    log "Wi-Fi $i: using its [device] block from $CONF (line ${DEV_START[d]})"
  fi
  known_add "$mac"
  if [[ -n ${DEV_ERRS[d]} ]]; then
    wifi_skip "$i" "config error, dongle skipped until fixed (tether reload):" \
      "${DEV_ERRS[d]//$'\n'/ ; }"
    return 0
  fi
  wifi_start "$i" "$d"
}

# One check of every USB Wi-Fi dongle: new ones, dead hostapds, retries, removed ones
wifi_scan() {
  local p i
  declare -A cur=()
  for p in /sys/class/net/*; do
    i=${p##*/}
    is_usb_wifi "$i" || continue
    cur[$i]=1
    [[ -n ${W_STATE[$i]:-} ]] || { wifi_plugged "$i"; continue; }
    case ${W_STATE[$i]} in
      running) wifi_check_running "$i" ;;
      failed) wifi_retry "$i" ;;
    esac
  done
  for i in "${!W_STATE[@]}"; do [[ -n ${cur[$i]:-} ]] || wifi_unplugged "$i"; done
}

# Dongle $1 should be running: if its hostapd died, find out why and plan the retry
wifi_check_running() {
  local i=$1 rc
  alive "${W_PID[$i]:-}" && return 0
  wait "${W_PID[$i]}" 2>/dev/null; rc=$?
  # Died right after starting with WPA3 and complained about SAE/PMF: the dongle
  # lacks WPA3 even though iw did not say so
  if [[ ${W_SEC[$i]:-} == wpa3 || ${W_SEC[$i]:-} == wpa2+wpa3 ]] \
    && ((SECONDS - ${W_STARTED[$i]:-0} < 30)) \
    && grep -qiE 'SAE|ieee80211w|MFP|PMF|BIP|key_mgmt|AKM' "$RUN_DIR/hostapd-$i.out" 2>/dev/null
  then
    wifi_stop "$i"
    if [[ ${W_SEC[$i]} == wpa3 ]]; then
      wifi_skip "$i" "config error: this dongle can't do WPA3 (hostapd failed with SAE)," \
        "so SECURITY=wpa3 can't work; set SECURITY=wpa2+wpa3 or wpa2 and run tether reload"
      return 0
    fi
    # retried with wpa2 on the next check
    wifi_no_wpa3 "$i"; W_STATE[$i]=failed; W_RETRY[$i]=0; return 0
  fi
  log "Wi-Fi $i: hostapd stopped (exit status $rc), retrying in ${CFG[RETRY_AFTER_FAIL]}s"
  wifi_stop "$i"
  W_FAILS[$i]=$((${W_FAILS[$i]:-0} + 1)); wifi_fail "$i"
}

# Dongle $1 failed earlier: once its wait is over, start it again from its current block
wifi_retry() {
  local i=$1 d
  ((SECONDS >= ${W_RETRY[$i]:-0})) || return 0
  reparse
  d=$(device_index "${W_MAC[$i]}")
  if ((d < 0)); then
    wifi_skip "$i" "its [device] block is gone from $CONF, unplug and replug to get a new one"
  elif [[ -n ${DEV_ERRS[d]} ]]; then
    wifi_skip "$i" "config error, dongle skipped: ${DEV_ERRS[d]//$'\n'/ ; }"
  else
    log "Wi-Fi $i: retrying"; wifi_start "$i" "$d"
  fi
}

# =============================================================================
# Status file: what "tether status" shows to a normal user (no secrets)
# =============================================================================
# The status file's lines: KEY=value, then one tab-separated WIFI_DONGLE line per dongle
status_lines() {
  local i n
  echo "UPDATED=$(date '+%Y-%m-%d %H:%M:%S')"
  echo "WATCHER_PID=$$"
  echo "BRIDGE=${CFG[BRIDGE]}"
  echo "LAN_IP=${CFG[LAN_IP]}"
  echo "LAN_NET=${CFG[LAN_NET]}"
  echo "UPLINK=${CFG[UPLINK]}"
  echo "ADAPTER_PATTERN=${CFG[ADAPTER_PATTERN]}"
  echo "LOG_FILE=${CFG[LOG_FILE]}"
  echo "WIFI=${CFG[WIFI]}"
  echo "DNSMASQ_PID=$DNSMASQ_PID"
  for i in "${!W_STATE[@]}"; do
    n=""
    [[ ${W_STATE[$i]} == running ]] && have iw \
      && n=$(iw dev "$i" station dump 2>/dev/null | grep -c '^Station')
    printf 'WIFI_DONGLE\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$i" "${W_STATE[$i]}" "${W_MAC[$i]:-}" \
      "${W_SSID[$i]:--}" "${W_BAND[$i]:--}" "${W_CHAN[$i]:--}" "${n:--}" "$(usb_desc "$i")"
  done
}
write_status() { atomic_write 644 "$STATUS_FILE" status_lines; }

# Read the KEY=value lines of the status file into the associative array named $1
# (the WIFI_DONGLE lines are left out)
read_status() {
  local -n _rs_into=$1
  local k v
  [[ -r $STATUS_FILE ]] || return 0
  while IFS='=' read -r k v; do [[ $k == WIFI_DONGLE* ]] || _rs_into["$k"]=$v; done < "$STATUS_FILE"
}

# =============================================================================
# The watcher (run by tether-watch.service; the only long-running part)
# =============================================================================
SLEEP_PID=""
# TERM/INT: stop the children, take the tether down and exit
watch_exit() {
  trap - TERM INT
  [[ -n $SLEEP_PID ]] && kill "$SLEEP_PID" 2>/dev/null
  log "watcher stopping: taking the tether down"
  wifi_stop_all
  stop_dnsmasq
  tether_down
  rm -f "$STATUS_FILE" "$RUN_DIR"/hostapd-*.conf
  log "watcher stopped"
  exit 0
}

# Sleep $1 seconds in the background and wait for it: wait (not plain sleep) lets the TERM
# trap run at once
watch_sleep() { sleep "$1" & SLEEP_PID=$!; wait "$SLEEP_PID"; }

# The watcher: read the conf, then build/repair the tether and scan the adapters every
# CHECK_EVERY seconds until TERM
cmd_watch() {
  local why
  mkdir -p "$RUN_DIR" && chmod 755 "$RUN_DIR"
  watch_wait_for_conf
  apply_parsed
  for why in "${NOTES[@]}"; do log "note: $why"; done
  if [[ ${CFG[LOGGING]} == 1 ]]; then touch "${CFG[LOG_FILE]}" && chmod 644 "${CFG[LOG_FILE]}"; fi
  exec 2> >(log_lines "stderr: ")          # stray errors go to the log too
  trap watch_exit TERM INT
  log "watcher started (pid $$, checking every ${CFG[CHECK_EVERY]}s)"
  if [[ ${CFG[WIFI]} == 1 ]]; then wifi_cleanup_conf; else wifi_clear_conf; fi
  while :; do
    if ! watch_ensure_tether; then watch_sleep "${CFG[RETRY_AFTER_FAIL]}"; continue; fi
    check_dnsmasq
    switch_cdmode_adapters
    wired_scan
    check_uplink
    [[ ${CFG[WIFI]} == 1 ]] && wifi_scan
    write_status
    watch_sleep "${CFG[CHECK_EVERY]}"
  done
}

# Parse the conf until its top part has no errors (it is read again every 60 s)
watch_wait_for_conf() {
  # Settings: a broken top part waits for a fix (reload restarts us); a broken
  # [device] block only skips that dongle
  # (with WIFI=0, errors in the [device] blocks that wifi_clear_conf removes don't count)
  until { parse_conf "$CONF" || true; conf_drop_wifi_errs "$CONF"; ((${#TOP_ERRS[@]} == 0)); }; do
    apply_parsed
    log "config error in $CONF, not starting until it is fixed" \
      "(tether settings, then tether reload):"
    printf '%s\n' "${TOP_ERRS[@]}" | log_lines "  "
    # "tether status" can't read the root-only conf, so it shows this copy of the errors
    atomic_write 644 "$CONF_ERR_FILE" printf '%s\n' "${TOP_ERRS_PUBLIC[@]}"
    sleep 60
  done
  rm -f "$CONF_ERR_FILE"
}

# Build the bridge and firewall if anything is missing; fails if that did not work
watch_ensure_tether() {
  local why
  why=$(tether_check) && return 0
  log "setting up the tether ($why)"
  if ! tether_up; then
    log "setting up failed, next try in ${CFG[RETRY_AFTER_FAIL]}s"
    return 1
  fi
  log "bridge ${CFG[BRIDGE]} up at ${CFG[LAN_IP]}, firewall rules in place"
  # dnsmasq is bound to the bridge, so a new bridge needs a new dnsmasq
  if ((BRIDGE_NEW)) && [[ -n $DNSMASQ_PID ]]; then
    stop_dnsmasq; log "bridge was re-created, restarting dnsmasq"
  fi
  return 0
}

# =============================================================================
# tether status
# =============================================================================
# "tether status": overview, cables, dongles, clients, firewall counters (root), last log lines
cmd_status() {
  local root=0 bridge pattern uplink logf
  local -A status=()
  ((EUID == 0)) && root=1
  # The watcher started with a broken conf top part and is waiting: the errors are all that matter
  if [[ -s $CONF_ERR_FILE ]]; then
    say "== tether =="
    say "config error, tether is not running"
    sed 's/^/  /' "$CONF_ERR_FILE"
    return 0
  fi
  read_status status
  parse_conf /dev/null >/dev/null 2>&1                      # the defaults
  ((root)) && reparse                                   # the real values (the file is root-only)
  bridge=${status[BRIDGE]:-${PARSED[BRIDGE]}}
  pattern=${status[ADAPTER_PATTERN]:-${PARSED[ADAPTER_PATTERN]}}
  uplink=${status[UPLINK]:-${PARSED[UPLINK]}}
  logf=${status[LOG_FILE]:-${PARSED[LOG_FILE]}}

  status_overview "$bridge" "$uplink" status
  status_cables "$pattern" "$bridge"
  [[ ${status[WIFI]:-${PARSED[WIFI]}} == 1 ]] && status_wifi "$root"
  status_leases
  ((root)) && have nft && status_counters
  say ""; say "== last log lines ($logf) =="
  if [[ -r $logf ]]; then tail -n 10 "$logf" | sed 's/^/  /'; else say "  (no log yet)"; fi
  ((root)) || { say ""; say "(run with sudo to also see Wi-Fi passwords and firewall counters)"; }
  return 0
}

# "== tether ==": service, watcher, uplink, bridge, dnsmasq.
# status_overview BRIDGE UPLINK STATUS_ARRAY_NAME
status_overview() {
  local br=$1 up=$2
  local -n _so_status=$3
  say "== tether =="
  if have systemctl; then say "service:   $UNIT $(systemctl is-active "$UNIT" 2>/dev/null)"; fi
  [[ -n ${_so_status[UPDATED]:-} ]] \
    && say "watcher:   pid ${_so_status[WATCHER_PID]}, last check ${_so_status[UPDATED]}"
  if have ip; then
    CFG[UPLINK]=$up
    say "uplink:    $up $(uplink_now)"
    if ip link show "$br" >/dev/null 2>&1; then
      say "bridge:    $br $(cat "/sys/class/net/$br/operstate" 2>/dev/null)," \
        "$(ip -4 -o addr show dev "$br" | awk '{print $4; exit}')"
    else say "bridge:    $br missing"; fi
  fi
  if [[ -n ${_so_status[DNSMASQ_PID]:-} ]] && [[ -d /proc/${_so_status[DNSMASQ_PID]} ]]; then
    say "dnsmasq:   running (pid ${_so_status[DNSMASQ_PID]})"
  else say "dnsmasq:   not running"; fi
}

# "== cable adapters ==": status_cables PATTERN BRIDGE
status_cables() {
  local pat=$1 br=$2 i cable membership found=0
  say ""; say "== cable adapters ($pat*) =="
  wired_ifaces "$pat"
  for i in "${WIRED_IFACES[@]}"; do
    found=1
    cable="no cable"
    [[ $(cat "/sys/class/net/$i/carrier" 2>/dev/null) == 1 ]] && cable="cable connected"
    membership="not in bridge"
    [[ $(bridge_of "$i") == "$br" ]] && membership="in $br"
    say "  $i: $cable, $membership, $(usb_desc "$i")"
  done
  ((found)) || say "  none plugged in"
}

# "== Wi-Fi dongles ==" from the status file; with $1 = 1 (root) also their passwords
status_wifi() {
  local root=$1 i st mac ssid band chan clients desc idx found=0
  say ""; say "== Wi-Fi dongles =="
  while IFS=$'\t' read -r _ i st mac ssid band chan clients desc; do
    found=1
    say "  $i: $desc"
    say "     $st, SSID \"$ssid\", $band GHz, channel $chan, clients $clients"
    if ((root)) && idx=$(device_index "$mac"); then
      say "     password: ${DEV_PASS[idx]:-} (${DEV_SECURITY[idx]})"
    fi
  done < <(grep $'^WIFI_DONGLE\t' "$STATUS_FILE" 2>/dev/null)
  ((found)) || say "  none plugged in"
}

# "== clients ==": the DHCP leases (IP, MAC, name)
status_leases() {
  local mac ip name
  say ""; say "== clients (DHCP leases) =="
  if [[ -s $LEASES ]]; then
    while read -r _ mac ip name _; do
      printf '  %-16s %s  %s\n' "$ip" "$mac" "$name"
    done < "$LEASES"
  else say "  none"; fi
}

# "== firewall counters ==": the rules of our tables that matched a packet (root only)
status_counters() {
  local counters
  say ""; say "== firewall counters (packets that hit a rule) =="
  counters=$({ nft list table bridge tether; nft list table ip tether; } 2>/dev/null \
    | grep -E 'counter packets [1-9]' | sed -E 's/^[[:space:]]+/  /')
  if [[ -n $counters ]]; then say "$counters"; else say "  no rule has matched a packet yet"; fi
}

# =============================================================================
# install / uninstall / reload / settings - part 1: log, settings, reload, reset
# =============================================================================
# Set EDITOR_CMD to $EDITOR, else vim, else vi; $1 = the tether command, for the error message
pick_editor() {
  EDITOR_CMD=${EDITOR:-}
  [[ -n $EDITOR_CMD ]] && return 0
  if have vim; then EDITOR_CMD="vim"
  elif have vi; then EDITOR_CMD="vi"
  else die "no editor found: set EDITOR (for example: EDITOR=nano tether $1)"; fi
}

# Show the log read-only in the editor "tether settings" uses, at its last line
cmd_log() {
  local ed logf=${CFG[LOG_FILE]:-} tmp rc
  local -A status=()
  # The conf is root-only; the watcher's status file has the LOG_FILE in use for everyone
  if [[ -z $logf && -r $STATUS_FILE ]]; then
    read_status status; logf=${status[LOG_FILE]:-}
  fi
  logf=${logf:-/var/log/tether.log}
  [[ -f $logf ]] || die "there is no log yet ($logf does not exist)"
  pick_editor log; ed=$EDITOR_CMD
  case ${ed%% *} in
    vim|vi|nvim|view|*/vim|*/vi|*/nvim|*/view)
      # -R = read-only, "+" = start on the last line
      # shellcheck disable=SC2086  # EDITOR may carry arguments
      $ed -R + "$logf"; return ;;
  esac
  # Other editors have no common read-only switch: open a read-only copy, deleted afterwards
  tmp=$(mktemp "${TMPDIR:-/tmp}/tether-log.XXXXXX") || die "could not create a temporary file"
  trap 'rm -f "$tmp"' EXIT
  { cp "$logf" "$tmp" && chmod 444 "$tmp"; } || die "could not copy $logf"
  # shellcheck disable=SC2086  # EDITOR may carry arguments, e.g. "code --wait"
  $ed "$tmp"; rc=$?
  rm -f "$tmp"; trap - EXIT
  return "$rc"
}

# Open the conf in the user's editor (applied only by "tether reload")
cmd_settings() {
  local ed
  pick_editor settings; ed=$EDITOR_CMD
  # shellcheck disable=SC2086  # EDITOR may carry arguments, e.g. "code --wait"
  $ed "$CONF"
  say "Saved. Run \"tether reload\" to check and apply the settings."
}

# Check the conf; if it has no errors restart the watcher with it
cmd_reload() {
  local n
  # With WIFI=0 the [device] blocks are removed when the watcher restarts, so their errors
  # don't count
  parse_conf "$CONF" || true
  conf_drop_wifi_errs "$CONF"
  if ((${#ERRS[@]})); then
    say "$CONF has errors:"
    printf '  %s\n' "${ERRS[@]}"
    # The watcher only reads the settings when it starts, so a running tether is untouched
    if [[ -s $CONF_ERR_FILE ]] || ! systemctl is-active --quiet "$UNIT"; then
      say "Nothing changed. tether is not running until these are fixed."
    else
      say "Nothing changed. tether is still running with the previous settings."
    fi
    return 1
  fi
  for n in "${NOTES[@]}"; do say "note: $n"; done
  systemctl restart "$UNIT" || die "could not restart $UNIT (see: journalctl -u $UNIT)"
  apply_parsed
  wait_for_bridge || return 1
  say "Settings applied, $UNIT restarted."
}

# Reset the conf to what a fresh install writes; the old one is kept in CONF_BAK
cmd_reset() {
  # No terminal (a script, a pipe) means nobody can answer, which counts as no
  if [[ ! -t 0 ]] || ! ask "Reset all settings to default?"; then
    say "Nothing changed."; return 0
  fi
  # The conf holds the Wi-Fi passwords, so the copy must stay root-only too
  if ! { (umask 077; cp -f "$CONF" "$CONF_BAK") \
    && chown root:root "$CONF_BAK" && chmod 600 "$CONF_BAK"; }; then
    die "could not save $CONF to $CONF_BAK, nothing changed"
  fi
  say "Saved the old settings to $CONF_BAK"
  # The same as install writes when there is no conf yet
  write_default_conf || die "could not write $CONF (the old settings are in $CONF_BAK)"
  say "Settings reset to default."
  # reload restarts the watcher with the new conf: plugged-in dongles get fresh blocks
  cmd_reload
}

# =============================================================================
# install / uninstall / reload / settings - part 2: install, uninstall
# =============================================================================
pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'ok installed'; }

# On Qubes the qube runs dom0's Fedora-built kernel, which only trusts the signature of the
# upstream regulatory.db, not Debian's (dmesg: "loaded regulatory.db is malformed or
# signature is missing/invalid"). With Debian's file every country stays 00 and 5 GHz
# access points can't start, so install points the regulatory.db alternative at the
# upstream file and uninstall puts it back to automatic (Debian's).
REGDB_UPSTREAM=/lib/firmware/regulatory.db-upstream
regdb_qubes() { [[ $(uname -r) == *qubes* && -e $REGDB_UPSTREAM ]]; }
# install: point the regulatory.db alternative at the upstream file (Qubes kernels only)
regdb_use_upstream() {
  regdb_qubes || return 0
  if update-alternatives --set regulatory.db "$REGDB_UPSTREAM" >/dev/null 2>&1; then
    iw reg reload 2>/dev/null
    say "Qubes kernel: using the upstream regulatory.db (Debian's signature is not trusted)"
  else
    say "Warning: could not switch regulatory.db to $REGDB_UPSTREAM, 5 GHz may not work."
  fi
}
regdb_restore_auto() {
  regdb_qubes || return 0
  update-alternatives --auto regulatory.db >/dev/null 2>&1 && iw reg reload 2>/dev/null
  say "regulatory.db set back to automatic"
}

# The systemd unit that runs the watcher
unit_text() {
  cat <<UNIT
[Unit]
Description=tether: share this qube's internet over USB Ethernet adapters and Wi-Fi dongles
After=network.target qubes-iptables.service qubes-network-uplink.service
Wants=qubes-iptables.service

[Service]
Type=simple
ExecStart=$BIN watch
Restart=on-failure
RestartSec=5
# TERM goes to the watcher only; it stops dnsmasq/hostapd and takes the bridge down itself
KillMode=mixed
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
UNIT
}

# Wait up to 20 s for the watcher to report the bridge as up
wait_for_bridge() {
  local i why=""
  reparse; apply_parsed
  for ((i = 0; i < 20; i++)); do
    why=$(tether_check) && [[ -s $STATUS_FILE ]] && return 0
    sleep 1
  done
  say "The service started, but the tether is not up yet (${why:-no status yet})." \
    "See: tether status"
  return 1
}

INSTALL_ADDED=()   # install: the packages it had to install (recorded for uninstall)

# "tether install": qube type check, packages, files, then the service
cmd_install() {
  install_check_qube_type || return 1
  install_packages
  install_files
  install_service || return 1
  say "Done. Everything is running, you can plug in the cable."
}

# AppVM and TemplateVM need a yes first (fails if the answer is no); other types are refused
install_check_qube_type() {
  local type
  type=$(qubesdb-read /type 2>/dev/null)
  case $type in
    StandaloneVM) ;;
    AppVM)
      say "This is an AppVM: everything install adds outside /home and /rw" \
        "(packages, /usr/bin/tether,"
      say "/etc/tether.conf, the service) is gone after the next reboot."
      ask "Continue?" || { say "Nothing changed."; return 1; } ;;
    TemplateVM)
      say "This is a TemplateVM: every AppVM based on it will run the tether watcher at boot."
      say "A dedicated template used only for tether qubes is recommended."
      ask "Continue?" || { say "Nothing changed."; return 1; } ;;
    *) die "this qube type ($type) is not supported" ;;
  esac
}

# apt-get the missing APT_PKGS into INSTALL_ADDED, then the system tweaks they need.
# No outer timer: apt's own Acquire timeouts/retries below stop a dead download, and wrapping
# apt in `timeout` puts it in a background process group, so it gets paused (and ignores Ctrl+C)
# as soon as it touches the terminal.
install_packages() {
  local p rc
  local -a opts=(-o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::Retries=3)
  INSTALL_ADDED=()
  for p in "${APT_PKGS[@]}"; do pkg_installed "$p" || INSTALL_ADDED+=("$p"); done
  if ((${#INSTALL_ADDED[@]})); then
    say "Installing packages: ${INSTALL_ADDED[*]}"
    apt-get "${opts[@]}" update \
      || say "Warning: apt-get update had errors, trying the install anyway."
    DEBIAN_FRONTEND=noninteractive \
      apt-get "${opts[@]}" install -y --no-install-recommends "${INSTALL_ADDED[@]}"
    rc=$?
    ((rc == 0)) || die "apt-get install failed (exit status $rc). Nothing else was changed."
  else
    say "Packages already installed: ${APT_PKGS[*]}"
  fi
  # hostapd's own service would fight our hostapd children over the dongles
  systemctl disable --now hostapd.service >/dev/null 2>&1
  systemctl mask hostapd.service >/dev/null 2>&1
  pkg_installed qubes-usb-proxy \
    || say "Warning: qubes-usb-proxy is not installed," \
      "USB devices can't be attached to this qube from dom0."
  regdb_use_upstream
}

# The package record, the dnsmasq user, the program in BIN, the conf (kept if it exists)
install_files() {
  mkdir -p "$STATE_DIR"
  if ((${#INSTALL_ADDED[@]})); then
    printf '%s\n' "${INSTALL_ADDED[@]}" >> "$PKG_RECORD"; sort -u -o "$PKG_RECORD" "$PKG_RECORD"
  fi
  id dnsmasq >/dev/null 2>&1 \
    || useradd --system --no-create-home --shell /usr/sbin/nologin --home-dir /nonexistent dnsmasq

  if [[ $SELF != "$BIN" ]]; then
    install -m 0755 "$SELF" "$BIN" || die "could not copy myself to $BIN"
  fi
  say "Installed $BIN"
  if [[ -e $CONF ]]; then say "Keeping the existing $CONF"
  else
    write_default_conf; say "Wrote $CONF (edit it with: tether settings)"
  fi
  reparse; apply_parsed
  if ((${#ERRS[@]})); then
    say "Warning: $CONF has problems (the watcher logs them):"; printf '  %s\n' "${ERRS[@]}"
  fi
}

# The log file and the systemd unit; start it and wait for the bridge
install_service() {
  touch "${CFG[LOG_FILE]}" && chmod 644 "${CFG[LOG_FILE]}"
  unit_text > "$UNIT_FILE"
  systemctl daemon-reload
  systemctl enable "$UNIT" >/dev/null 2>&1 || die "could not enable $UNIT"
  systemctl restart "$UNIT" || die "could not start $UNIT (see: journalctl -u $UNIT)"
  say "Started $UNIT"
  wait_for_bridge
}

# Stop and remove everything install added; offer to remove the packages it installed
cmd_uninstall() {
  local pkgs=""
  say "Stopping the tether and removing it..."
  systemctl disable --now "$UNIT" >/dev/null 2>&1
  reparse; apply_parsed
  # Leftovers in case the watcher did not get to clean up
  pkill -f "^dnsmasq .*--conf-file=$RUN_DIR/" 2>/dev/null
  pkill -f "^hostapd $RUN_DIR/" 2>/dev/null
  tether_down
  rm -f "$UNIT_FILE"; systemctl daemon-reload
  rm -f "$BIN" "$CONF" "${CFG[LOG_FILE]}" /var/log/tether.log
  rm -rf "$RUN_DIR"
  systemctl unmask hostapd.service >/dev/null 2>&1      # back to normal, but left disabled
  systemctl disable hostapd.service >/dev/null 2>&1
  regdb_restore_auto
  [[ -r $PKG_RECORD ]] && pkgs=$(xargs < "$PKG_RECORD")
  rm -rf "$STATE_DIR"
  say "Removed the service, $BIN, $CONF, the log and $RUN_DIR."
  if [[ -n $pkgs ]]; then
    say "Packages that tether install added:"
    say "  apt-get remove $pkgs"
    if ask "Remove them now?"; then
      # shellcheck disable=SC2086  # one argument per package name
      apt-get remove -y $pkgs
    else
      say "Packages kept."
    fi
  fi
  return 0
}

# =============================================================================
# Help and main
# =============================================================================
# The --help text
usage() {
  # first line carries $VERSION; the rest is a quoted heredoc, so nothing in it expands
  echo "tether $VERSION - share this qube's internet with devices on USB Ethernet and Wi-Fi"
  cat <<'EOF'

tether turns a dedicated qube into a router. Plug USB Ethernet
adapters or USB Wi-Fi dongles into the qube, and the devices behind them
(laptops, phones, anything) get internet through this qube's NetVM, which
can be a VPN, Whonix or sys-firewall. sys-net stays untouched.
Wi-Fi dongles must support AP (access point) mode; many cheap ones don't.
Check with "iw list" (look for "AP" under "Supported interface modes").

It is meant to run alone in its own qube. For a first try, install it in
an AppVM: it works until the next reboot, then it is gone. For permanent
use, install it in a TemplateVM and run it from an AppVM based on it. Use
a dedicated template, because every AppVM based on that template runs
tether and takes your USB adapters, and tether's packages and settings
would end up in qubes that don't need them. A StandaloneVM works too.

Usage: tether <command>

Commands:
  install     Install tether and start it. Installs the needed packages,
              copies itself to /usr/bin/tether, writes the settings
              to /etc/tether.conf (only if missing) and starts the
              tether-watch service, which also runs at every boot.
              Must be run first; the other commands refuse until then.

  status      Show what is going on: adapters and dongles, link state,
              connected devices (IP, MAC, name), the bridge, DNS/DHCP,
              the uplink and the last log lines. Works as a normal user;
              as root it also shows firewall counters and Wi-Fi passwords.

  settings    Open /etc/tether.conf in your editor ($EDITOR, vim or vi).
              Changes apply only after "tether reload".

  log         Open /var/log/tether.log read-only in your editor.

  reload      Check /etc/tether.conf and apply it. If a line is wrong, it
              prints the line number and the reason and changes nothing.
              Otherwise it restarts the service; devices drop for a few
              seconds and reconnect.

  reset       Reset all settings to default, keeping the old file as .bak.

  uninstall   Stop tether and remove everything it added: the service,
              the program, the settings, the log and the network setup.
              Then it shows the apt command for the packages it installed
              and asks whether to remove them.

How it works:
  One background service, tether-watch, does all the work. Every few
  seconds it checks for adapters and:
   - joins plugged-in USB Ethernet adapters to one bridge (br-tether)
     and removes them when unplugged
   - switches adapters that show up as a virtual CD-ROM into network mode
   - turns each plugged-in AP-capable Wi-Fi dongle into an access point
     on the same bridge, with a new random name and password written at
     the end of /etc/tether.conf. A dongle gets a new name and password
     every time it is plugged in, unless you set STICKY=1 in its section.
     For AppVMs: plug the dongle into their template and set STICKY=1 there
     (changes made inside an AppVM are lost on reboot)
   - runs DHCP/DNS for the devices and restarts it if it stops

  Devices get addresses in 192.168.100.0/24, or any other range you set
  in the settings, and are blocked by default from your other qubes and
  private networks. Every event is logged to /var/log/tether.log, which
  every user can read.

Commands that change something need root and use sudo automatically.
EOF
}

is_installed() { [[ -x $BIN && -f $CONF && -f $UNIT_FILE ]]; }

# Re-run this command as root through sudo (keeping the user's EDITOR)
need_root() {
  ((EUID == 0)) && return 0
  if ! have sudo || ! sudo -v 2>/dev/null; then
    die "$1 needs root, and sudo is not available or failed."
  fi
  exec sudo -- env "EDITOR=${EDITOR:-}" "$SELF" "$@"
}

# Check the command, where we run and who we are, then run cmd_<command>
main() {
  local cmd=${1:-}
  case $cmd in
    status|install|uninstall|reload|settings|reset|log|watch) ;;
    ""|-h|--help|help) usage; return 0 ;;
    *) usage >&2; return 1 ;;
  esac
  if [[ -z $(qubesdb-read /type 2>/dev/null) ]]; then
    die "this is not a Qubes qube; tether only runs in Qubes OS."
  fi
  if [[ $cmd != install && $cmd != watch ]] && ! is_installed; then
    die "tether is not installed yet. Run: $0 install"
  fi
  case $cmd in
    install|uninstall|reload|settings|reset) need_root "$@" ;;
    watch) ((EUID == 0)) || die "watch is run by $UNIT as root" ;;
  esac
  "cmd_$cmd"          # the first case above only lets the eight command names through
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi

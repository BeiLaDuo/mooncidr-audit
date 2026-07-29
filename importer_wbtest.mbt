///|
test "plain importer preserves valid rules and captures errors" {
  let report = import_plain_rules([
    "# gateway policy", "allow 10.0.0.0/8 internal", "broken line", "deny 0.0.0.0/0 fallback",
  ])
  inspect(report.format().label(), content="plain")
  inspect(report.source_count(), content="4")
  inspect(report.accepted_count(), content="2")
  inspect(report.error_count(), content="1")
  inspect(report.rules()[1].action().label(), content="deny")
}

///|
test "Nginx importer supports allow deny and all" {
  let report = import_nginx_access([
    "allow 10.0.0.0/8;", "deny 192.0.2.5;", "deny all;",
  ])
  inspect(report.accepted_count(), content="3")
  inspect(report.error_count(), content="0")
  inspect(report.rules()[0].block().to_string(), content="10.0.0.0/8")
  inspect(report.rules()[1].block().to_string(), content="192.0.2.5/32")
  inspect(report.rules()[2].block().to_string(), content="0.0.0.0/0")
}

///|
test "Nginx importer strips comments" {
  let report = import_nginx_access([
    "allow 172.16.0.0/12; # office tunnel", "# deny 0.0.0.0/0;",
  ])
  inspect(report.accepted_count(), content="1")
  inspect(report.issues().length(), content="0")
}

///|
test "Nginx importer reports missing semicolon" {
  let report = import_nginx_access(["allow 10.0.0.0/8"])
  inspect(report.error_count(), content="1")
  inspect(report.issues()[0].code(), content="missing_semicolon")
}

///|
test "Nginx importer rejects unrelated directive" {
  let report = import_nginx_access(["proxy_pass http://backend;"])
  inspect(report.accepted_count(), content="0")
  inspect(report.issues()[0].code(), content="unsupported_directive")
}

///|
test "CSV importer recognizes optional header" {
  let report = import_csv_rules([
    "action,cidr,note", "allow,10.0.0.0/8,internal network", "deny,0.0.0.0/0,default",
  ])
  inspect(report.source_count(), content="3")
  inspect(report.accepted_count(), content="2")
  inspect(report.rules()[0].note(), content="internal network")
}

///|
test "CSV importer parses quoted comma in note" {
  let report = import_csv_rules(["allow,192.0.2.0/24,\"partner, temporary\""])
  inspect(report.accepted_count(), content="1")
  inspect(report.rules()[0].note(), content="partner, temporary")
}

///|
test "CSV importer parses doubled quote escape" {
  let report = import_csv_rules([
    "deny,198.51.100.0/24,\"ticket \"\"SEC-42\"\"\"",
  ])
  inspect(report.accepted_count(), content="1")
  inspect(report.rules()[0].note(), content="ticket \"SEC-42\"")
}

///|
test "CSV importer reports unclosed quote" {
  let report = import_csv_rules(["allow,10.0.0.0/8,\"broken"])
  inspect(report.error_count(), content="1")
  inspect(report.issues()[0].code(), content="invalid_csv")
}

///|
test "CSV importer folds extra columns into note with warning" {
  let report = import_csv_rules(["allow,203.0.113.0/24,partner,expires soon"])
  inspect(report.accepted_count(), content="1")
  inspect(report.warning_count(), content="1")
  inspect(report.rules()[0].note(), content="partner, expires soon")
}

///|
test "import report converts to auditable ruleset" {
  let imported = import_nginx_access(["allow 10.0.0.0/8;", "deny 10.1.0.0/16;"])
  let audit = imported.to_ruleset().audit()
  inspect(audit.count_kind(ShadowedRule), content="1")
}

///|
test "import report renders rules and issues" {
  let report = import_nginx_access(["allow 10.0.0.0/8;", "deny 10.1.0.0/16"])
  inspect(
    report.text_report(),
    content=(
      #|MoonCIDR import report
      #|format=nginx_access, source_lines=2, accepted=1, warnings=0, errors=1
      #|
      #|Imported rules:
      #|- R1: allow 10.0.0.0/8 # imported from nginx
      #|
      #|Import issues:
      #|- [error] line 2 missing_semicolon: Nginx access directive must end with a semicolon
      #|
    ),
  )
}

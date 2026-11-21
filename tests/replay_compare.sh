#!/usr/bin/env bash
# 실측 pcap 하나에 여러 룰 묶음을 돌려 경보를 비교한다(컨테이너 --network none, docker cp 방식).
# 공개 룰 묶음 원문은 저장소에 넣지 않는다. 경로를 인자로 받는다.
# 사용: bash tests/replay_compare.sh <pcap> <이름=suricata룰파일|snort3:룰파일> [...]
#   예: bash tests/replay_compare.sh cap.pcap ours=rules/suricata/anti-artex.rules mmd=/x/mmd.rules mmd-s3=snort3:/x/mmd-snort3.rules
# 결과: 표준 출력에 묶음별 (sid, msg, 건수) 표, <pcap>.alerts/<이름>.json에 원본 경보.
set -euo pipefail
PCAP=$1; shift
SURICATA_IMAGE=${SURICATA_IMAGE:-jasonish/suricata:7.0}
SNORT_IMAGE=${SNORT_IMAGE:-ciscotalos/snort3:latest}
OUT="${PCAP}.alerts"; mkdir -p "$OUT"
WORK=$(mktemp -d); trap 'rm -rf -- "$WORK"' EXIT
cp "$PCAP" "$WORK/cap.pcap"
chmod 755 "$WORK"  # 컨테이너 안 snort 사용자도 읽게
for spec in "$@"; do
  name=${spec%%=*}; rule=${spec#*=}; engine=suricata
  case "$rule" in snort3:*) engine=snort; rule=${rule#snort3:} ;; esac
  rm -f "$WORK/r.rules"; cp "$rule" "$WORK/r.rules"; chmod 644 "$WORK/r.rules" "$WORK/cap.pcap"
  if [ "$engine" = suricata ]; then
    cid=$(docker create --network none --entrypoint sh "$SURICATA_IMAGE" -c \
      "mkdir -p /t/o && suricata --runmode single -r /t/cap.pcap -S /t/r.rules -k none -l /t/o >/t/o/run.log 2>&1; grep -c . /t/o/run.log >/dev/null; cat /t/o/eve.json 2>/dev/null; echo; grep -iE 'rules successfully loaded|error' /t/o/run.log | head -5 >&2")
    docker cp "$WORK/." "$cid:/t" >/dev/null
    docker start -a "$cid" > "$OUT/$name.json" 2> "$OUT/$name.log" || true
  else
    S=/home/snorty/snort3
    cid=$(docker create --network none --entrypoint sh "$SNORT_IMAGE" -c \
      "$S/bin/snort -c $S/etc/snort/snort.lua -R /home/snorty/t/r.rules -r /home/snorty/t/cap.pcap -k none -A alert_json -q 2>/tmp/err.log; grep -iE 'error|warn' /tmp/err.log | head -5 >&2")
    docker cp "$WORK/." "$cid:/home/snorty/t" >/dev/null
    docker start -a "$cid" > "$OUT/$name.json" 2> "$OUT/$name.log" || true
  fi
  docker rm -v "$cid" >/dev/null
  python3 -I - "$OUT/$name.json" "$name" "$engine" "$rule" <<'PY'
import json, re, sys, collections
c = collections.Counter()
msgs = {m.group(2): m.group(1) for m in re.finditer(r'msg:"([^"]*)".*?sid:(\d+)', open(sys.argv[4], errors="ignore").read())}
for line in open(sys.argv[1], errors="ignore"):
    line = line.strip()
    if not line.startswith("{"): continue
    try: e = json.loads(line)
    except ValueError: continue
    if sys.argv[3] == "suricata":
        if e.get("event_type") != "alert": continue
        a = e["alert"]; c[(a["signature_id"], a["signature"][:90])] += 1
    else:
        sid = str(e.get("rule", "")).split(":")[1] if ":" in str(e.get("rule", "")) else str(e.get("sid"))
        c[(sid, msgs.get(sid, "")[:90])] += 1
print(f"== {sys.argv[2]} ({sys.argv[3]}): 경보 {sum(c.values())}건, 룰 {len(c)}개")
for (sid, msg), n in sorted(c.items(), key=lambda x: -x[1]): print(f"  {sid}\t{n}\t{msg}")
PY
  [ -s "$OUT/$name.log" ] && sed 's/^/  [log] /' "$OUT/$name.log" | head -5 || true
done

#!/usr/bin/env bash
#
# bump-compose-images.sh — locally bump pinned image tags in a compose file to
# their newest compatible version so you can run your tests against them.
# Edits the file in place (no backup). Not a PR bot.
#
# Borrows Renovate's techniques: structure-aware extraction that honours
# `build:` and skips ${templated}/*aliased images; docker versioning that
# rejects commit-hash tags, strips a leading `v`, and only treats tags as
# updatable when release-length AND suffix match (so `-alpine` stays `-alpine`
# and `1.50` stays two-component). It never crosses a major version. Tag
# schemes docker versioning can't parse (e.g. MinIO RELEASE.* date stamps)
# fall back to shape-matching.
#
# Deps: crane (github.com/google/go-containerregistry), awk, sort, coreutils.
# Usage: ./bump-compose-images.sh [path/to/docker-compose.yml]
#
set -euo pipefail

COMPOSE="${1:-docker-compose.yml}"
[ -f "$COMPOSE" ] || { echo "no such file: $COMPOSE" >&2; exit 1; }
command -v crane >/dev/null 2>&1 || { echo "need crane on PATH" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. Extract eligible images: "<lineNumber>\t<service>\t<imageRef>"
#    structure-aware; skips services with build:, and ${}/*/& image values.
# ---------------------------------------------------------------------------
read -r -d '' EXTRACT_AWK <<'AWK' || true
function indent(s,   i){ i=match(s,/[^ ]/); return (i?i-1:length(s)) }
function eligible(r){
  if (r=="" || r ~ /[[:space:]]/) return 0
  if (r ~ /[$]/ || r ~ /^[*&]/) return 0
  return 1
}
function name(s,   t){ t=s; sub(/^[[:space:]]+/,"",t); sub(/:[[:space:]]*$/,"",t); return t }
function flush(){
  if (svc!="" && img_line>0 && !has_build && eligible(img_ref))
    print img_line "\t" name(svc) "\t" img_ref
  svc=""; img_line=0; img_ref=""; has_build=0
}
BEGIN{ svc_indent=-1; svc_parent=-1; expect_child=0 }
{
  line=$0
  if (line ~ /^[[:space:]]*#/ || line ~ /^[[:space:]]*$/) next
  ind=indent(line)
  if (svc_indent<0 && line ~ /^[[:space:]]*services:[[:space:]]*$/){ svc_parent=ind; expect_child=1; next }
  if (expect_child && ind>svc_parent){ svc_indent=ind; expect_child=0 }
  if (svc_indent<0) next
  if (ind==svc_indent && line ~ /:[[:space:]]*$/){ flush(); svc=line; next }
  if (svc=="") next
  if (ind<=svc_indent){ flush(); next }
  if (line ~ /^[[:space:]]*build:/) has_build=1
  if (img_line==0 && match(line,/^[[:space:]]*image:[[:space:]]*/)){
    img_ref=substr(line,RLENGTH+1); sub(/[[:space:]]+$/,"",img_ref); img_line=NR
  }
}
END{ flush() }
AWK

# ---------------------------------------------------------------------------
# 2. Selector: print updatable candidate tags for CUR (stdin = candidate tags)
#    Renovate docker versioning, with shape-matching fallback.
# ---------------------------------------------------------------------------
read -r -d '' SELECT_AWK <<'AWK' || true
function pdock(v, o,   s,n,parts,i,suf,prefix,rel,pre,tmp){
  delete o; o["ok"]=0
  if (v ~ /^[a-f0-9]{7,40}$/ && v !~ /^[0-9]+$/) return 0
  s=v; sub(/^v/,"",s)
  n=split(s,parts,"-"); prefix=parts[1]; suf=""
  for(i=2;i<=n;i++) suf=suf (i>2?"-":"") parts[i]
  if (match(prefix,/^[0-9]+(\.[0-9]+)*/)){
    rel=substr(prefix,1,RLENGTH); pre=substr(prefix,RLENGTH+1)
    if (pre ~ /^[A-Za-z0-9_]*$/ && rel!=""){
      o["ok"]=1; o["len"]=split(rel,tmp,"."); o["maj"]=tmp[1]; o["rel"]=rel; o["suf"]=suf; o["pre"]=pre; return 1
    }
  }
  return 0
}
function shape(v,   t){ t=v; gsub(/[0-9]+/,"#",t); return t }
BEGIN{ curok=pdock(CUR,C) }
{
  cand=$0; if (cand=="") next
  if (curok){
    if (pdock(cand,D) && D["suf"]==C["suf"] && D["len"]==C["len"] && D["maj"]==C["maj"] && (C["pre"]!="" || D["pre"]=="")) print cand
  } else if (shape(cand)==shape(CUR)) print cand
}
AWK

# split an image ref into REPO / TAG / DIGEST (handles registry:port + @sha256)
parse_ref(){
  local ref="$1" namever last
  DIGEST=""
  if [[ "$ref" == *@* ]]; then DIGEST="${ref##*@}"; namever="${ref%@*}"; else namever="$ref"; fi
  last="${namever##*/}"
  if [[ "$last" == *:* ]]; then REPO="${namever%:*}"; TAG="${namever##*:}"; else REPO="$namever"; TAG=""; fi
}

# choose the newest updatable tag for REPO:TAG, or empty
newest_tag(){
  local repo="$1" tag="$2" tags
  tags=$(crane ls "$repo" 2>/dev/null) || return 0
  printf '%s\n' "$tags" | awk -v CUR="$tag" "$SELECT_AWK" | sort -V | tail -1
}

# ---------------------------------------------------------------------------
# 3. Decide updates, then rewrite the file by line number (Renovate LineMapper)
# ---------------------------------------------------------------------------
declare -A CACHE        # ref -> new ref
mapfile=$(mktemp); report=$(mktemp); changed=0

while IFS=$'\t' read -r lineno svc ref; do
  if [[ -n "${CACHE[$ref]+x}" ]]; then newref="${CACHE[$ref]}"; else
    parse_ref "$ref"
    newref="$ref"
    if [[ -n "$TAG" && "$TAG" == *[0-9]* ]]; then
      newtag=$(newest_tag "$REPO" "$TAG")
      if [[ -n "$newtag" && "$newtag" != "$TAG" ]]; then
        newref="$REPO:$newtag"
        if [[ -n "$DIGEST" ]]; then
          newdig=$(crane digest "$REPO:$newtag" 2>/dev/null || true)
          [[ -n "$newdig" ]] && newref="$newref@$newdig"
        fi
      fi
    fi
    CACHE[$ref]="$newref"
  fi
  if [[ "$newref" != "$ref" ]]; then
    printf '%s\t%s\n' "$lineno" "$newref" >> "$mapfile"
    printf '  %-16s %s  ->  %s\n' "$svc" "$ref" "$newref" >> "$report"
    changed=$((changed+1))
  fi
done < <(awk "$EXTRACT_AWK" "$COMPOSE")

if [[ "$changed" -eq 0 ]]; then
  rm -f "$mapfile" "$report"; echo "nothing to update"; exit 0
fi

tmp=$(mktemp)
awk -v MAP="$mapfile" '
  BEGIN{ while((getline l < MAP)>0){ split(l,a,"\t"); NEW[a[1]]=a[2] } }
  { if ((FNR in NEW) && match($0,/^[[:space:]]*image:[[:space:]]*/))
      print substr($0,1,RLENGTH) NEW[FNR]
    else print }
' "$COMPOSE" > "$tmp"

cat "$tmp" > "$COMPOSE"; rm -f "$tmp"
cat "$report"; rm -f "$mapfile" "$report"
echo "updated $COMPOSE ($changed image(s))"

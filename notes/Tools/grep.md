---
title: Grep & Text Processing
tags: [cheatsheet, grep, awk, sed, ripgrep, text, cli]
category: tools
notes: "Focus on practical, memorable incantations. Prefer ripgrep (rg) where available for speed and sane defaults. GNU grep/awk/sed syntax assumed."
---

# Grep & Friends – Fast Text-Fu

## Common Commands
- `rg -n 'pattern'` — fast search, show line numbers (recursive, ignores junk)
- `rg -nI --hidden -S 'foo\(\d+\)'` — search everything, ignore binaries, smart-case, PCRE
- `grep -Rni --color=always 'pattern' .` — classic recursive grep
- `grep -RniE 'foo|bar'` — extended regex (alternation)
- `awk -F: '/regex/ {print $1 ":" $2 ":" $3}' file` — quick column slicing
- `sed -n '1,120p' file` — print range  
- `sed -i 's/old/new/g' **/*.conf` — in-place replace (GNU sed)

---

## Examples

- Find TODOs except vendor/:  
  `rg -n 'TODO|FIXME' -g '!vendor' -S`  

- Find function defs + 2 lines after:  
  `rg -nA2 -P '^\s*(def|func|class)\s+\w+'`  

- Extract emails:  
  `rg -oP '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' *.md | sort -u`  

- Count HTTP status codes:  
  `awk '{a[$9]++} END{for(k in a) print k,a[k]}' access.log | sort -n`  

- Replace DEBUG with INFO:  
  `rg -l 'DEBUG' -g '*.yaml' | xargs -r sed -i 's/\bDEBUG\b/INFO/g'`  

- Lines not containing pattern:  
  `grep -Rnv 'pattern' .`  

---

## Patterns & Flags (grep/rg)

### Grep Core
- `grep 'pat' file` — exact substring
- `grep -n 'pat' file` — show line numbers
- `grep -R 'pat' .` — recurse
- `grep -i 'pat'` — ignore case
- `grep -v 'pat'` — invert match
- `grep -c 'pat'` — count matches
- `grep -o 're'` — only show match
- `grep -H 'pat' file` — show filename
- `grep -E 're'` — extended regex
- `grep -P 're'` — PCRE regex
- `grep -nC3 'pat'` — ±3 lines context
- `grep -R --include='*.py' 'pat' .` — only Python files
- `grep -I 'pat'` — ignore binary
- `grep -w 'word'` — whole word only
- `grep -x 'line'` — whole line only

### ripgrep (`rg`)
- `rg 'pat'` — recursive by default
- `rg -n --color=always 'pat'` — line numbers
- `rg -i 'pat'` — ignore case
- `rg -S 'Pat'` — smart-case
- `rg -v 'pat'` — invert
- `rg -c 'pat'` — count per-file
- `rg -l 'pat'` — list files only
- `rg -P '\bfoo(?=.*bar)'` — PCRE lookahead
- `rg -C3 'pat'` — 3 lines context
- `rg -uuu 'pat'` — search all files
- `rg -g '!node_modules' 'pat'` — exclude dir
- `rg -t py -t sh 'pat'` — only Python + shell
- `rg -oP '(?<=key=)[^&]+'` — extract capture

---

## Handy Recipes

### File lists to actions
- `rg -n 'pat' | fzf` — fuzzy pick match  
- `rg -l 'pat' | xargs -r $EDITOR` — edit all matching files  
- `rg -l 'LICENSE' | xargs -r rm -i` — safe delete files  

### Extract fields / values
- `rg -o -nP '(?<=^key=).*' file` — values after `key=`  
- `rg -oP 'https?://\S+' access.log | sort -u` — URLs  
- `rg -oP '\b(?:\d{1,3}\.){3}\d{1,3}\b' file | sort -u` — IPv4s  

### Count & rank
- `rg -o '\w+' file | sort | uniq -c | sort -nr | head` — top words  
- `grep -Ric 'pat' . | sort -t: -k2,2nr` — match counts  

### Multi-line
- `grep -Pzo '(?s)BEGIN.*?END' file` — grep multiline  
- `rg -Up '(?s)BEGIN.*?END'` — ripgrep multiline  

---

## awk – Columns & Filters
- `awk -F: '{print $1,$3,$7}' /etc/passwd` — select cols  
- `awk -F, 'NR>1 {print $2}' file.csv` — skip header  
- `awk '/ERROR/ {print FNR ":" $0}' logfile` — numbered matches  
- `awk '$3 > 100 {sum+=$3} END {print sum}' data.txt` — sum col  
- `awk 'BEGIN{FS=OFS=","} {gsub(/ /,"_",$1); print $1,$2}' in.csv` — clean col1  
- `awk '{a[$1]++} END {for(k in a) print a[k],k}' | sort -nr` — histogram  
- `awk '{print $NF}' file` — last field  

---

## sed – Edit Streams
- `sed -n '20,40p' file` — show lines 20–40  
- `sed -E '/^\s*($|#)/d' file.conf` — drop comments/blanks  
- `sed -i 's/old/new/g' file` — replace in-place  
- `find . -name '*.conf' -print0 | xargs -0 sed -i 's/old/new/g'` — bulk replace  
- `sed -E -i 's/(user=).*/\1admin/' app.env` — replace with capture  
- `sed -i '/^\[server\]/i # added by script' config.ini` — insert before match  
- `sed -i '5a NEW_LINE' file` — append after line 5  

---

## Joins, Intersections, Diffs
- `sort file | uniq` — dedup  
- `awk '!seen[$0]++' file` — dedup keep order  
- `grep -Fxf listA.txt listB.txt` — intersection  
- `grep -Fvx -f B.txt A.txt` — A not in B  
- `diff -qr dir1 dir2` — dir differences  

---

## Binary / Encoding
- `grep -I -R 'pat' .` — ignore binary  
- `rg -nI 'pat'` — ripgrep ignore binary  
- `iconv -f utf-8 -t utf-8 -c file > clean.txt` — clean encoding  

---

## Regex Crashpad
- `\bfoo\b` — word boundary  
- `^foo` / `bar$` — line anchors  
- `a+` / `colou?r` — repetition/optional  
- `foo|bar` — alternation  
- `[A-Za-z0-9_]` — character class  
- `(?s).*?` — non-greedy dotall  
- `(?<=prefix)thing` — after prefix  
- `thing(?=suffix)` — before suffix  
- `(?!bad)` — not followed by bad  

---

## See Also
- `man rg`, `man grep`, `man 7 regex`, `man awk`, `man sed`  
- `less -p 'regex' file` — jump to regex inside pager  
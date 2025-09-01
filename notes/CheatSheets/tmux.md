---
title: tmux
tags: [tool, terminal, multiplexing, cheatsheet]
service: Terminal Multiplexer
tools: ['tmux']
notes: "Session management, windows, panes, copy mode, and configuration"
---

# tmux Cheat Sheet

## Session Management
- Start new session:  
  `tmux`  

- Start with name:  
  `tmux new -s myname`  

- Attach:  
  `tmux a`  

- Attach named:  
  `tmux a -t myname`  

- List sessions:  
  `tmux ls`  

- Kill session:  
  `tmux kill-session -t myname`  

- Kill all sessions:  
  `tmux ls | awk '{print $1}' | tr -d ':' | xargs kill`  

---

## Prefix Key
- Default: `Ctrl+b`  
- (Commonly remapped to `Ctrl+a`)  

---

## Sessions
- `:new<CR>` → new session  
- `s` → list sessions  
- `$` → rename session  

---

## Windows (Tabs)
- `c` → create window  
- `w` → list windows  
- `n` → next window  
- `p` → previous window  
- `f` → find window  
- `,` → rename window  
- `&` → kill window  

---

## Panes (Splits)
- `%` → vertical split  
- `"` → horizontal split  
- `o` → swap panes  
- `q` → show pane numbers  
- `x` → kill pane  
- `+` → break pane into new window  
- `-` → restore pane from window  
- `Space` → toggle layouts  
- `{` → move pane left  
- `}` → move pane right  
- `z` → zoom toggle  

---

## Sync Panes
Enable across window:  
`:setw synchronize-panes on`  

Disable:  
`:setw synchronize-panes off`  

---

## Resize Panes
- `PREFIX : resize-pane -D` → resize down  
- `PREFIX : resize-pane -U` → resize up  
- `PREFIX : resize-pane -L` → resize left  
- `PREFIX : resize-pane -R` → resize right  
- Append number for amount:  
  `resize-pane -D 20`  

---

## Copy Mode
- Enter: `PREFIX [`  
- Exit: `Enter` or `q`  
- Enable vi keys:  
  `setw -g mode-keys vi`  

### Movement (vi mode)
- `h`/`l` → left/right  
- `j`/`k` → down/up  
- `0`/`$` → line start/end  
- `w`/`b` → next/prev word  
- `/pattern` → search forward  
- `?pattern` → search backward  

### Actions
- `Space` → start selection  
- `Enter` → copy selection  
- `p` → paste buffer  

---

## Misc
- `d` → detach  
- `t` → big clock  
- `?` → list shortcuts  
- `:` → command prompt  

---

## Common Config Options
```tmux
# Mouse support
set -g mouse on

# 256 color terminal
set -g default-terminal "screen-256color"

# Activity alerts
setw -g monitor-activity on
set -g visual-activity on

# Center window list
set -g status-justify centre

# Vi-style keys in copy mode
setw -g mode-keys vi

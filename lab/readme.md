# Basic instructions for SSH into AWS

## Step 1: chmod

```bash
chmod 400 labsuser.pem
```

## Step 2: SSH

```bash
ssh -i labsuser.pem labuser@ip
```

## tmux capture

### Within terminal

```bash
tmux capture-pane -pS -1000000 > out.txt
```

### Within tmux

```tmux
:capture-pane -S -30000
:save-buffer ~/out.txt
```

```bash
cat out.txt
```

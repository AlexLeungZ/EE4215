# Basic instructions for SSH into AWS

## Step 1: chmod

```bash
chmod 400 labsuser.pem
```

## Step 2: SSH

```bash
ssh -i labsuser.pem labuser@ip
```

## Result

### [Lab1](./lab1/lab1.md)

### [Lab2](./lab2/lab2.md)

### [Lab3](./lab3/lab3.md)

## tmux capture

### Within terminal

```bash
tmux capture-pane -pS -10000 > out.txt
```

### Within tmux

```tmux
:capture-pane -S -30000
:save-buffer ~/out.txt
```

```bash
cat out.txt
```

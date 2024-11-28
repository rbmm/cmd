demo tool for remote cmd/power shell

client enter credentials (name/password) and connect to server (by udp)
server run invisible cmd for client. it output redirect to pipe and pipe output  resend to client socket
client can use interactive or network or batch logon. elevated or not
both socket and pipe I/O complete asynchronous
all data is encrypted.
simply demo code

----------------------------------------
run both server and client with *<path-to-pfx>*<password to pfx>

by default 0.pfx (empty password) is used

so run CmdClient.exe equal to CmdClient.exe *0.pfx*
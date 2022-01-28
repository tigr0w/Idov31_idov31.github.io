---
layout: post
title: UdpInspector - Getting active UDP connections without sniffing
subtitle: A new way to get the active UDP connections.
gh-repo: idov31/UdpInspector
gh-badge: [star, fork, follow]
tags: [network, windows]
comments: true
---

## UdpInspector - Getting active UDP connections without sniffing
Many times I've wondered how comes that there are no tools to get the active udp connections?<br />
Of course you can always sniff with wireshark or any other tool of your choosing but, why netstat
doesn't have it built in? That is the point that I went for a quest to investigate the matter.<br /><br />
Naturally, I started with msdn to read more about what I can get about udp connections, that is the moment when I found these
two functions:<br />
<ul>
  <li><a href="https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getudptable"><u>GetUdpTable</u></a></li>
  <li><a href="https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable"><u>GetExtendedUdpTable</u></a></li>
</ul>
So, I started to look at the struct they return and saw a struct named <a href="https://docs.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udptable"><u>MIB_UDPTABLE</u></a>.<br /><br />
<img src="../assets/img/list-udp-connections/udptable.png" alt="udptable" class="center" /><br /><br />
Sadly and unsuprisingly it gave none useful information but remember this struct - It will be used in the future. This is when I started to check another
path - Reverse Engineering netstat.

I will tell you that now - It wasn't helpful at all, but I did learned about a new undocumented function - Always good to know!<br />
When I opened netstat I searched for the interesting part - How it gets the UDP connections? Maybe it uses special function that would help me as well?<br /><br />
<img src="../assets/img/list-udp-connections/netstat1.png" alt="netstatudpfunction" class="center" /><br /><br />
After locating the area when it calls to get the udp connections I saw that weird function: InternalGetUdpTableWithOwnerModule.<br /><br />
<img src="../assets/img/list-udp-connections/netstat2.png" alt="InternalGetUdpTableWithOwnerModule" class="center" /><br /><br />
After a quick check on Google I saw that it won't help me, there isn't much documentation about it. After I realised that it won't help I went back to the source: The GetExtendedUdpTable function.<br /><br />

After rechecking it I found out that it gives also the PIDs of the processes that communicates in udp. That is the moment when I understood and built a baseline of
what will be my first step in solving the problem: GetExtendedUdpTable and then get the socket out of the process. But it wasn't enough. 
I needed somehow to iterate and locate the socket that the process holds. After opening process explorer I saw something unusual - I excepted to see something
like \device\udp or \device\tcp but I saw instead a weird \device\afd.<br /><br />
After we duplicated the socket we are one step from the entire solution: What left is to extract the remote address and port.
Confusingly, the function that need to use is getsockname and not getpeername - Although that the getpeername function theortically should be used.<br />
Summing up, this are the steps that you need to apply to do it:<br />

<ul>
  <li>Get all the PIDs that are currently communicating via UDP (via GetExtendedUdpTable).</li>
  <li>Enumerate the PIDs and extract their handles table (NtQueryInformation, NtQueryObject).</li>
  <li>Duplicate the handle to the socket (identified with \Device\Afd).</li>
  <li>Extract from the socket the remote address.</li>
</ul><br />
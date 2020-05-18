# Overview

WnfExec is a C# proof of concept library that injects shellcode into a process by hijacking a WNF subscription callback then triggering a state change. There's nothing novel here and was built based on the research of others. My intent was to solidfy the concept in my head, document the journey, and provide my code along the way.

Follow me on Twitter for some more tool releases soon!
[@ustayready](https://twitter.com/ustayready)

## Requirements

- .NET Framework 4.5
- x64 Shellcode
- x64 Process to inject into


## Usage
```
byte[] shellcode = new byte[] { .... };
var client = new WNF(shellcode);
client.InjectProcess("explorer");
```

## Prior Work/Research

As I mentioned in Beau Bullock ([@dafthack](https://twitter.com/dafthack)) and I's talk at WWHF 2018, most of my WNF research is because I stood on the shoulders of giants that had gone before me. While the list isn't exhaustive, the following prior research and work helped me grasp the fundamentals necessary to integrate these types of techniques into the red team services we offer at CrowdStrike.

**Alex Ionescu and Gabrielle Viala**
- [Blackhat 2019: Windows Notification Facility: Peeling the Onion of the Most Undocumented Kernel Attack Surface Yet](https://www.youtube.com/watch?v=MybmgE95weo&list=PLH15HpR5qRsVAXGmSVfjWrGtGLJjIJuGe&index=57&t=0s)
- [Playing with the Windows Notification Facility](https://blog.quarkslab.com/playing-with-the-windows-notification-facility-wnf.html)

**Redplait Research**
- [WNF Notifiers](http://redplait.blogspot.com/2012/09/wnf-notifiers.html)
- [WNF State IDs](http://redplait.blogspot.com/2017/08/wnf-ids-from-perfntcdll.html)

**Odzhan**
- [Odzhan's Process Injection](https://modexp.wordpress.com/2019/06/15/4083/)

**Amit Klein and Itzik Kotler**
- [Blackhat 2019: Process Injection Techniques - Gotta Catch Them All](https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf)

**Code Examples**
- [My Persisting .NET Payloads in WNF](https://github.com/ustayready/CasperStager)
- [Odzhan's WNF Injection](https://github.com/odzhan/injection/tree/master/wnf)
- [FuzzySec's WindfarmDynamite](https://github.com/FuzzySecurity/Sharp-Suite/blob/master/WindfarmDynamite) (super helpful example!)
- [Alex/Gabby's WNFun](https://github.com/ionescu007/wnfun)
- [Tyranid's P0 WNF Tooling](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/blob/master/NtApiDotNet/NtWnf.cs)
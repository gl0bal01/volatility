# Volatility 3 Cheatsheet

[https://volatilityfoundation.org/the-volatility-framework/](https://volatilityfoundation.org/the-volatility-framework/)

[https://code.google.com/archive/p/volatility/wikis/CommandReference23.wiki#dumpfiles](https://code.google.com/archive/p/volatility/wikis/CommandReference23.wiki#dumpfiles)



## Learn & test ##

[https://tryhackme.com/r/room/analysingvolatilememory](https://tryhackme.com/r/room/analysingvolatilememory)

[https://hackropole.fr/en/forensics/](https://hackropole.fr/en/forensics/)

[https://hacktoria.com/](https://hacktoria.com/) (memory mystery)


## Check pageFile.sys

```powershell
1) Run **FTK Imager**
Extract pagefile.sys from C:\ on Desktop
2) Get Strings : strings.exe .\pagefile.sys > pagefile.out
3) Use bulk_extractor.exe -o output .\pagefile.sys
```

## Check hiberfil.sys

```bash
1) Run **FTK Imager**
Extract hyberfil.sys from C:\ on Desktop
2) Use **Hibernation Recon** on the <file> to extract and create .bin/.raw...
3) Use Volatility to analyse
```

## Get infos about the memory dump

```python
volatility3 -f <file> windows.info
```

## Check for Malware

```powershell
volatility3 -f <file> windows.malfind
```

## Check process

```python
volatility3 -f <file> windows.psscan
```

## Dump suspicious ID

```python
volatility3 -f <file> -o . windows.memmap.Memmap --pid 1640 --dump
```

## Dump file from offset

```powershell
volatility3 -f <file> -o .  windows.dumpfiles --physaddr/virtaddr 0x3fc77360
```

## Get  the full path of a suspicious PID 740

```python
volatility3 -f <file> windows.dlllist|grep 740
```

## Get  the parent process

```python
volatility3 -f Investigation-2.raw windows.pstree
volatility3 -f Investigation-2.raw windows.psscan
```

## What DLL is loaded by a specific string/pid

```python
volatility3 -f <file> windows.dlllist|grep -i "decryptor"

volatility3 -f <file> -o . windows.memmap.Memmap --pid 740 --dump
strings pid.740.dmp|grep -i '.dll'|uniq -u
```

## Look for mutex from PID

```python
volatility3 -f <file> windows.handles|grep 1940

```

## Identify all files

```python
volatility3 -f <file> windows.filescan
```

## What commands were executed on the host

```bash
volatility3 -f <file> windows.cmdline
```

## Get info from a Windows crash dump

```powershell
volatility3 -f <file> windows.crashinfo.Crashinfo
```

## Dump the Registry Hives

```powershell
volatility3 -f <file> windows.registry.hivelist

volatility2 -f <file> --profile=<profile> dumpregistry -D .
```

## Dump the Registry Hives

```powershell
volatility2 -e <file> imageinfo # to get the profile
volatility2 -f <file> --profile=<profile> dumpregistry -D .
```

## Print a specific Windows Registry Key, subkey value

```powershell
volatility3 -f <file> windows.registry.printkey.PrintKey --key "\SystemRoot\System32\Config\SAM" --recurse
```

## Explore the SAM Hive

[https://www.kali.org/tools/regripper/](https://www.kali.org/tools/regripper/)

[https://www.sans.org/tools/registry-explorer/](https://www.sans.org/tools/registry-explorer/)

```powershell
sudo apt-get install reglookup
------
pip install regipy
regipy parse registry.0x12345678.SAM > sam_hive_output.txt
------
xxd
```

# For HITBCTF2018
# Name: HackU

## Design
The victim opens the CHM file. The CHM will Run PowerShell code. The code can be divided into three stages. 
The first stage is to load the second stage through DNS tunnel. 
The second stage is a simple remote control based on PowerShell. 
The next stage is to send the third stage code in the communication between servers. The code is a MBR' CrackMe. 
Challengers need to collect flag_1 in PowerShell phase and flag_2 in MBR CrackMe phase.
Combine the above two flag to get a complete flag.

## 题目的设计思路
受害者通过打开CHM文件，该CHM会引导PowerShell代码，该代码分3个阶段，
第一阶段通过DNS隧道引导第二阶段，
第二阶段是一个基于PowerShell的简单远控，
后续在服务器的通信中会下发第三阶段代码，而该代码是一个MBR的CrackMe，
挑战者需要收集PowerShell阶段的flag1以及MBR CrackMe阶段的flag2拼凑得到完整flag.

WriteUp
See
https://www.xctf.org.cn/library/details/hitb-quals-2018/ 

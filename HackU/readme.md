# For HITBCTF2018
# Name: HackU

## Design
The victim opens the CHM file. The CHM will Run PowerShell code. The code can be divided into three stages. 
The first stage is to load the second stage through DNS tunnel. 
The second stage is a simple remote control based on PowerShell. 
The next stage is to send the third stage code in the communication between servers. The code is a MBR' CrackMe. 
Challengers need to collect flag_1 in PowerShell phase and flag_2 in MBR CrackMe phase.
Combine the above two flag to get a complete flag.

## ��Ŀ�����˼·
�ܺ���ͨ����CHM�ļ�����CHM������PowerShell���룬�ô����3���׶Σ�
��һ�׶�ͨ��DNS��������ڶ��׶Σ�
�ڶ��׶���һ������PowerShell�ļ�Զ�أ�
�����ڷ�������ͨ���л��·������׶δ��룬���ô�����һ��MBR��CrackMe��
��ս����Ҫ�ռ�PowerShell�׶ε�flag1�Լ�MBR CrackMe�׶ε�flag2ƴ�յõ�����flag.

WriteUp
See
https://www.xctf.org.cn/library/details/hitb-quals-2018/ 

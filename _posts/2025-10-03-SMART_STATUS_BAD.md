---
layout: post
title: "S.M.A.R.T Status Bad"
date: 2025-10-02 
categories: Miscellaneous
---
# Fixing SSD Failure and Reinstalling Windows 11 on ASUS ROG Strix 17

A couple of days ago, my laptop suddenly showed a **S.M.A.R.T. Status BAD** error. After some research, I learned this meant my SSD was failing and could die at any moment. Unfortunately, my system crashed before I could back anything up and would only boot into BIOS. The only solution was to replace the SSD.

I ordered a **Samsung 990 Pro SSD** for my **ROG ASUS Strix 17**. Here’s the process I followed, in case it helps others facing the same issue.

---

### 1. Replacing the SSD

Remove the old SSD and install the new one. These videos helped with disassembly and SSD installation:

- [https://www.youtube.com/watch?v=yyOTjN1-3RQ&t=308s](https://www.youtube.com/watch?v=yyOTjN1-3RQ&t=308s)
- [https://youtu.be/wnBNatfiyEU?si=6bYFxn9VXHUUBa5](https://youtu.be/wnBNatfiyEU?si=6bYFxn9VXHUUBa5)_

---

### 2. Preparing a Windows 11 USB Installer

On another computer:

- Download the Windows 11 installation media tool from Microsoft:
    
    [https://www.microsoft.com/en-gb/software-download/windows11](https://www.microsoft.com/en-gb/software-download/windows11)
    
- Create a bootable USB stick.
- Use one of these tutorials if needed:
    - [https://www.youtube.com/watch?v=6sTB5teBURg&list=PLDowCKzG53yB4-S_Un5U28HLbpPbvOLhl&index=2](https://www.youtube.com/watch?v=6sTB5teBURg&list=PLDowCKzG53yB4-S_Un5U28HLbpPbvOLhl&index=2)
    - [https://www.youtube.com/watch?v=mTDbHgs9dHk&t=178s](https://www.youtube.com/watch?v=mTDbHgs9dHk&t=178s)

---

### 3. Troubleshooting SSD Not Detected During Install

When booting from the USB stick, my new SSD wasn’t showing up—only the USB drive was visible. Here’s how I fixed it:

1. Enter BIOS (press **F2** or **Del** on ASUS).
2. Ensure the SSD is detected under the BIOS main menu or under *Advanced → Intel Storage; This verifies you have plugged your SSD in correctly.*

![image.png]({{ site.baseurl }}/assets/SMART_error/bff76826-b979-4d89-837e-6f10eaa71e27.png)

1. **Disable Secure Boot** and Fast Boot, this option should be in the Advanced mode in BIOS under Security/Boot:
    - [https://learn.microsoft.com/en-us/answers/questions/4338287/ssd-not-detected-during-windows-11-install](https://learn.microsoft.com/en-us/answers/questions/4338287/ssd-not-detected-during-windows-11-install)
    
    ```bash
    Boot into BIOS → ensure UEFI Mode → disable Secure Boot, Safe Boot, and CSM → save and restart.
    
    ```
    
2. **Disable VMD** (this was the actual fix for me):
    - [https://www.reddit.com/r/PcBuildHelp/comments/1daebsh/windows_11_installer_doesnt_see_my_ssd_drive/](https://www.reddit.com/r/PcBuildHelp/comments/1daebsh/windows_11_installer_doesnt_see_my_ssd_drive/)

After this, my SSD was finally detected and I could install Windows 11.

---

### 4. Fixing Missing WiFi After Installation

After installation, Windows 11 prompted me to connect to WiFi, but no WiFi option appeared. I used an Ethernet cable to finish setup, but WiFi still wasn’t available.

- First, I downloaded drivers from ASUS’s support page:
    
    [https://rog.asus.com/support/download-center/](https://rog.asus.com/support/download-center/)
    
    *(search for your specific build via System Information)*
    
- When that didn’t work, I followed this Reddit fix:
    
    [https://www.reddit.com/r/ASUS/comments/15ejyok/my_wifi_option_is_not_showing_at_all/](https://www.reddit.com/r/ASUS/comments/15ejyok/my_wifi_option_is_not_showing_at_all/)
    

Key steps:

```bash
1. Download and install Intel Driver Support Assistant:
   https://www.intel.com/content/www/us/en/support/detect.html
2. Update all drivers.
3. Check Control Panel → Network and Internet → Network Connections.
   Disable/enable wireless card if needed.
4. Run as Administrator:
   Netsh winsock reset
   sfc /scannow && DISM /online /cleanup-image /restorehealth

```

This fixed the WiFi issue completely.

---

### Final Notes

Replacing the SSD and reinstalling Windows 11 took longer than expected due to BIOS and driver issues, but everything is now working perfectly. I hope this guide saves others time if you run into the same problems.
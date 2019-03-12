## Windows 10 Debloat Scripts
A few personal scripts I use whenever I install Windows 10, their purpose is to make Windows 10 faster by disabling and removing bloat. These are scripts I modified to fit my personal needs, you can find the original scripts here https://github.com/W4RH4WK/Debloat-Windows-10
## Notice
I recommend you run these scripts on a fresh install of Windows 10 after installing all Window's updates. **All of these scripts are provided as is and you run them at your own risk!**
## Instructions
* Open Powershell in administrator mode and type in `Set-ExecutionPolicy RemoteSigned`. This will allow scripts that are created on your system and signed scripts by a trusted publisher.
* Double click on `disable_bloat.ps1` or run them in Powershell by typing `.scripts\debloat.ps1` and then let them do their thing.
## Scripts Provided
* `debloat.ps1` - Disables a lot of default Windows 10 features and removes mostly all of the default applications.
* `privacy_settings.ps1` - Disables a lot of privacy settings used to send information to Microsoft about your system and you.
* `remove_onedrive.ps1` - Kills the OneDrive process and completely gets rid of it from your system.
* `utils.psm1` - Functions that are used in the scripts above, no need to ever run this script.
## Issues and Contributions
Feel free to report any issues you run across or contribute any changes you feel are necessary.

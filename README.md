# Introduction

During an incident, you want to do your analysis as quickly and as precisely as possible. Although there are many scripts available to do proper research within Microsoft 365, if you are working with Exchange Online, OneDrive, SharePoint, they all need separate modules. Not to mention that Exchange Online sometimes need multiple modules depending on what data you want to extract. Using numerous modules can be a pain due to numerous logins that are required.

I wanted to create a '*One ring to rule them all*' for any incident response within Microsoft 365, which is Operating System independent, runs natively on Windows, and works with or without Multi-Factor Authentication. PowerShell runs on Linux, macOS, natively on Windows, and it happens to be a language I somewhat understand.

Since many Microsoft security products and services connect to the Microsoft Graph Security API, I have chosen to use PowerShell in combination with the Microsoft Graph Security API.

# Conclusion

If you are missing any function, please let me know or add a GitHub feature request. For more information about what the script can do, check out my blog post at https://thalpius.com
